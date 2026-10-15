import hashlib
import hmac
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import healthcheck


class ProbeTests(unittest.TestCase):
    def server(self, handler):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(2)
        address = listener.getsockname()
        failures = []

        def serve():
            try:
                with listener:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(2)
                        handler(connection)
            except Exception as error:
                failures.append(error)

        thread = threading.Thread(target=serve)
        thread.start()

        def finish():
            thread.join(3)
            self.assertFalse(thread.is_alive())
            if failures:
                raise failures[0]

        self.addCleanup(finish)
        return address

    def test_no_auth_handshake_and_list(self):
        def handler(connection):
            stream = connection.makefile("rb")
            self.assertEqual(json.loads(stream.readline())["op"], "hello")
            connection.sendall(b'{"seq":1,"ok":true,"proto":"FLINT-SYNC/1","server":"flintd"}\n')
            self.assertEqual(json.loads(stream.readline())["op"], "list")
            connection.sendall(b'{"seq":2,"ok":true,"streams":[{"name":"test"}]}\n')
        self.assertEqual(healthcheck.probe(self.server(handler), timeout=1), 1)

    def test_authenticated_probe(self):
        key = bytes([0x11]) * 32
        nonce = "00" * 16

        def handler(connection):
            stream = connection.makefile("rb")
            stream.readline()
            connection.sendall(json.dumps({"seq": 1, "ok": True, "proto": "FLINT-SYNC/1", "server": "flintd", "nonce": nonce}).encode() + b"\n")
            request = json.loads(stream.readline())
            expected = hmac.new(key, b"FLINT-SYNC-AUTH/1\0" + bytes.fromhex(nonce), hashlib.sha256).hexdigest()
            self.assertEqual(request["hmac"], expected)
            connection.sendall(b'{"seq":2,"ok":true}\n')
            self.assertEqual(json.loads(stream.readline())["seq"], 3)
            connection.sendall(b'{"seq":3,"ok":true,"streams":[]}\n')
        self.assertEqual(healthcheck.probe(self.server(handler), timeout=1, key=key), 0)

    def test_untrusted_refusal_never_echoed(self):
        client, server = socket.socketpair()
        with client, server:
            server.sendall(b'{"seq":1,"ok":false,"detail":"secret-private-message"}\n')
            session = healthcheck.Session(client, time.monotonic() + 1)
            with self.assertRaises(healthcheck.ProbeError) as error:
                session.request({"seq": 1})
            self.assertNotIn("secret-private-message", str(error.exception))

    def test_invalid_responses(self):
        for data in (b"not-json\n", b"[]\n", b'{"seq":true,"ok":true}\n', b'{"seq":9,"ok":true}\n'):
            with self.subTest(data=data):
                client, server = socket.socketpair()
                with client, server:
                    server.sendall(data)
                    with self.assertRaises(healthcheck.ProbeError):
                        healthcheck.Session(client, time.monotonic() + 1).request({"seq": 1})

    def test_deadline(self):
        client, server = socket.socketpair()
        with client, server:
            with self.assertRaises(healthcheck.ProbeError):
                healthcheck.Session(client, time.monotonic() - 1).request({"seq": 1})

    def test_response_size_excludes_newline(self):
        response = b'{"seq":1,"ok":true}'
        client, server = socket.socketpair()
        with client, server, patch.object(healthcheck, "MAX_LINE_BYTES", len(response)):
            server.sendall(response + b"\n")
            self.assertTrue(healthcheck.Session(client, time.monotonic() + 1).request({"seq": 1})["ok"])
        client, server = socket.socketpair()
        with client, server, patch.object(healthcheck, "MAX_LINE_BYTES", len(response) - 1):
            server.sendall(response + b"\n")
            with self.assertRaises(healthcheck.ProbeError):
                healthcheck.Session(client, time.monotonic() + 1).request({"seq": 1})

    def test_key_format_and_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.key"
            path.write_text("11" * 32 + "\n")
            self.assertEqual(healthcheck.load_key(path), bytes([0x11]) * 32)
            path.write_text("NOT A KEY")
            with self.assertRaises(healthcheck.ProbeError):
                healthcheck.load_key(path)
        self.assertIn("flint_up 0\n", healthcheck.metrics(False, 0, .5))
        self.assertEqual(healthcheck.parse_address("[::1]:4748"), ("::1", 4748))


if __name__ == "__main__":
    unittest.main()
