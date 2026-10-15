#!/usr/bin/env python3
"""Read-only FLINT-SYNC/1 health probe with an overall deadline."""

import argparse
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import re
import socket
import sys
import time
import urllib.parse

MAX_LINE_BYTES = 4 * 1024 * 1024


class ProbeError(Exception):
    """Only static, non-sensitive messages may be used for this exception."""


class Session:
    def __init__(self, connection, deadline):
        self.connection = connection
        self.deadline = deadline
        self.buffer = bytearray()

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError("probe deadline exceeded")
        return remaining

    def request(self, payload):
        self.connection.settimeout(self.remaining())
        self.connection.sendall((json.dumps(payload, separators=(",", ":")) + "\n").encode())
        while b"\n" not in self.buffer:
            self.connection.settimeout(self.remaining())
            chunk = self.connection.recv(min(65536, MAX_LINE_BYTES + 1 - len(self.buffer)))
            if not chunk:
                raise ProbeError("server closed the session")
            self.buffer.extend(chunk)
            newline = self.buffer.find(b"\n")
            if newline > MAX_LINE_BYTES or (newline < 0 and len(self.buffer) > MAX_LINE_BYTES):
                raise ProbeError("oversized server response")
        line, _, rest = self.buffer.partition(b"\n")
        self.buffer = bytearray(rest)
        try:
            response = json.loads(line)
        except (ValueError, UnicodeError, RecursionError):
            raise ProbeError("malformed server response") from None
        if not isinstance(response, dict) or type(response.get("seq")) is not int:
            raise ProbeError("invalid response envelope")
        if response["seq"] != payload["seq"] or response.get("ok") is not True:
            raise ProbeError("request refused or response sequence mismatch")
        return response


def parse_address(value):
    try:
        parsed = urllib.parse.urlsplit("//" + value)
        port = parsed.port
        if not parsed.hostname or not port or parsed.path or parsed.username or parsed.password:
            raise ValueError
        # Numeric addresses avoid an unbounded platform DNS lookup before the
        # socket deadline. Operators can resolve hostnames separately.
        ipaddress.ip_address(parsed.hostname)
        return parsed.hostname, port
    except ValueError:
        raise argparse.ArgumentTypeError("expected numeric IP:port or [ipv6]:port") from None


def load_key(path):
    with path.open("rb") as source:
        raw = source.read(4097).rstrip(b"\r\n")
    if not re.fullmatch(b"[0-9a-f]{64}", raw):
        raise ProbeError("invalid auth-key file")
    return bytes.fromhex(raw.decode())


def probe(address, timeout=5.0, key=None):
    deadline = time.monotonic() + timeout
    with socket.create_connection(address, timeout=timeout) as connection:
        session = Session(connection, deadline)
        hello = session.request({"op": "hello", "seq": 1, "proto": "FLINT-SYNC/1"})
        if hello.get("proto") != "FLINT-SYNC/1" or hello.get("server") != "flintd":
            raise ProbeError("unexpected server identity")
        nonce = hello.get("nonce")
        sequence = 2
        if nonce is not None:
            if key is None:
                raise ProbeError("server requires an auth-key file")
            if not isinstance(nonce, str) or not re.fullmatch("[0-9a-f]{32}", nonce):
                raise ProbeError("invalid server challenge")
            mac = hmac.new(key, b"FLINT-SYNC-AUTH/1\0" + bytes.fromhex(nonce), hashlib.sha256).hexdigest()
            session.request({"op": "auth", "seq": sequence, "nonce": nonce, "hmac": mac})
            sequence += 1
        elif key is not None:
            raise ProbeError("authentication expected but not enabled by server")
        response = session.request({"op": "list", "seq": sequence})
        streams = response.get("streams")
        if not isinstance(streams, list) or any(not isinstance(item, dict) for item in streams):
            raise ProbeError("invalid stream listing")
        return len(streams)


def metrics(ok, streams, seconds):
    return (
        "# HELP flint_up Whether the FLINT handshake and stream listing succeeded.\n"
        "# TYPE flint_up gauge\n"
        f"flint_up {int(ok)}\n"
        "# HELP flint_streams Number of stream records returned by the probe.\n"
        "# TYPE flint_streams gauge\n"
        f"flint_streams {streams}\n"
        "# HELP flint_probe_duration_seconds Total read-only probe duration.\n"
        "# TYPE flint_probe_duration_seconds gauge\n"
        f"flint_probe_duration_seconds {seconds:.6f}\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", type=parse_address, default=("127.0.0.1", 4748))
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--auth-key", type=Path)
    parser.add_argument("--prometheus", action="store_true")
    args = parser.parse_args()
    if not 0 < args.timeout <= 300:
        parser.error("timeout must be positive and at most 300 seconds")
    started = time.monotonic()
    ok, streams = False, 0
    try:
        key = load_key(args.auth_key) if args.auth_key else None
        streams = probe(args.address, args.timeout, key)
        ok = True
    except ProbeError as error:
        print(f"flint probe: {error}", file=sys.stderr)
    except (OSError, ValueError):
        # OS and parser exception text can contain paths or untrusted input.
        print("flint probe: connection, timeout, or key-file error", file=sys.stderr)
    seconds = time.monotonic() - started
    if args.prometheus:
        print(metrics(ok, streams, seconds), end="")
    else:
        print(json.dumps({"ok": ok, "streams": streams, "seconds": round(seconds, 6)}))
    return int(not ok)


if __name__ == "__main__":
    raise SystemExit(main())
