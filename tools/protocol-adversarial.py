#!/usr/bin/env python3
"""Adversarial live-protocol checks against a real flintd over TCP.

Complements tcp-smoke (happy path) and live-journey (client workflows) by
sending malformed, out-of-order, oversized and racing requests straight at the
wire and asserting the documented refusal names, seq echo, state integrity,
and that the server keeps serving afterwards. Uses an isolated temporary
store and the pinned signed vectors from testdata/sync/push_pull.ndjson.
"""

import json
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "zig-out" / "bin" / "flintd"
PROTO = "FLINT-SYNC/1"
STREAM = "0199de2d-dc00-7000-8000-000000000010"
RESULTS = []


def load_vectors():
    changes = []
    for line in (ROOT / "testdata/sync/push_pull.ndjson").read_text().splitlines():
        if line.startswith("> ") and '"op":"append"' in line:
            req = json.loads(line[2:])
            if req["changes"]:
                changes = req["changes"]
                break
    # The first append in the transcript carries the two pinned changes.
    assert len(changes) == 2, "expected two pinned signed changes"
    return changes


class Conn:
    def __init__(self, port, timeout=5):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.buf = b""

    def send_raw(self, data):
        self.sock.sendall(data)

    def recv_line(self, timeout=5):
        self.sock.settimeout(timeout)
        while b"\n" not in self.buf:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                # A hung server must surface as a failed check, not a
                # traceback that aborts the whole run.
                return "<timeout>"
            if not chunk:
                line, self.buf = self.buf, b""
                return line.decode(errors="replace") if line else None
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode()

    def call(self, req):
        self.send_raw(json.dumps(req, separators=(",", ":")).encode() + b"\n")
        line = self.recv_line()
        if line is None:
            return None
        try:
            return json.loads(line)
        except ValueError:
            # Non-JSON reply or a recv timeout: fail the check, keep the run.
            return {"_transport": line}

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# Checks that reproduce a tracked issue report KNOWN instead of failing, and
# start failing the run (as "fixed, remove from KNOWN") once the bug is fixed.
KNOWN = {}


def check(name, condition, detail=""):
    issue = KNOWN.get(name)
    if issue and not condition:
        RESULTS.append((name, True, detail))
        print("KNOWN %s  %s  -> %s" % (issue, name, detail))
        return
    if issue and condition:
        RESULTS.append((name, False, "fixed; remove from KNOWN (" + issue + ")"))
        print("FAIL " + name + "  -> fixed; remove from KNOWN (" + issue + ")")
        return
    RESULTS.append((name, bool(condition), detail))
    print(("ok   " if condition else "FAIL ") + name + ("" if condition else "  -> " + str(detail)))


def refused(resp, name):
    return resp is not None and resp.get("ok") is False and resp.get("refuse") == name


def start(store, extra=()):
    proc = subprocess.Popen(
        [str(BINARY), "serve", "--store=" + str(store), "--listen=127.0.0.1:0", *extra],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    ready, _, _ = select.select([proc.stderr], [], [], 5)
    if not ready:
        proc.kill()
        proc.wait(5)
        raise RuntimeError("server did not start")
    first = proc.stderr.readline()
    match = re.fullmatch(r"flintd: listening 127\.0\.0\.1:(\d+)\n", first)
    if not match:
        proc.kill()
        proc.wait(5)
        raise RuntimeError("unexpected startup line: %r" % first)
    # Drain stderr so logging can never block the server during the run.
    threading.Thread(target=lambda: [None for _ in proc.stderr], daemon=True).start()
    return proc, int(match[1])


def stop(proc):
    proc.terminate()
    try:
        proc.wait(5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(5)


def hello(port):
    c = Conn(port)
    r = c.call({"op": "hello", "seq": 1, "proto": PROTO})
    assert r and r.get("ok"), r
    return c


def new_store(directory, name):
    store = directory / name
    subprocess.run([str(BINARY), "init", "--store=" + str(store)], check=True,
                   capture_output=True, timeout=10)
    return store


def record(stream_id=STREAM, name="main", head=None, forked_from=None):
    return {"id": stream_id, "name": name, "head": head, "created": 1760000000000,
            "forked_from": forked_from}


def alive(port):
    try:
        c = hello(port)
        c.close()
        return True
    except (OSError, AssertionError):
        return False


def test_framing_and_envelope(port):
    # flintd serves connections serially (spec 3.3): never hold two open.
    for label, payload in [
        ("non-JSON line", b"not json\n"),
        ("JSON array", b"[1,2,3]\n"),
        ("JSON string", b'"hello"\n'),
        ("empty object", b"{}\n"),
        ("missing seq", b'{"op":"list"}\n'),
        ("op wrong type", b'{"op":7,"seq":1}\n'),
        ("negative seq", b'{"op":"list","seq":-1}\n'),
        ("seq above u32", b'{"op":"list","seq":4294967296}\n'),
        ("float seq", b'{"op":"list","seq":1.5}\n'),
        ("string seq", b'{"op":"list","seq":"1"}\n'),
        ("NUL bytes", b'{"op":"list","seq":1}\x00\n'),
        ("truncated JSON", b'{"op":"list","seq":\n'),
    ]:
        conn = hello(port)
        conn.send_raw(payload)
        line = conn.recv_line(3)
        resp = None
        try:
            resp = json.loads(line) if line else None
        except ValueError:
            pass
        check("bad envelope refuses usage: " + label,
              resp is None and line is None or refused(resp, "usage"),
              line)
        conn.close()
    c = hello(port)
    r = c.call({"op": "no-such-op", "seq": 9})
    check("unknown op refuses without dropping seq", r is not None and r.get("seq") == 9 and r.get("ok") is False, r)
    r = c.call({"op": "list", "seq": 4294967295})
    check("max u32 seq is echoed", r is not None and r.get("seq") == 4294967295 and r.get("ok") is True, r)
    # Duplicate keys and unknown fields must not change behaviour.
    c.send_raw(b'{"op":"list","seq":5,"seq":6,"extra":{"a":[1,2]}}\n')
    line = c.recv_line()
    resp = json.loads(line) if line and line.startswith("{") else {}
    check("duplicate/unknown keys do not crash", resp.get("seq") in (5, 6, 0), line)
    c.close()


def test_pipelining_and_split_frames(port):
    c = hello(port)
    c.send_raw(b'{"op":"list","seq":10}\n{"op":"heads","seq":11}\n{"op":"list","seq":12}\n')
    # Spec 2.1 puts one request in flight per connection, so pipelining is a
    # client violation: closing is as legal as answering. Assert only that
    # replies are never reordered — an in-order prefix then EOF, or all three.
    seqs = []
    closed = False
    for _ in range(3):
        line = c.recv_line(3)
        if line is None:
            closed = True
            break
        if not line.startswith("{"):
            break
        seqs.append(json.loads(line).get("seq"))
    check("pipelined requests answered in order or connection closed",
          seqs == [10, 11, 12][:len(seqs)] and (closed or len(seqs) == 3), (seqs, closed))
    if not closed:
        frame = b'{"op":"heads","seq":13}\n'
        for byte in frame:
            c.send_raw(bytes([byte]))
        line = c.recv_line()
        resp = json.loads(line) if line and line.startswith("{") else {}
        check("byte-at-a-time frame is reassembled", resp.get("seq") == 13 and resp.get("ok") is True, line)
        c.send_raw(b'{"op":"list","seq":14}\r\n')
        line = c.recv_line()
        resp = json.loads(line) if line and line.startswith("{") else {}
        check("CRLF framing tolerated or refused cleanly", resp.get("seq") in (14, 0), line)
    c.close()


def test_oversize(port):
    c = hello(port)
    c.send_raw(b'{"op":"list","seq":1,"pad":"' + b"A" * (4 * 1024 * 1024 + 1024) + b'"}\n')
    try:
        line = c.recv_line(10)
    except ConnectionError as exc:
        line = "<closed: %s>" % type(exc).__name__
    resp = json.loads(line) if line and line.startswith("{") else None
    ok = line is None or line.startswith("<closed") or refused(resp, "store_too_large")
    check("line over 4 MiB refuses store_too_large or closes", ok, (line or "")[:120])
    c.close()
    check("server alive after oversize line", alive(port))


def test_handshake(port):
    c = Conn(port)
    r = c.call({"op": "list", "seq": 1})
    check("list before hello is served; hello gates auth only (spec 3.2)",
          r is not None and r.get("ok") is True and r.get("seq") == 1, r)
    r = c.call({"op": "auth", "seq": 2, "nonce": "00" * 16, "hmac": "00" * 32})
    check("auth with no --auth-key refuses usage without closing", refused(r, "usage"), r)
    c.close()
    for proto in ["", "FLINT-SYNC/0", "flint-sync/1", "FLINT-SYNC/1 ", None, 1]:
        conn = Conn(port)
        req = {"op": "hello", "seq": 1}
        if proto is not None:
            req["proto"] = proto
        r = conn.call(req)
        check("hello proto %r refuses" % (proto,), refused(r, "proto_version") or refused(r, "usage"), r)
        conn.close()


def test_stream_lifecycle(port, changes):
    c = hello(port)
    bad_records = [
        ("uppercase name", record(name="Main")),
        ("empty name", record(name="")),
        ("33-char name", record(name="a" * 33)),
        ("name with slash", record(name="a/b")),
        ("name with dot-dot", record(name="..")),
        ("non-UUID id", record(stream_id="not-a-uuid")),
        ("uppercase UUID id", record(stream_id=STREAM.upper())),
        ("non-null head", record(head="0199de2d-dc00-7000-8000-000000000100")),
        ("path-traversal id", record(stream_id="../../etc/passwd")),
    ]
    for label, rec in bad_records:
        r = c.call({"op": "create", "seq": 2, "record": rec})
        check("create rejects " + label, r is not None and r.get("ok") is False and
              r.get("refuse") in ("stream_malformed", "usage"), r)
    r = c.call({"op": "create", "seq": 3, "record": {"id": STREAM}})
    check("create with missing fields is malformed", r is not None and r.get("ok") is False, r)
    r = c.call({"op": "create", "seq": 4, "record": record(head="0199de2d-dc00-7000-8000-000000000100", forked_from={
        "stream": "0199de2d-dc00-7000-8000-0000000000ff", "change": "0199de2d-dc00-7000-8000-000000000100"})})
    check("create fork of missing stream refuses stream_missing", refused(r, "stream_missing"), r)

    r = c.call({"op": "create", "seq": 5, "record": record()})
    check("valid create succeeds", r is not None and r.get("ok") is True, r)
    r = c.call({"op": "create", "seq": 6, "record": record()})
    check("duplicate create refuses stream_exists", refused(r, "stream_exists"), r)
    r = c.call({"op": "create", "seq": 7, "record": record(stream_id="0199de2d-dc00-7000-8000-000000000011")})
    check("name collision refuses stream_exists", refused(r, "stream_exists"), r)

    for label, req in [
        ("open unknown name", {"op": "open", "seq": 8, "stream": "nope"}),
        ("open unknown id", {"op": "open", "seq": 9, "stream": "0199de2d-dc00-7000-8000-0000000000aa"}),
        ("read unknown stream", {"op": "read", "seq": 10, "stream": "nope"}),
        ("append unknown stream", {"op": "append", "seq": 11, "stream": "0199de2d-dc00-7000-8000-0000000000aa",
                                   "expected_head": None, "changes": changes[:1]}),
    ]:
        r = c.call(req)
        check(label + " refuses stream_missing", refused(r, "stream_missing"), r)
    r = c.call({"op": "open", "seq": 12, "stream": "../streams/" + STREAM})
    check("open with path-like name does not escape the store", r is not None and r.get("ok") is False, r)

    r = c.call({"op": "read", "seq": 13, "stream": STREAM})
    check("read of empty stream has no changes", r is not None and r.get("ok") and r.get("changes") == [] and r.get("more") is False, r)
    c.close()


def test_append_validation(port, changes):
    c = hello(port)
    base = {"op": "append", "stream": STREAM}

    r = c.call({**base, "seq": 1, "expected_head": None, "changes": []})
    check("empty batch refuses change_malformed", refused(r, "change_malformed"), r)
    r = c.call({**base, "seq": 2, "expected_head": "0199de2d-dc00-7000-8000-000000000999", "changes": changes[:1]})
    check("wrong expected_head refuses stale_head", refused(r, "stale_head"), r)
    r = c.call({**base, "seq": 3, "expected_head": None, "changes": [changes[1]]})
    check("batch whose parent is not expected_head is change_malformed", refused(r, "change_malformed"), r)
    r = c.call({**base, "seq": 4, "expected_head": None, "changes": ["{}"]})
    check("empty change object is change_malformed", refused(r, "change_malformed"), r)
    r = c.call({**base, "seq": 5, "expected_head": None, "changes": ["not json"]})
    check("non-JSON change is change_malformed", refused(r, "change_malformed"), r)
    r = c.call({**base, "seq": 6, "expected_head": None, "changes": [42]})
    check("non-string change entry is rejected", r is not None and r.get("ok") is False, r)
    foreign = changes[0].replace('"stream":"%s"' % STREAM, '"stream":"0199de2d-dc00-7000-8000-0000000000aa"')
    r = c.call({**base, "seq": 7, "expected_head": None, "changes": [foreign]})
    check("change for a different stream is change_malformed", refused(r, "change_malformed") or refused(r, "sig_invalid"), r)

    tampered = changes[0].replace("pinned vector change", "pinned vector changf")
    r = c.call({**base, "seq": 8, "expected_head": None, "changes": [tampered]})
    check("tampered message refuses sig_invalid", refused(r, "sig_invalid"), r)
    flipped = re.sub(r'("sig":")([0-9a-f])', lambda m: m[1] + ("0" if m[2] != "0" else "1"), changes[0])
    r = c.call({**base, "seq": 9, "expected_head": None, "changes": [flipped]})
    check("flipped signature nibble refuses sig_invalid", refused(r, "sig_invalid"), r)
    r = c.call({**base, "seq": 10, "expected_head": None, "changes": [changes[0].replace('"ts":1760000000000', '"ts":0')]})
    check("ts=0 refuses change_malformed", refused(r, "change_malformed"), r)
    r = c.call({**base, "seq": 11, "expected_head": None, "changes": [changes[0].replace('"sig":"', '"sig":"G')]})
    check("non-hex signature refuses change_malformed", refused(r, "change_malformed") or refused(r, "sig_invalid"), r)

    big = json.loads(changes[0])
    big["message"] = "x" * 513
    r = c.call({**base, "seq": 12, "expected_head": None, "changes": [json.dumps(big, separators=(",", ":"))]})
    check("513-byte message refuses message_invalid (or sig_invalid)", refused(r, "message_invalid") or refused(r, "sig_invalid"), r)

    r = c.call({"op": "read", "seq": 13, "stream": STREAM})
    check("no rejected batch left anything behind", r.get("changes") == [] and r.get("head") is None, r)

    # A batch with one good and one bad change must append nothing.
    r = c.call({**base, "seq": 14, "expected_head": None,
                "changes": [changes[0], changes[1].replace("second change", "second chanxe")]})
    check("mixed good/bad batch is refused", r is not None and r.get("ok") is False, r)
    r = c.call({"op": "read", "seq": 15, "stream": STREAM})
    check("mixed batch is all-or-nothing", r.get("changes") == [], r)

    r = c.call({**base, "seq": 16, "expected_head": None, "changes": changes})
    check("valid two-change batch appends", r is not None and r.get("ok") is True and r.get("head"), r)
    head = r.get("head")
    r = c.call({**base, "seq": 17, "expected_head": None, "changes": changes})
    check("replaying the same batch refuses stale_head", refused(r, "stale_head"), r)
    r = c.call({**base, "seq": 18, "expected_head": head, "changes": [changes[0]]})
    check("re-appending an existing change refuses (no duplicate log lines)",
          r is not None and r.get("ok") is False, r)
    c.close()
    return head


def test_read_semantics(port, changes, head):
    c = hello(port)
    first = json.loads(changes[0])["id"]
    for limit, label in [(0, "limit 0"), (-1, "limit -1"), (1025, "limit above max"), ("5", "string limit"), (1.5, "float limit")]:
        r = c.call({"op": "read", "seq": 1, "stream": STREAM, "limit": limit})
        ok = r is not None and (r.get("ok") is False or (r.get("ok") and len(r.get("changes", [])) <= 1024))
        check("read " + label + " is bounded or refused", ok, str(r)[:160])
    r = c.call({"op": "read", "seq": 2, "stream": STREAM, "limit": 1})
    check("limit 1 pages with more=true", r.get("ok") and len(r["changes"]) == 1 and r.get("more") is True, str(r)[:160])
    r = c.call({"op": "read", "seq": 3, "stream": STREAM, "after": first})
    check("read after first returns the rest", r.get("ok") and len(r["changes"]) == 1 and r.get("more") is False, str(r)[:160])
    r = c.call({"op": "read", "seq": 4, "stream": STREAM, "after": head})
    check("read after head is empty", r.get("ok") and r["changes"] == [], str(r)[:160])
    r = c.call({"op": "read", "seq": 5, "stream": STREAM, "after": "0199de2d-dc00-7000-8000-000000000999"})
    check("read after unknown change refuses change_missing", refused(r, "change_missing"), r)
    r = c.call({"op": "read", "seq": 6, "stream": STREAM, "after": "garbage"})
    check("read after malformed id refuses cleanly", r is not None and r.get("ok") is False, r)
    r = c.call({"op": "read", "seq": 7, "stream": STREAM})
    check("raw change lines are returned byte-identical", r.get("changes") == changes, "")
    r = c.call({"op": "heads", "seq": 8})
    check("heads reflects the appended head", r.get("heads", {}).get(STREAM) == head, r)
    c.close()


def test_fork_chain(port, changes, head):
    c = hello(port)
    fork_id = "0199de2d-dc00-7000-8000-000000000020"
    r = c.call({"op": "create", "seq": 1, "record": record(fork_id, "side", head, {"stream": STREAM, "change": head})})
    check("fork at origin head is accepted", r is not None and r.get("ok") is True, r)
    r = c.call({"op": "create", "seq": 2, "record": record(
        "0199de2d-dc00-7000-8000-000000000021", "bad-fork", "0199de2d-dc00-7000-8000-000000000999",
        {"stream": STREAM, "change": "0199de2d-dc00-7000-8000-000000000999"})})
    check("fork from unknown change refuses change_missing", refused(r, "change_missing"), r)
    r = c.call({"op": "create", "seq": 3, "record": record(
        "0199de2d-dc00-7000-8000-000000000022", "bad-head", None,
        {"stream": STREAM, "change": head})})
    check("fork record whose head differs from forked_from.change is malformed",
          r is not None and r.get("ok") is False, r)
    c.close()


def test_connection_stress(port):
    # Idle connections must not block an active client.
    idle = [Conn(port) for _ in range(4)]
    start_time = time.time()
    try:
        c = hello(port)
        check("active client served once read-timeout reaps 4 idle connections",
              c.call({"op": "list", "seq": 2}).get("ok") is True, "")
        c.close()
    except (OSError, AssertionError, socket.timeout) as exc:
        check("active client served once read-timeout reaps 4 idle connections", False, exc)
    for conn in idle:
        conn.close()

    # Abrupt disconnects mid-frame, mid-append, and with unread replies.
    for _ in range(50):
        conn = Conn(port)
        conn.send_raw(b'{"op":"hello","seq":1,"proto":"FLINT-SYNC/1"')
        conn.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
        conn.close()
    conn = hello(port)
    conn.send_raw(b'{"op":"list","seq":2}\n' * 200)
    conn.close()
    check("server survives abrupt resets and unread replies", alive(port))

    results = []

    def worker():
        try:
            conn = hello(port)
            for i in range(20):
                results.append(conn.call({"op": "heads", "seq": i}).get("ok") is True)
            conn.close()
        except Exception:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    check("16 concurrent clients x 20 requests all succeed", len(results) == 320 and all(results),
          "%d/%d" % (sum(results), len(results)))
    check("stress run completed in reasonable time", time.time() - start_time < 90, time.time() - start_time)


def test_concurrent_create_race(port):
    sid = "0199de2d-dc00-7000-8000-000000000030"
    # The pinned vectors are bound to STREAM, so no second valid append batch
    # exists to race with; race create instead and assert single-winner
    # semantics.
    outcomes = []

    def racer():
        try:
            conn = hello(port)
            r = conn.call({"op": "create", "seq": 2, "record": record(sid, "racer")})
            outcomes.append("ok" if r.get("ok") else r.get("refuse"))
            conn.close()
        except Exception as exc:
            outcomes.append("error:" + type(exc).__name__)

    threads = [threading.Thread(target=racer) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    check("12 racing creates yield exactly one winner", outcomes.count("ok") == 1 and
          outcomes.count("stream_exists") == 11, outcomes)
    c = hello(port)
    r = c.call({"op": "list", "seq": 3})
    names = [s["name"] for s in r["streams"]]
    check("list shows the racing stream exactly once", names.count("racer") == 1, names)
    c.close()


def test_persistence_and_recovery(store, changes, head):
    proc, port = start(store)
    try:
        c = hello(port)
        r = c.call({"op": "read", "seq": 1, "stream": STREAM})
        check("changes survive a server restart byte-identically", r.get("changes") == changes and r.get("head") == head, str(r)[:160])
        c.close()
    finally:
        stop(proc)

    log = store / "streams" / (STREAM + ".jsonl")
    original = log.read_bytes()
    log.write_bytes(original + b'{"id":"torn')
    check("torn trailing line is refused at startup (stream_torn), never served",
          startup_refusal(store, "stream_torn"), "")
    log.write_bytes(original)

    record_path = store / "streams" / (STREAM + ".json")
    saved = record_path.read_bytes()
    record_path.write_text("{ corrupt")
    check("corrupt stream record fails startup with a named refusal, not a crash",
          startup_refusal(store, None), "")
    record_path.write_bytes(saved)
    proc, port = start(store)
    try:
        check("store serves again once the damage is repaired", alive(port))
    finally:
        stop(proc)


def startup_refusal(store, name):
    proc = subprocess.Popen([str(BINARY), "serve", "--store=" + str(store), "--listen=127.0.0.1:0"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        err = proc.communicate(timeout=5)[1]
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(5)
        return False
    named = "flintd: refuse " + (name or "")
    return proc.returncode == 1 and named in err and "panic" not in err and "listening" not in err


def test_auth(directory, changes):
    key = bytes([0x42]) * 32
    keyfile = directory / "adv.key"
    keyfile.write_text(key.hex() + "\n")
    keyfile.chmod(0o600)
    store = new_store(directory, "auth-store")
    proc, port = start(store, ["--auth-key=" + str(keyfile)])
    try:
        import hashlib
        import hmac
        c = Conn(port)
        r = c.call({"op": "auth", "seq": 1, "nonce": "00" * 16, "hmac": "00" * 32})
        check("auth before hello refuses auth_failed", refused(r, "auth_failed"), r)
        check("connection closes after auth before hello", c.recv_line(3) is None)
        c.close()
        c = Conn(port)
        r = c.call({"op": "hello", "seq": 1, "proto": PROTO})
        nonce = r.get("nonce")
        check("auth server issues a 32-hex nonce", isinstance(nonce, str) and re.fullmatch("[0-9a-f]{32}", nonce), r)
        for verb in [{"op": "list"}, {"op": "heads"}, {"op": "create", "record": record()},
                     {"op": "open", "stream": "main"}, {"op": "read", "stream": STREAM},
                     {"op": "append", "stream": STREAM, "expected_head": None, "changes": changes[:1]}]:
            r = c.call({**verb, "seq": 2})
            check("unauthenticated %s refuses auth_required" % verb["op"], refused(r, "auth_required"), r)
        r = c.call({"op": "auth", "seq": 3, "nonce": nonce, "hmac": "0" * 64})
        check("wrong hmac refuses auth_failed", refused(r, "auth_failed"), r)
        line = c.recv_line(3)
        check("connection closes after auth_failed", line is None, line)
        c.close()

        c = Conn(port)
        nonce = c.call({"op": "hello", "seq": 1, "proto": PROTO})["nonce"]
        r = c.call({"op": "auth", "seq": 2, "nonce": "ff" * 16, "hmac": "0" * 64})
        check("auth with a foreign nonce refuses auth_failed", refused(r, "auth_failed"), r)
        c.close()

        c = Conn(port)
        nonce = c.call({"op": "hello", "seq": 1, "proto": PROTO})["nonce"]
        mac = hmac.new(key, b"FLINT-SYNC-AUTH/1\x00" + bytes.fromhex(nonce), hashlib.sha256).hexdigest()
        r = c.call({"op": "auth", "seq": 2, "nonce": nonce, "hmac": mac.upper()})
        check("uppercase hmac refuses auth_failed (hex is lowercase-only)", refused(r, "auth_failed"), r)
        check("connection closes after uppercase-hmac refusal", c.recv_line(3) is None)
        c.close()

        c = Conn(port)
        nonce = c.call({"op": "hello", "seq": 1, "proto": PROTO})["nonce"]
        mac = hmac.new(key, b"FLINT-SYNC-AUTH/1\x00" + bytes.fromhex(nonce), hashlib.sha256).hexdigest()
        r = c.call({"op": "auth", "seq": 2, "nonce": nonce, "hmac": mac})
        check("correct hmac authenticates", r is not None and r.get("ok") is True, r)
        r = c.call({"op": "auth", "seq": 3, "nonce": nonce, "hmac": mac})
        check("replaying auth on the same connection does not break the session",
              r is not None and "ok" in r, r)
        c.close()

        # A nonce captured from one connection must not authenticate another.
        c1 = Conn(port)
        n1 = c1.call({"op": "hello", "seq": 1, "proto": PROTO})["nonce"]
        mac1 = hmac.new(key, b"FLINT-SYNC-AUTH/1\x00" + bytes.fromhex(n1), hashlib.sha256).hexdigest()
        c1.close()
        c2 = Conn(port)
        n2 = c2.call({"op": "hello", "seq": 1, "proto": PROTO})["nonce"]
        r = c2.call({"op": "auth", "seq": 2, "nonce": n1, "hmac": mac1})
        check("nonces are unique per connection", n1 != n2, "")
        check("auth replayed from another connection is refused", refused(r, "auth_failed"), r)
        c2.close()
        check("auth server alive after abuse", proc.poll() is None)
    finally:
        stop(proc)


def test_allow_author(directory, changes):
    allow = directory / "allow.txt"
    allow.write_text("11" * 32 + "\n")
    store = new_store(directory, "allow-store")
    proc, port = start(store, ["--allow-author=" + str(allow)])
    try:
        c = hello(port)
        c.call({"op": "create", "seq": 2, "record": record()})
        r = c.call({"op": "append", "seq": 3, "stream": STREAM, "expected_head": None, "changes": changes})
        check("author outside the allowlist refuses author_not_allowed", refused(r, "author_not_allowed"), r)
        r = c.call({"op": "read", "seq": 4, "stream": STREAM})
        check("disallowed author left no log", r.get("changes") == [], r)
        c.close()
    finally:
        stop(proc)


def test_cli(directory):
    def run(*args):
        return subprocess.run([str(BINARY), *args], capture_output=True, text=True, timeout=10)

    p = run("serve", "--store=" + str(directory / "does-not-exist"), "--listen=127.0.0.1:0")
    check("serve on a missing store exits 1 with store_missing", p.returncode == 1 and "store_missing" in p.stderr, (p.returncode, p.stderr))
    p = run("bogus-subcommand")
    check("unknown subcommand exits 2", p.returncode == 2, (p.returncode, p.stderr))
    p = run("serve", "--store=" + str(directory / "store"), "--listen=not-an-address")
    check("bad listen address exits 2", p.returncode == 2, (p.returncode, p.stderr))
    p = run("serve", "--store=" + str(directory), "--auth-key=" + str(directory / "missing.key"), "--listen=127.0.0.1:0")
    check("missing auth key file fails to start", p.returncode != 0, (p.returncode, p.stderr))
    bad = directory / "short.key"
    bad.write_text("abcd\n")
    store = new_store(directory, "cli-store")
    p = run("serve", "--store=" + str(store), "--auth-key=" + str(bad), "--listen=127.0.0.1:0")
    check("malformed auth key file fails to start", p.returncode != 0, (p.returncode, p.stderr))
    check("auth key material never echoed on failure", "abcd" not in p.stdout + p.stderr, p.stderr)
    p = run("init", "--store=" + str(store))
    check("re-init of an existing store does not clobber or crash", p.returncode in (0, 1), (p.returncode, p.stderr))


def run_test(fn, *args):
    # A transport error (timeout, reset, wedge) fails the one check scope that
    # hit it instead of aborting the whole run with a traceback.
    try:
        return fn(*args)
    except Exception as exc:
        check(fn.__name__, False, "crashed: %s: %s" % (type(exc).__name__, exc))
        return None


def main():
    if not BINARY.exists():
        print("build first: zig build", file=sys.stderr)
        return 2
    changes = load_vectors()
    with tempfile.TemporaryDirectory(prefix="flint-adversarial-") as tmp:
        directory = Path(tmp)
        store = new_store(directory, "store")
        proc, port = start(store, ["--read-timeout=1"])
        head = None
        try:
            run_test(test_framing_and_envelope, port)
            run_test(test_pipelining_and_split_frames, port)
            run_test(test_handshake, port)
            run_test(test_stream_lifecycle, port, changes)
            head = run_test(test_append_validation, port, changes)
            run_test(test_read_semantics, port, changes, head)
            run_test(test_fork_chain, port, changes, head)
            run_test(test_oversize, port)
            run_test(test_connection_stress, port)
            run_test(test_concurrent_create_race, port)
            check("server process still running at end of run", proc.poll() is None)
        finally:
            stop(proc)
        run_test(test_persistence_and_recovery, store, changes, head)
        run_test(test_auth, directory, changes)
        run_test(test_allow_author, directory, changes)
        run_test(test_cli, directory)
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed" % (len(RESULTS), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
