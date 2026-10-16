#!/usr/bin/env python3
"""Adversarial live-protocol checks against a real flintd over TCP.

Complements tcp-smoke (happy path) and live-journey (client workflows) by
sending malformed, out-of-order, oversized and racing requests straight at the
wire and asserting the documented refusal names, seq echo, state integrity,
and that the server keeps serving afterwards. Uses an isolated temporary
store and the pinned signed vectors from testdata/sync/push_pull.ndjson.
"""

import json
import os
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

# Signed Changes on STREAM for the deposit checks (spec_rev 3, issue #40):
# DETACHED roots at the first pinned change, DETACHED_CHILD roots at DETACHED,
# EXTENDS_HEAD parents the head the pinned append batch produces, and ORPHAN
# names an id nobody holds. All verify under the pinned vector key.
DETACHED = '{"id":"0199de2d-dc00-7000-8000-000000000102","parent":"0199de2d-dc00-7000-8000-000000000100","stream":"0199de2d-dc00-7000-8000-000000000010","ts":1760000002000,"author":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","message":"preserved recovery original","ops":[],"merged":null,"sig":"0576aa4b885bc6bb20bd26a6cacbf686a7f2914bd9ebd637af8527f0d463dc620187624effdc3eebe1393e94e1186aa54d8934e5d60437322dcced51886fe20f"}'
EXTENDS_HEAD = '{"id":"0199de2d-dc00-7000-8000-000000000103","parent":"0199de2d-dc00-7000-8000-000000000101","stream":"0199de2d-dc00-7000-8000-000000000010","ts":1760000003000,"author":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","message":"looks like an append","ops":[],"merged":null,"sig":"e1126add21199e066fcd29cfc857f5a69c56913321b4415ea9a6a2b31cdc5abaffdf664f8fd140fea818b36cf5c313f80b36cdd55623aa09e8bf8780abf3dd0c"}'
ORPHAN = '{"id":"0199de2d-dc00-7000-8000-000000000104","parent":"0199de2d-dc00-7000-8000-00000000ffff","stream":"0199de2d-dc00-7000-8000-000000000010","ts":1760000004000,"author":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","message":"orphan parent","ops":[],"merged":null,"sig":"319e99a18317a0f22d5a1906832a7e7c4f8d5df13e6855448e13d4320de5a721a353d8a4622c6aa8501b247e82ca8cf18748f2eb2b4a5371edd68b7268810e04"}'
DETACHED_CHILD = '{"id":"0199de2d-dc00-7000-8000-000000000105","parent":"0199de2d-dc00-7000-8000-000000000102","stream":"0199de2d-dc00-7000-8000-000000000010","ts":1760000005000,"author":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","message":"child of detached","ops":[],"merged":null,"sig":"5a864337aa1f288c43909d4b2fc1df9e1fd5e4ab2fc4a8132b885c49f9c8980c827b82aaeef987b02592155ffc6fbd6e7dcc8daa3835fcf9755a4271f8f07603"}'

# Signed manifest lines for the spec_rev 4 content checks (issue #43):
# signed with the same pinned key over the "flint-manifest-v1" domain for
# changes the shared store holds (append head chain and the deposited
# detached line) plus one for a change nobody holds.
MANIFEST_C1 = '{"stream":"0199de2d-dc00-7000-8000-000000000010","change":"0199de2d-dc00-7000-8000-000000000100","author":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","files":[{"path":"go/sample.go","blob":"b7ead51daa2b6803b293b2518b882feb3ac4f1af03799375683b821306ed7eb7","bytes":54,"mode":644}],"sig":"bc383d0d0886b6b3b437c10e6775a73ce729d54c42755168130b0d1cb53e5981a4534223946a739cf3bc67e3f656dd3f28d07543818529807d0cfbe98a71970b"}'
MANIFEST_DET = '{"stream":"0199de2d-dc00-7000-8000-000000000010","change":"0199de2d-dc00-7000-8000-000000000102","author":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","files":[{"path":"go/sample.go","blob":"b7ead51daa2b6803b293b2518b882feb3ac4f1af03799375683b821306ed7eb7","bytes":54,"mode":644}],"sig":"4a8b1ddbb60ace0daa587fb4416a4026c2589fe75fd17c7b8420e9818d923488e5a45bd20ae11adf3254333702364fffa6fee3cbfd0281fdc706aa1314d89d0d"}'
MANIFEST_UNKNOWN = '{"stream":"0199de2d-dc00-7000-8000-000000000010","change":"0199de2d-dc00-7000-8000-000000000999","author":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","files":[{"path":"go/sample.go","blob":"b7ead51daa2b6803b293b2518b882feb3ac4f1af03799375683b821306ed7eb7","bytes":54,"mode":644}],"sig":"2303a4d6647186e67d0ca816182ec682075eefdf334ebb18eea79faace110f6be7cf5f346580520c11a27b149b0e9c63bfc26566b3ebfee097c061d3a454c20e"}'
BLOB_BYTES = b"adversarial blob payload\n"
BLOB_ID = __import__("hashlib").sha256(BLOB_BYTES).hexdigest()


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


def test_deposit(port, changes, head):
    """spec_rev 3 deposit op: detached lines land without moving the head,
    resends are idempotent, and every abuse case refuses by name."""
    c = hello(port)
    base = {"op": "deposit", "stream": STREAM}

    r = c.call({"op": "deposit", "seq": 1, "stream": STREAM})
    check("deposit without changes refuses usage", refused(r, "usage"), r)
    r = c.call({**base, "seq": 2, "changes": "nope"})
    check("deposit with non-array changes refuses usage", refused(r, "usage"), r)
    r = c.call({**base, "seq": 3, "changes": [42]})
    check("deposit non-string change entry refuses", r is not None and r.get("ok") is False, r)
    r = c.call({**base, "seq": 4, "changes": []})
    check("deposit empty batch refuses change_malformed", refused(r, "change_malformed"), r)
    r = c.call({"op": "deposit", "seq": 5, "stream": "0199de2d-dc00-7000-8000-0000000000aa",
                "changes": [DETACHED]})
    check("deposit on unknown stream refuses stream_missing", refused(r, "stream_missing"), r)

    # A well-formed detached line whose signature fails refuses sig_invalid.
    bad_sig = DETACHED.replace("preserved recovery original", "preserved recovery oxiginal")
    r = c.call({**base, "seq": 6, "changes": [bad_sig]})
    check("deposit bad signature refuses sig_invalid", refused(r, "sig_invalid"), r)
    # Validly signed, but a detached Change may not extend the current head.
    r = c.call({**base, "seq": 7, "changes": [EXTENDS_HEAD]})
    check("deposit with parent=head refuses change_malformed", refused(r, "change_malformed"), r)
    r = c.call({**base, "seq": 8, "changes": [ORPHAN]})
    check("deposit with unknown parent refuses change_malformed", refused(r, "change_malformed"), r)
    r = c.call({**base, "seq": 9, "changes": [changes[0]] * 257})
    check("deposit batch over 256 refuses change_malformed", refused(r, "change_malformed"), r)

    # Nothing refused above may have been written.
    r = c.call({"op": "read", "seq": 10, "stream": STREAM})
    check("refused deposits left the log untouched",
          r.get("changes") == changes and r.get("head") == head, str(r)[:160])

    # Happy path by name: a detached line stores, head echoes unchanged.
    r = c.call({"op": "deposit", "seq": 11, "stream": "main", "changes": [DETACHED]})
    check("deposit of a detached change stores it, head unmoved",
          r is not None and r.get("ok") is True and r.get("stored") == 1 and r.get("head") == head, r)
    r = c.call({**base, "seq": 12, "changes": [DETACHED]})
    check("re-deposit of identical bytes is a no-op (stored=0)",
          r is not None and r.get("ok") is True and r.get("stored") == 0 and r.get("head") == head, r)
    r = c.call({**base, "seq": 13, "changes": [DETACHED + " "]})
    check("same id under different bytes refuses change_malformed", refused(r, "change_malformed"), r)
    # A child rooted at the just-deposited line resolves its parent in-log.
    r = c.call({**base, "seq": 14, "changes": [DETACHED_CHILD]})
    check("deposit child of a detached line stores",
          r is not None and r.get("ok") is True and r.get("stored") == 1, r)

    r = c.call({"op": "read", "seq": 15, "stream": STREAM})
    check("read returns deposited detached lines verbatim",
          r.get("changes") == changes + [DETACHED, DETACHED_CHILD] and r.get("head") == head,
          str(r)[:160])
    r = c.call({"op": "heads", "seq": 16})
    check("heads still shows the pre-deposit head", r.get("heads", {}).get(STREAM) == head, r)
    c.close()


def test_content_ops(port, changes, head):
    """spec_rev 4 content ops: blob_put/blob_get and put_manifest/get_manifest
    happy paths plus the refusal surface for bad hashes, bad bindings, torn
    paths, conflicts, and oversize payloads."""
    c = hello(port)

    # --- blob_put / blob_get ------------------------------------------
    r = c.call({"op": "blob_put", "seq": 1, "id": BLOB_ID, "hex": BLOB_BYTES.hex()})
    check("blob_put stores a well-formed blob", r is not None and r.get("ok") is True, r)
    r = c.call({"op": "blob_put", "seq": 2, "id": BLOB_ID, "hex": BLOB_BYTES.hex()})
    check("blob_put resend is idempotent", r is not None and r.get("ok") is True, r)
    r = c.call({"op": "blob_get", "seq": 3, "id": BLOB_ID})
    check("blob_get returns the exact bytes", r is not None and r.get("hex") == BLOB_BYTES.hex(), r)

    for label, req, want in [
        ("blob_put missing id", {"op": "blob_put", "seq": 4, "hex": "aa"}, "usage"),
        ("blob_put missing hex", {"op": "blob_put", "seq": 5, "id": BLOB_ID}, "usage"),
        ("blob_put non-string hex", {"op": "blob_put", "seq": 6, "id": BLOB_ID, "hex": 7}, "usage"),
        ("blob_put short id", {"op": "blob_put", "seq": 7, "id": "ab", "hex": "aa"}, "blob_malformed"),
        ("blob_put uppercase id", {"op": "blob_put", "seq": 8, "id": BLOB_ID.upper(), "hex": BLOB_BYTES.hex()}, "blob_malformed"),
        ("blob_put wrong hash", {"op": "blob_put", "seq": 9, "id": "0" * 64, "hex": BLOB_BYTES.hex()}, "blob_malformed"),
        ("blob_put non-hex payload", {"op": "blob_put", "seq": 10, "id": BLOB_ID, "hex": "zz"}, "blob_malformed"),
        ("blob_put odd-length hex", {"op": "blob_put", "seq": 11, "id": BLOB_ID, "hex": "abc"}, "blob_malformed"),
        ("blob_get missing id", {"op": "blob_get", "seq": 12}, "usage"),
        ("blob_get unknown blob", {"op": "blob_get", "seq": 13, "id": "1" * 64}, "blob_missing"),
        ("blob_get bad id shape", {"op": "blob_get", "seq": 14, "id": "nope"}, "blob_malformed"),
    ]:
        r = c.call(req)
        check(label + " refuses " + want, refused(r, want), r)

    r = c.call({"op": "blob_put", "seq": 15, "id": BLOB_ID, "hex": "aa" * (1800000 + 1)})
    check("blob_put over the 1,800,000-byte cap refuses change_too_large",
          refused(r, "change_too_large"), r)

    # --- put_manifest --------------------------------------------------
    for label, req, want in [
        ("put_manifest missing stream", {"op": "put_manifest", "seq": 16, "lines": [MANIFEST_C1]}, "usage"),
        ("put_manifest missing lines", {"op": "put_manifest", "seq": 17, "stream": STREAM}, "usage"),
        ("put_manifest non-array lines", {"op": "put_manifest", "seq": 18, "stream": STREAM, "lines": "x"}, "usage"),
        ("put_manifest non-string line", {"op": "put_manifest", "seq": 19, "stream": STREAM, "lines": [42]}, "change_malformed"),
        ("put_manifest empty batch", {"op": "put_manifest", "seq": 20, "stream": STREAM, "lines": []}, "change_malformed"),
        ("put_manifest unknown stream", {"op": "put_manifest", "seq": 21, "stream": "0199de2d-dc00-7000-8000-0000000000aa",
                                         "lines": [MANIFEST_C1]}, "stream_missing"),
        ("put_manifest unknown change", {"op": "put_manifest", "seq": 22, "stream": STREAM, "lines": [MANIFEST_UNKNOWN]}, "change_missing"),
    ]:
        r = c.call(req)
        check(label + " refuses " + want, refused(r, want), r)

    # A manifest signed for a different change fails verification; a
    # containment-breaking path is manifest_torn; a foreign stream binding
    # is change_malformed.
    bad_sig = MANIFEST_DET.replace(
        '"change":"0199de2d-dc00-7000-8000-000000000102"',
        '"change":"0199de2d-dc00-7000-8000-000000000105"')
    r = c.call({"op": "put_manifest", "seq": 23, "stream": STREAM, "lines": [bad_sig]})
    check("put_manifest wrong-change signature refuses sig_invalid", refused(r, "sig_invalid"), r)
    bad_path = MANIFEST_C1.replace('"path":"go/sample.go"', '"path":"../escape.go"')
    r = c.call({"op": "put_manifest", "seq": 24, "stream": STREAM, "lines": [bad_path]})
    check("put_manifest path escape refuses manifest_torn", refused(r, "manifest_torn"), r)
    wrong_stream = MANIFEST_C1.replace('"stream":"0199de2d-dc00-7000-8000-000000000010"',
                                       '"stream":"0199de2d-dc00-7000-8000-0000000000aa"')
    r = c.call({"op": "put_manifest", "seq": 25, "stream": STREAM, "lines": [wrong_stream]})
    check("put_manifest foreign stream binding refuses change_malformed", refused(r, "change_malformed"), r)
    r = c.call({"op": "put_manifest", "seq": 26, "stream": STREAM, "lines": [MANIFEST_C1] * 257})
    check("put_manifest batch over 256 refuses change_malformed", refused(r, "change_malformed"), r)
    unsorted = MANIFEST_C1.replace(
        '"files":[{"path":"go/sample.go"',
        '"files":[{"path":"z/z.go","blob":"' + "0" * 64 + '","bytes":0,"mode":644},{"path":"go/sample.go"')
    r = c.call({"op": "put_manifest", "seq": 27, "stream": STREAM, "lines": [unsorted]})
    check("put_manifest unsorted inventory refuses change_malformed", refused(r, "change_malformed"), r)

    # Nothing refused above may have been written.
    r = c.call({"op": "get_manifest", "seq": 28, "stream": STREAM, "after": None})
    check("refused manifests left the log empty", r is not None and r.get("ok") and r.get("lines") == [], r)

    r = c.call({"op": "put_manifest", "seq": 29, "stream": "main", "lines": [MANIFEST_C1, MANIFEST_DET]})
    check("put_manifest stores chain + detached manifests, head untouched",
          r is not None and r.get("ok") is True and r.get("stored") == 2, r)
    r = c.call({"op": "put_manifest", "seq": 30, "stream": STREAM, "lines": [MANIFEST_C1]})
    check("put_manifest resend skips stored bytes", r is not None and r.get("stored") == 0, r)
    conflict = re.sub(r'("sig":")([0-9a-f])', lambda m: m[1] + ("0" if m[2] != "0" else "1"), MANIFEST_C1)
    r = c.call({"op": "put_manifest", "seq": 31, "stream": STREAM, "lines": [conflict]})
    check("put_manifest same change different bytes refuses change_malformed",
          refused(r, "change_malformed"), r)

    # --- get_manifest --------------------------------------------------
    first = json.loads(changes[0])["id"]
    r = c.call({"op": "get_manifest", "seq": 32, "stream": STREAM, "after": None})
    check("get_manifest returns the stored lines verbatim",
          r is not None and r.get("lines") == [MANIFEST_C1, MANIFEST_DET], r)
    r = c.call({"op": "get_manifest", "seq": 33, "stream": STREAM, "after": first})
    check("get_manifest after first returns manifests for the rest of the log",
          r is not None and r.get("lines") == [MANIFEST_DET], r)
    r = c.call({"op": "get_manifest", "seq": 34, "stream": STREAM, "after": "0199de2d-dc00-7000-8000-000000000105"})
    check("get_manifest after last change is empty", r is not None and r.get("lines") == [], r)
    r = c.call({"op": "get_manifest", "seq": 35, "stream": STREAM, "after": "0199de2d-dc00-7000-8000-000000000999"})
    check("get_manifest unknown after refuses change_missing", refused(r, "change_missing"), r)
    r = c.call({"op": "get_manifest", "seq": 36, "stream": "0199de2d-dc00-7000-8000-0000000000aa", "after": None})
    check("get_manifest unknown stream refuses stream_missing", refused(r, "stream_missing"), r)
    r = c.call({"op": "get_manifest", "seq": 37, "stream": STREAM})
    check("get_manifest missing after defaults to whole log",
          r is not None and r.get("lines") == [MANIFEST_C1, MANIFEST_DET], r)

    r = c.call({"op": "heads", "seq": 38})
    check("content publication never moved the head", r.get("heads", {}).get(STREAM) == head, r)
    r = c.call({"op": "read", "seq": 39, "stream": STREAM})
    check("change log untouched by content ops", r.get("head") == head and len(r.get("changes", [])) == 4, r)
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
    # The deposit leg appended two detached lines; they persist verbatim too.
    expected_lines = changes + [DETACHED, DETACHED_CHILD]
    proc, port = start(store)
    try:
        c = hello(port)
        r = c.call({"op": "read", "seq": 1, "stream": STREAM})
        check("changes survive a server restart byte-identically", r.get("changes") == expected_lines and r.get("head") == head, str(r)[:160])
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
                     {"op": "append", "stream": STREAM, "expected_head": None, "changes": changes[:1]},
                     {"op": "put_manifest", "stream": STREAM, "lines": [MANIFEST_C1]},
                     {"op": "get_manifest", "stream": STREAM, "after": None},
                     {"op": "blob_put", "id": BLOB_ID, "hex": BLOB_BYTES.hex()},
                     {"op": "blob_get", "id": BLOB_ID}]:
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
        # The author gate mirrors append's order (after signature and parent
        # checks): on an empty stream DETACHED's parent cannot resolve, so the
        # refusal surfaces as change_malformed rather than author_not_allowed.
        r = c.call({"op": "deposit", "seq": 4, "stream": STREAM, "changes": [DETACHED]})
        check("deposit on a gated empty stream refuses cleanly", refused(r, "change_malformed"), r)
        r = c.call({"op": "read", "seq": 5, "stream": STREAM})
        check("disallowed author left no log", r.get("changes") == [], r)
        c.close()
    finally:
        stop(proc)


def test_read_only_store(directory, changes):
    """Issue #36: a store the daemon cannot write refuses writes with
    store_io — not stream_malformed — and keeps serving reads."""
    ro = new_store(directory, "ro-store")
    proc, port = start(ro, [])
    try:
        c = hello(port)
        r = c.call({"op": "create", "seq": 2, "record": record()})
        assert r and r.get("ok"), r
        r = c.call({"op": "append", "seq": 3, "stream": STREAM,
                    "expected_head": None, "changes": changes[:1]})
        assert r and r.get("ok") and r.get("head"), r
        head = r["head"]
        c.close()
    finally:
        stop(proc)

    def tree_mode(mode_dirs, mode_files):
        for root, dirs, files in os.walk(ro):
            for d in dirs:
                os.chmod(os.path.join(root, d), mode_dirs)
            for f in files:
                os.chmod(os.path.join(root, f), mode_files)

    # Content dirs are created lazily — pre-create them so the chmod applies
    # and the write paths inside fail like every other store write.
    os.makedirs(os.path.join(ro, "blobs", BLOB_ID[:2]), exist_ok=True)
    os.makedirs(os.path.join(ro, "manifests"), exist_ok=True)
    tree_mode(0o555, 0o444)
    try:
        proc, port = start(ro, [])
        try:
            c = hello(port)
            r = c.call({"op": "create", "seq": 1, "record": record(
                stream_id="0199de2d-dc00-7000-8000-000000000020", name="ro2")})
            check("read-only store: create refuses store_io", refused(r, "store_io"), r)
            r = c.call({"op": "append", "seq": 2, "stream": STREAM,
                        "expected_head": head, "changes": changes[1:]})
            check("read-only store: append refuses store_io", refused(r, "store_io"), r)
            r = c.call({"op": "blob_put", "seq": 4, "id": BLOB_ID, "hex": BLOB_BYTES.hex()})
            check("read-only store: blob_put refuses store_io", refused(r, "store_io"), r)
            r = c.call({"op": "put_manifest", "seq": 5, "stream": STREAM, "lines": [MANIFEST_C1]})
            check("read-only store: put_manifest refuses store_io", refused(r, "store_io"), r)
            r = c.call({"op": "read", "seq": 3, "stream": STREAM})
            check("read-only store: read still serves",
                  r is not None and r.get("ok") and r.get("head") == head, r)
            c.close()
            check("read-only store: server keeps serving", alive(port))
        finally:
            stop(proc)
    finally:
        tree_mode(0o755, 0o644)


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
            run_test(test_deposit, port, changes, head)
            run_test(test_content_ops, port, changes, head)
            run_test(test_oversize, port)
            run_test(test_connection_stress, port)
            run_test(test_concurrent_create_race, port)
            check("server process still running at end of run", proc.poll() is None)
        finally:
            stop(proc)
        run_test(test_persistence_and_recovery, store, changes, head)
        run_test(test_auth, directory, changes)
        run_test(test_allow_author, directory, changes)
        run_test(test_read_only_store, directory, changes)
        run_test(test_cli, directory)
    failed = [r for r in RESULTS if not r[1]]
    print("\n%d checks, %d failed" % (len(RESULTS), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
