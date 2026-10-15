#!/usr/bin/env python3
"""Exercise the real TCP server and verify redacted request correlation."""

import json
from pathlib import Path
import re
import select
import subprocess
import tempfile

import healthcheck

ROOT = Path(__file__).resolve().parents[1]


def exercise(binary, directory, authenticated):
    store = directory / ("auth-store" if authenticated else "plain-store")
    subprocess.run([str(binary), "init", "--store=" + str(store)],
                   check=True, capture_output=True, timeout=10)
    command = [str(binary), "serve", "--store=" + str(store), "--listen=127.0.0.1:0"]
    key = None
    if authenticated:
        key = bytes([0x37]) * 32
        path = directory / "auth.key"
        path.write_text(key.hex() + "\n")
        path.chmod(0o600)
        command.append("--auth-key=" + str(path))
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        ready, _, _ = select.select([process.stderr], [], [], 5)
        if not ready:
            raise RuntimeError("server did not become ready")
        marker = process.stderr.readline()
        match = re.fullmatch(r"flintd: listening 127\.0\.0\.1:(\d+)\n", marker)
        if not match:
            raise RuntimeError("server startup failed")
        address = ("127.0.0.1", int(match[1]))
        assert healthcheck.probe(address, timeout=2, key=key) == 0
        if authenticated:
            try:
                healthcheck.probe(address, timeout=2, key=bytes(32))
            except healthcheck.ProbeError:
                pass
            else:
                raise AssertionError("incorrect authentication key was accepted")
        assert healthcheck.probe(address, timeout=2, key=key) == 0
    finally:
        process.terminate()
        try:
            _, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            _, stderr = process.communicate()
    events = [json.loads(line) for line in stderr.splitlines() if line.startswith("{")]
    assert events, "no structured request logs"
    assert all(set(event) == {"event", "connection", "seq", "operation", "outcome"} for event in events)
    assert all(re.fullmatch("[0-9a-f]{32}", event["connection"]) for event in events)
    assert all(event["outcome"] == "handled" for event in events)
    connections = {event["connection"] for event in events}
    assert len(connections) >= 2, "connections must have independent correlation IDs"
    if key:
        assert key.hex() not in stderr, "authentication secret leaked into logs"


def main():
    binary = ROOT / "zig-out/bin/flintd"
    with tempfile.TemporaryDirectory(prefix="flint-tcp-smoke-") as directory:
        for authenticated in (False, True):
            exercise(binary, Path(directory), authenticated)
        backpressure(binary, Path(directory))
    print("TCP smoke passed: no-auth/auth probes, invalid-key refusal, and redacted connection/sequence logs.")


def backpressure(binary, directory):
    store = directory / "backpressure-store"
    subprocess.run([str(binary), "init", "--store=" + str(store)],
                   check=True, capture_output=True, timeout=10)
    requests = directory / "requests"
    responses = directory / "responses"
    count = 1024
    requests.write_text("".join(
        json.dumps({"op": "hello", "seq": seq, "proto": "FLINT-SYNC/1"}) + "\n"
        for seq in range(count)
    ))
    with requests.open() as source, responses.open("w") as destination:
        process = subprocess.Popen(
            [str(binary), "serve", "--store=" + str(store), "--stdio"],
            stdin=source, stdout=destination, stderr=subprocess.PIPE,
        )
        try:
            # Intentionally never drain stderr while the server is running.
            assert process.wait(timeout=10) == 0
            logged = process.stderr.read().count(b'"event":"request"')
            assert logged < count, "test did not saturate the stderr pipe"
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stderr.close()
    replies = [json.loads(line) for line in responses.read_text().splitlines()]
    assert len(replies) == count and all(reply["ok"] for reply in replies)
    print("Stderr backpressure passed: 1024 replies completed while log records were dropped.")


if __name__ == "__main__":
    main()
