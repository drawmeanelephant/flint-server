# flintd operations runbook

## Startup and health

Build a reviewed release and initialize a new store once. Bind to loopback or
an encrypted tunnel. Keep auth keys outside the store/repository and mount them
read-only from the deployment secret manager. Run the daemon as a dedicated
unprivileged account with write access only to its store.

```sh
python3 tools/healthcheck.py --address=127.0.0.1:4748
python3 tools/healthcheck.py --address=127.0.0.1:4748 --auth-key=/run/secrets/flint-auth
```

The probe performs a real handshake, optional HMAC authentication, and a stream
listing. It is read-only, has a total deadline, and exits nonzero on refusal,
malformed/oversized response, timeout, or connection failure.

`--prometheus` writes bounded-cardinality probe metrics (`flint_up`,
`flint_streams`, `flint_probe_duration_seconds`) to stdout. An operator can
atomically install this output in a Prometheus node-exporter textfile directory.
Alert on `flint_up == 0` for two consecutive probes and on probe latency above
the deployment's baseline. A failed probe still exits nonzero when emitting
metrics. No collector or paging endpoint is assumed to exist here.

The serial server can be occupied by an idle client. A probe timeout may mean
the current client has not disconnected, not that the process crashed. Check
the process and connection boundary before restarting.

## Diagnostics and redaction

Protocol bytes belong only on stdout. Structured request records go to stderr
and contain allowlisted operation names, server-generated connection IDs, and
sequence numbers. A sequence number is only unique within a connection; use
both values to follow a request. These records are local request correlation,
not an OpenTelemetry or cross-service trace.

Request logging is best-effort with a one-millisecond write deadline. A full
or stalled stderr sink can drop records rather than stall the serial server.
Do not use these records as a lossless audit trail; drain stderr continuously.

Do not log or upload store paths, request bodies, Changes, authors, messages,
keys, HMACs, or nonces. Error reports should include the binary commit, OS/arch,
refusal code, and a synthetic reproduction. Do not attach private store copies.
Keep logs on an operator-controlled sink with access and retention policies.

## Store corruption or failed append

1. Stop accepting clients and stop the daemon. Do not run two writers.
2. Make a consistent backup with permissions preserved.
3. Record the refusal code without copying private record contents.
4. `stream_torn` means an incomplete final JSONL line. Do not delete or
   reserialize records blindly; preserve the evidence and obtain an explicit
   recovery decision from the owner.
5. Head roll-forward from a fully appended verified chain is automatic.
   `stale_head` is a client synchronization conflict, not a reason to rewrite
   server history.
6. Restore a known-good backup if approved, then run the probe and
   `flint verify --all --store=<dir>` using a compatible companion client
   before resuming writes.

## Authentication failure

Check that both sides use the same transport auth key, the current nonce, and
the FLINT-SYNC domain prefix. Never paste the key or an authentication
transcript into an issue. Check author allowlists separately from shared-key
authentication. Rotate compromised keys through the secret manager and
restart peers during a coordinated maintenance window.

## Bad release

Stop the daemon, retain a backup, restore the last known-compatible binary,
and probe it before reopening access. Do not roll back a store format without
a reviewed migration plan. Open a bug with sanitized symptoms and link it
from the release. No automatic production rollback is configured.

## Development profiling

Start a development-only server against an isolated temporary store, find that
process's PID, and generate load with the probe or a fixture client. Capture
at most 60 seconds with:

```sh
python3 tools/profile-server.py --pid=<development-pid> --seconds=10 --output=reports/profile.out
```

macOS uses the platform `sample` tool. Linux uses `perf record` with DWARF
call graphs; install the matching kernel tools and obtain profiling permission
from the host administrator. Do not weaken host security settings or attach to
someone else's process. Inspect Linux results with `perf report -i reports/profile.out`.
Profiles stay local and may contain paths or memory addresses. Never upload
them automatically. This is development profiling, not a configured production APM.
