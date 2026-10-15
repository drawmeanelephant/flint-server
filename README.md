# flint-server

A standalone, cross-platform (Linux + macOS) **server** for **FLINT**, the
agent-native source-control system designed for VirelaiOS
([ADR 0049](docs/adr-0049.md)) and implemented in Go as `FLINT.ELF` in the
[VirelaiOS](https://github.com/drawmeanelephant/VirelaiOS) repository.

This repository is the host port of the server half — a single static
`flintd` binary written in **Zig 0.17.0**, standard library only, no
dependencies. It holds byte-compatible ADR 0049 stores (`streams/<id>.json`,
`streams/<id>.jsonl`) and serves `FLINT-SYNC/1`, a newline-delimited-JSON
push/pull protocol, to [flint-client](https://github.com/drawmeanelephant/flint-client)
peers. It verifies Ed25519 signatures on every inbound Change; it holds no
signing keys and signs nothing. Optional transport authentication uses an
externally provisioned shared key. A store written by this server loads in the client
and in the guest implementation.

## Quick start

The build/test commands below require a source checkout. Binary release
archives run without Zig: use `./flintd init --store=.local/store`, then
`./flintd serve --store=.local/store --listen=127.0.0.1:4748`.
They include the operational health/profiling tools and documentation.

Install **Zig 0.17.0** from [ziglang.org/download](https://ziglang.org/download/)
and Python **3.11 or newer** for development tooling. There are no external
runtime dependencies, databases, or services to install.

```sh
zig version
zig build
zig-out/bin/flintd init --store=.local/store
zig-out/bin/flintd serve --store=.local/store --listen=127.0.0.1:4748
```

The last command stays in the foreground. In another terminal:

```sh
python3 tools/healthcheck.py --address=127.0.0.1:4748
```

The probe performs `hello` and `list`, exits zero when both succeed, and does
not modify the store. Stop the server with Ctrl-C. Initialization is a
one-time step; reinitializing an existing store intentionally fails.

For a self-contained, temporary-store end-to-end check:

```sh
bash tools/sync-journey
```

It builds the binary and replays signed push/pull fixtures without a companion
client or authentication credentials. To additionally check client compatibility,
set `FLINT_BIN` to an explicitly chosen `flint` executable.

## Development

```sh
python3 tools/check.py
zig build test --summary all
zig test src/store.zig --test-filter 'validators and UUID parsing'
```

`tools/check.py` runs formatting, Zig static analysis, repository policy checks,
tooling tests, build, the Zig test suite, generated-document checks, and the
sync journey. Reports are written to the ignored `reports/` directory.
The gate also checks a real loopback TCP server with and without authentication.
CI repeats the tests to expose instability and retains timing and failure
reports. See [AGENTS.md](AGENTS.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

Install the optional pre-commit hook with `bash tools/install-hooks`.
It validates the staged snapshot in a temporary directory, not unstaged work.

## Environment and authentication

See [.env.example](.env.example). The binary does **not** load `.env` files.

| Variable | Meaning |
| --- | --- |
| `FLINT_STORE` | Store directory when `--store` is omitted; the flag takes precedence. |
| `FLINT_BIN` | Optional companion client for `tools/sync-journey`; never auto-discovered outside this repository. |

Default serving is loopback-only and unauthenticated. Do not expose it to an
untrusted network. For shared environments, use `--auth-key=<file>` and
`--allow-author=<file>` behind an authenticated, encrypted tunnel. The auth key
is 32 random bytes encoded as 64 lowercase hex characters, stored outside the
repository and store with owner-only permissions. Never put key material on
the command line or in an issue. See [SECURITY.md](SECURITY.md).

## Documents

- `docs/flint-server-spec.md` — the implementation spec for this port,
  including the `FLINT-SYNC/1` wire protocol and the client-side
  `push`/`pull`/`clone` deltas.
- `docs/adr-0049.md` — the normative FLINT design, copied verbatim from
  VirelaiOS ADR 0049.
- `docs/adr-0044.md` — the agent control channel ADR (the protocol
  precedent FLINT-SYNC/1 descends from), copied verbatim.
- `testdata/sig/` — the Ed25519 signature vectors, copied verbatim from
  the Go implementation's `user/go/flint/testdata/`. The Go implementation
  in VirelaiOS stays the reference oracle for store semantics.

## Tracking

VirelaiOS milestone **M106** — an index issue plus cards M106a–f, which build
the port in order: wire model + crypto → store IO → `FLINT-SYNC/1` server →
auth/gating → client remote verbs (in flint-client) → interop conformance.
See `docs/flint-server-spec.md` §6.

## Status

Implemented: store IO and crash recovery, Ed25519 verification, TCP and stdio
protocol sessions, optional HMAC authentication and author gating, golden
transcripts, and sync/portability conformance tests.

Operational guidance:
[runbooks](docs/runbooks/operations.md),
[security and dependency policy](SECURITY.md), and
[release procedure](docs/releases.md).
External setup and intentionally deferred work are listed in
[readiness follow-ups](docs/readiness-followups.md).

## License

See [LICENSE](LICENSE) (carried over from VirelaiOS).
