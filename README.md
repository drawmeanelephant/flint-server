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
keys and signs nothing. A store written by this server loads in the client
and in the guest implementation.

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

Scaffold only. No implementation yet.

## License

See [LICENSE](LICENSE) (carried over from VirelaiOS).
