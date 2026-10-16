---
title: Start here
parent: index
status: published
summary: Build once, init a store, serve it on loopback, and probe it.
---

# Serve your first store

Start with a loopback server. It proves the daemon works without a client,
a network, or anyone else's permission.

## 1. Get the source

Install [Zig 0.17.0](https://ziglang.org/download/) and Python 3.11+ on
macOS or Linux. Run these commands in a terminal:

```bash
git clone https://github.com/drawmeanelephant/flint-server.git
cd flint-server
zig version
zig build
```

`zig version` should print `0.17.0`. The build installs a single static
executable, `zig-out/bin/flintd`. Standard library only — there is no
dependency install step, no database, and no service to start first.

## 2. Init and serve

```bash
zig-out/bin/flintd init --store=.local/store
zig-out/bin/flintd serve --store=.local/store --listen=127.0.0.1:4748
```

`init` creates the store root (`<dir>/streams/`) and prints
`flintd: init ok store=<dir>`. Reinitializing an existing store refuses
`stream_exists` — on purpose. `serve` stays in the foreground and prints
`flintd: listening 127.0.0.1:4748`.

Default serving is loopback-only and unauthenticated. Do not expose it to
an untrusted network.

## 3. Probe it

In another terminal:

```bash
python3 tools/healthcheck.py --address=127.0.0.1:4748
```

The probe performs `hello` and `list`, exits zero when both succeed, and
does not modify the store. Stop the server with Ctrl-C.

For a self-contained end-to-end check with no companion client:

```bash
bash tools/sync-journey
```

It builds the binary and replays signed push/pull fixtures over `--stdio`.

## 4. Optional: provision an auth key

`--auth-key=<file>` turns on an HMAC challenge at `hello`. The key file is
32 random bytes as 64 lowercase hex characters — the same shape as a
client signing-key file, but a shared secret, not an Ed25519 seed:

```bash
openssl rand -hex 32 > ~/.flint-auth-key
chmod 600 ~/.flint-auth-key
zig-out/bin/flintd serve --store=.local/store --auth-key=$HOME/.flint-auth-key
```

Keep the file outside the repository and the store, owner-only. `--auth-key`
takes a path, so key material never touches the command line.

<Aside kind="tip">

Author identities are a different layer. `flintd` verifies the Ed25519
signature inside each Change but never signs anything; per-author keys are
minted client-side with `flint keygen` in the companion
[flint-client](https://github.com/drawmeanelephant/flint-client) repo.
`--allow-author=<file>` gates which author public keys may append.

</Aside>

## Verify the build

```bash
zig build test --summary all
python3 tools/check.py
```

The full gate runs formatting, static analysis, policy checks, the test
suite, generated-document checks, the sync journey, and a real loopback
TCP server — with and without authentication. See
[[testing|Testing and evidence]] for the whole matrix.
