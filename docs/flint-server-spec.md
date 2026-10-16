# FLINT host server — implementation spec

A standalone, cross-platform (Linux + macOS) **server** for FLINT, the
agent-native SCM designed in VirelaiOS **ADR 0049** and implemented in Go as
`FLINT.ELF` (`user/go/flint/`). This document is the spec for `flintd`, the
host-side counterpart of the future `FLINTD.ELF` daemon (ADR 0049 "Future
arcs: FLINT M1"). Where it says "the ADR" it means ADR 0049; where it says
"the Go implementation" it means `user/go/flint/` in the VirelaiOS
repository; "the client" means the `flint` binary in
[drawmeanelephant/flint-client](https://github.com/drawmeanelephant/flint-client)
(spec: `docs/flint-client-spec.md` there and in VirelaiOS, PR #2282).

**Read this with the reference material.** Copy into this repo:

- `docs/decisions/0049-flint-scm.md` → `docs/adr-0049.md` (normative)
- `docs/decisions/0044-agent-control-channel.md` → `docs/adr-0044.md`
  (protocol precedent)
- `user/go/flint/testdata/sig/` → `testdata/sig/` (Ed25519 vectors,
  verbatim)

The Go implementation stays the reference oracle for store semantics. No
guest implementation of the daemon exists yet — the wire protocol defined in
§2 is **new design**, and when `FLINTD.ELF` lands in VirelaiOS (FLINT M1) it
should serve this protocol so guest and host are interchangeable endpoints.

## 0. Identity and hard rules

- Binary name: `flintd`. Single static executable, **Zig 0.17.0**, no
  dependencies outside the Zig standard library.
- Targets (must compile and pass the full suite on each):
  `x86_64-linux`, `aarch64-linux`, `aarch64-macos`, `x86_64-macos`.
- **The server holds ADR 0049 stores.** Interior layout is the contract,
  byte-for-byte: `streams/<id>.json`, `streams/<id>.jsonl`. A store copied
  off the server must load in the client and in the guest implementation,
  and `flint verify`/`FLINT.ELF verify` must pass on it. The server never
  writes `ws/` (workspaces are per-host) or `keys/` (the server holds no
  secrets — it verifies signatures, it does not sign).
- **Changes cross the wire as raw JSONL line bytes, verbatim.** The server
  never re-serializes a Change for transport; a pulled `.jsonl` written
  from those bytes is byte-identical to the pushed original, so canonical
  bytes and signatures are trivially preserved.
- Refusal names are the ADR/Go vocabulary (`stream_missing`,
  `stream_exists`, `stale_head`, `change_malformed`, `sig_invalid`,
  `store_too_large`, `stream_malformed`, `stream_torn`,
  `message_invalid`, `usage`, …). Wire additions are listed in §2.5 and
  nowhere else.
- No GPL-family code anywhere (VirelaiOS rule; carries over).

## 1. `flintd` CLI surface

| Verb | Notes |
|---|---|
| `flintd init --store=<dir>` | Create an empty store root (`<dir>/streams/`). Refuses `stream_exists` if already initialized. Prints `flintd: init ok store=<dir>`. |
| `flintd serve --store=<dir> [--listen=<addr:port>] [--stdio] [--auth-key=<file>] [--allow-author=<file>]` | Serve the store. Default listen `127.0.0.1:4748`. Prints `flintd: listening <addr>` (TCP) or `flintd: ready` (stdio). |

Store root resolution: `--store` flag → `FLINT_STORE` env →
`store_not_found` naming where it looked. **No walk-up** — a daemon does
not infer state from cwd. `serve` refuses `store_missing` when `<root>/streams/`
is absent.

Exit codes: `0` success, `1` refusal/error, `2` usage error. CLI refusals
print `flintd: refuse <name>`.

`--stdio` runs one protocol session on stdin/stdout. It exists so the same
protocol can be hung behind any byte-stream transport — a TCP socket on a
POSIX host today, the runner's `--net-tcp-connect-stream` agent channel
(ADR 0044) when `FLINTD.ELF` lands in-guest, an `ssh` forced-command, or a
test harness pipe.

## 2. Wire protocol — `FLINT-SYNC/1`

Newline-delimited JSON over an ordered byte stream. Each line is one
complete JSON object — a request or a response. The framing matches the
agent-channel precedent (ADR 0044: NDJSON on a single stream), so the
protocol is transport-agnostic.

### 2.1 Envelope

Request:

```json
{"op":"read","seq":7,"stream":"<uuid>","after":"<uuid>","limit":256}
```

Response:

```json
{"seq":7,"ok":true,"head":"<uuid>","changes":["<raw line>","<raw line>"],"more":false}
```

Refusal:

```json
{"seq":7,"ok":false,"refuse":"stale_head","detail":""}
```

- `seq` is a client-chosen u32 correlator echoed in the response. One
  request in flight per connection in v1 (no pipelining).
- `ok:true` responses carry verb-specific fields; `ok:false` responses
  carry exactly `refuse` (the ADR name) and `detail` (optional detail
  string, may be empty).
- Any line that is not a well-formed request object refuses `usage`.
  Lines larger than 4 MiB refuse `store_too_large`.
- Wire JSON is emitted with Go `encoding/json`-compatible escaping
  (`<`, `>`, `&`, U+2028/2029) — same rule as store files (client spec
  errata #4).

### 2.2 Verbs

| `op` | Request fields | Response fields | Refusals |
|---|---|---|---|
| `hello` | `proto` | `proto:"FLINT-SYNC/1"`, `server:"flintd"`, `spec_rev:<int>` | `proto_version` on mismatch; `auth_required` when `--auth-key` is set and no `auth` has succeeded |
| `auth` | `nonce`, `hmac` | `ok:true` | `auth_failed`; only present with `--auth-key` (§3.2) |
| `list` | — | `streams:[<record>, …]` | — |
| `heads` | — | `heads:{<id>:<head|null>, …}` | — |
| `open` | `stream` (id or name) | `record:<Stream>` | `stream_missing` |
| `read` | `stream`, `after` (optional change id), `limit` (optional, default 256, max 1024) | `record`, `head`, `changes:[<raw line>,…]`, `more` | `stream_missing`, `change_missing` (unknown `after`) |
| `create` | `record:<Stream>` | `ok:true` | `stream_exists`, `stream_malformed`, `stream_missing`/`change_missing` (bad `forked_from`), `store_io` |
| `append` | `stream` (id), `expected_head` (nullable), `changes:[<raw line>,…]` | `head:<new head>` | `stream_missing`, `stale_head`, `change_malformed`, `sig_invalid`, `message_invalid`, `store_too_large`, `author_not_allowed`, `store_io` |

`stream`/`after` fields take canonical lowercase UUID strings; `open` also
accepts a stream **name**.

`hello` success replies announce `spec_rev`, the server's
protocol-visible spec revision (repo-root `SPECREV`;
`docs/spec-versioning.md`). It is the last field of the ok reply —
after `nonce` when `--auth-key` is set — so an unauthenticated probe
can read it before answering the challenge. The field is additive:
clients must tolerate its absence or a non-integer value as
unannounced, and `proto` remains the only compatibility gate —
`spec_rev` is a drift signal, not negotiation.

### 2.3 `append` semantics — the ADR commit order, verbatim

For each batch `{expected_head, changes[]}` on stream `S`:

1. Re-read `S`'s Stream record (with the ADR roll-forward). If
   `record.head != expected_head` → `stale_head`. An empty batch is
   `change_malformed`.
2. Validate **all** Changes before appending any:
   - `ParseChange` each raw line → `change_malformed` (this covers JSON
     shape, `ops` presence, `ts > 0`, lowercase-hex sig, and sig_msg
     computability).
   - `c.stream == S.id` → else `change_malformed`.
   - Message ≤ 512 bytes valid UTF-8 → `message_invalid`.
   - Parent chain: `changes[0].parent == expected_head`, and each
     subsequent `parent` equals the previous Change's `id` → else
     `change_malformed`.
   - `VerifyChange` each Change (Ed25519, `c.author` key, canonical
     `sig_msg`) → `sig_invalid`. The server's only trust decision is the
     signature — plus the optional `--allow-author` gate (`author_not_allowed`).
   - Total stream change count after append must stay ≤ `MaxChanges`
     (4096) → `store_too_large`.
3. Append the raw lines to `streams/<id>.jsonl` and fsync (the ADR's
   append step; a torn final line is `stream_torn` on next read — the
   same recovery rule).
4. Rewrite `streams/<id>.json` with the new head via the crash-safe write
   (§3.1).

Nothing is appended unless the entire batch validates. `merged` Changes
(the merge records) ride this path unchanged — the server does not
interpret them.

### 2.4 `create` semantics

- Validate the record shape: `id`/`name`/`created` present; `name` is
  `[a-z0-9-]{1,32}`; `id` parses as UUID → else `stream_malformed`.
- Refuse `stream_exists` when `id` or `name` collides with an existing
  stream.
- `forked_from`, when present, must resolve: `forked_from.stream` exists
  (else `stream_missing`) and `forked_from.change` is that stream's head
  or an id in its log or in the resolved fork chain — the guest rule is
  "fork of a non-empty stream at its head"; for transport, require the
  origin change to be reachable from the origin stream's history → else
  `change_missing`.
- `head` may be null (fresh stream) or equal `forked_from.change` (fork).
  Any other non-null head is `stream_malformed`.
- Write `streams/<id>.json` only. The `.jsonl` is created lazily by the
  first `append` — identical to the guest `fork`, which writes no log.

### 2.5 Wire-only refusal names (additions to the vocabulary)

`proto_version`, `auth_required`, `auth_failed`, `author_not_allowed`,
`store_not_found`, `store_missing`, `store_io`. Everything else is the
existing ADR/Go vocabulary — a refusal arriving over the wire prints on
the client as `flint: refuse <name>` with no translation table.

`store_io` means the store filesystem itself failed — permissions, a
read-only store, disk errors — on any op that touches the store. It is
distinct from `*_malformed` names, which mean the record or change
itself failed validation; a `store_io` refusal says nothing about the
request's validity, and the server keeps serving afterwards.

## 3. Host deltas

### 3.1 Filesystem semantics (same rules as the client port)

- `vi.WriteFileSafe` → write `<path>.tmp-<pid>-<rand>`, fsync file, rename
  over destination, fsync the containing directory.
- Append + fsync for `streams/*.jsonl` (never rewritten).
- Store files are created `0644`; the server writes no key material.

### 3.2 Optional auth and author gating

FLINT's integrity model is per-Change Ed25519 signatures; `verify` proves
which key signed, not that the key is trusted. The server v1 mirrors that:

- **No auth by default.** Any well-signed, well-chained Change is
  accepted. Deployment is loopback/LAN or an authenticated tunnel
  (`--stdio` behind `ssh`, or the runner's hermetic `--net`).
- `--auth-key=<file>` enables a challenge round at `hello`: the server
  issues a 16-byte random `nonce`; the client answers
  `auth {nonce, hmac}` where `hmac = HMAC-SHA256(key, "FLINT-SYNC-AUTH/1\x00" || nonce)`.
  Same shape as ADR 0024/0044's `VIRELAIOS-AUTH/1`, new domain string.
  Key file = 64 lowercase hex chars + `\n` — the same format as a client
  signing-key file, though it is a shared secret, not an Ed25519 seed.
  Wrong answer → `auth_failed`, connection closes.
- `--allow-author=<file>` lists lowercase-hex author public keys, one per
  line. When set, `append` additionally refuses `author_not_allowed` for
  any Change whose `author` is not listed.
- The key file and allowlist live **outside** the store root
  (`--auth-key`/`--allow-author` paths are independent of `--store`), so
  the store stays byte-portable with nothing extraneous inside.

### 3.3 Concurrency

One process, one store, connections served serially in accept order; each
`append` takes a per-stream lock around the check+append+record sequence.
A loser of a head race sees `stale_head` — exactly the guest's
single-writer semantics, preserved. No leases, no locking protocol.

### 3.4 What the server does NOT do

- No scanning/parsing (Atoms arrive inside signed Ops; the server treats
  Op payloads as opaque beyond `change_malformed` field validation).
- No merge logic, no `MERGE.json`, no `ws/` — all host-local client state.
- No `keygen`, no signing, no `verify` verb of its own output — signature
  verification happens only as an `append` gate. (`verify` on a server
  store is the client's job: `flint verify --all --store <dir>`.)
- No UUIDv7 minting — stream IDs and Change IDs are client-generated.

## 4. Client deltas (defined here, landed in flint-client)

The client gains remote verbs under its own milestone (cards below).
Remote resolution order: `--remote=<url>` flag → `FLINT_REMOTE` env →
`ws/<name>/REMOTE.json` → `remote_missing` naming where it looked.
`<url>` is `tcp://<host>:<port>`.

| Verb | Notes |
|---|---|
| `clone <remote> --stream=<name\|id> --name=<ws> --src=<dir>` | Init a store, create the stream record(s) — following `forked_from` chains — replay `read` verbatim, then create the workspace. Prints `flint: clone ok stream=<name> changes=<n>`. |
| `push [--remote] [--stream=<s>]` | `create` any streams the server lacks, then `append` the client's unsent suffix. Prints `flint: push ok stream=<s> changes=<n>`; `flint: push up to date`. |
| `pull [--remote] [--stream=<s>]` | `heads`/`read after=<head>`; appends returned raw lines and rolls the local record head forward. Prints `flint: pull ok stream=<s> changes=<n>`; `flint: pull up to date`. Refuses `fork_needed` when the remote head diverges from the local head (neither is a prefix) — the client resolves divergence with `fork`/`merge`, never silent overwrite. |

Every pulled Change is re-verified client-side (`sig_invalid` aborts the
pull and writes nothing) — integrity must not depend on the transport.
Wire refusals print as `flint: refuse <name>`.

`REMOTE.json` shape: `{"remote":"tcp://<host>:<port>","stream":"<id>"}`
— additive fields in `ws/` are host-local and invisible to the guest.

## 5. Conformance suite

| Suite | Source | Pass condition |
|---|---|---|
| Signatures | `testdata/sig/{good,bad}.jsonl, preimage.hex, seed.hex` | `append` accepts every `good` line on a matching store and refuses `sig_invalid` on every `bad` line; recomputed sig_msg equals `preimage.hex`; Ed25519 verify matches the stdlib-independent vectors. |
| Store | ported from `flint_test.go` store legs | Stream record write/load, roll-forward on stale record, torn line → `stream_torn`, 4 MiB / 4096 bounds → `store_too_large`. |
| Protocol | golden NDJSON transcripts in `testdata/sync/` | Recorded request/response sessions replay byte-for-byte (field order, escaping, refusal envelopes). |
| Sync journey | driver script | `flint` A: init→commit→`push`; `flint` B: `clone`→edit→commit→`push` (`stale_head` until `pull`)→`pull`→merge→`push`; A `pull`s; both sides `verify --all` green; server store dir loads read-only in the guest layout. |
| Portability | fixture store | A store produced by `flintd` `create`/`append` is byte-loadable by the client, and vice versa — `streams/*.json` field order and `.jsonl` trailing newlines identical. |

## 6. Suggested card breakdown

Claimable in order (each is landable with its own tests):

| # | Card | Delivers | Suite legs |
|---|---|---|---|
| S1 | Skeleton + wire model + crypto | `build.zig` (0.17), arg parsing, Stream/Change/Op/Span types in Go field order, JSON emit/parse with Go escaping, Ed25519 verify, `ParseChange`/`sigMsg`/`VerifyChange`, torn-append JSONL reader, `flintd init` | Signatures |
| S2 | Store IO | `streams/` layout, `LoadStoreIndex` (streams only), `LoadStream` + roll-forward, crash-safe write + append+fsync, bounds | Store |
| S3 | `FLINT-SYNC/1` server | TCP listener + `--stdio`, NDJSON framing, `hello`/`list`/`heads`/`open`/`read`/`create`/`append` (§2.3 order), refusal envelope | Protocol |
| S4 | Auth + gating | `--auth-key` HMAC challenge, `--allow-author` gate, `auth_required`/`auth_failed`/`author_not_allowed` | Protocol (auth legs) |
| S5 | Client remote verbs | flint-client: `push`/`pull`/`clone`, remote resolution, `REMOTE.json`, wire→CLI refusal mapping | Sync journey (client half) |
| S6 | Interop conformance | `testdata/sync/` goldens, portability checks, end-to-end two-client journey | Sync journey, Portability |

S5 lives in flint-client and depends on M105f plus S3; everything else
lands in this repo in order.

## 7. Explicitly out of scope (v1)

- TLS / transport encryption (loopback, LAN, or `--stdio` under an
  authenticated channel; TLS can layer on later without changing the
  protocol).
- Content store / blob transport, checkout, materialization (FLINT M1
  scope in VirelaiOS).
- `ws/`, `MERGE.json`, `ATOMS.jsonl`/`STAGE.jsonl` sync — workspace state
  stays per-host; only `streams/` replicates.
- Multi-store serving, per-stream ACLs, quotas, rate limits, discovery.
- Trust roots/policy for `author` beyond the optional allowlist — same
  non-goal as the ADR.
- Concurrent-writer semantics beyond serialization (leases stay FLINT M1).
- Any guest change. When `FLINTD.ELF` lands, it adopts §2 — the spec here
  is written to be that protocol.
