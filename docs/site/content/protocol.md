---
title: Protocol overview
parent: index
status: published
summary: Seven verbs, one correlator, and a refusal vocabulary older than the server.
---

# FLINT-SYNC/1

Newline-delimited JSON over an ordered byte stream. Each line is one
complete JSON object — a request or a response. The framing matches the
agent-channel precedent (ADR 0044), so the protocol is transport-agnostic:
a TCP socket today, an `ssh` forced-command or a test pipe tomorrow. The
same session runs over `--stdio`.

## Envelope

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

`seq` is a client-chosen u32 correlator echoed in the response. One request
in flight per connection — no pipelining in v1. `ok:false` carries exactly
`refuse` (a name from the ADR/Go vocabulary) and an optional `detail`.
Malformed lines refuse `usage`; lines over 4 MiB refuse `store_too_large`.
Wire JSON uses Go `encoding/json`-compatible escaping, same as the store
files.

## The verbs

| `op` | Request fields | Response fields | Refusals |
|---|---|---|---|
| `hello` | `proto` | `proto:"FLINT-SYNC/1"`, `server:"flintd"`, `spec_rev:<int>` | `proto_version`, `auth_required` |
| `auth` | `nonce`, `hmac` | `ok:true` | `auth_failed` |
| `list` | — | `streams:[<record>, …]` | — |
| `heads` | — | `heads:{<id>:<head\|null>, …}` | — |
| `open` | `stream` (id or name) | `record:<Stream>` | `stream_missing` |
| `read` | `stream`, `after`, `limit` (≤1024) | `record`, `head`, `changes`, `more` | `stream_missing`, `change_missing` |
| `create` | `record:<Stream>` | `ok:true` | `stream_exists`, `stream_malformed`, `stream_missing`, `change_missing` |
| `append` | `stream`, `expected_head`, `changes` | `head:<new head>` | `stream_missing`, `stale_head`, `change_malformed`, `sig_invalid`, `message_invalid`, `store_too_large`, `author_not_allowed` |
| `deposit` | `stream` (id or name), `changes` (1–256) | `head:<unchanged>`, `stored:<count>` | `stream_missing`, `change_malformed`, `sig_invalid`, `message_invalid`, `author_not_allowed`, `store_too_large` |

`hello` replies announce `spec_rev`, the server's protocol-visible spec
revision — a drift signal, not negotiation. `proto` remains the only
compatibility gate.

## append is the whole ballgame

For each batch `{expected_head, changes[]}` on a stream:

1. Re-read the Stream record. `record.head != expected_head` →
   `stale_head`. An empty batch is `change_malformed`.
2. Validate **all** Changes before appending any: parse, stream match,
   ≤512-byte UTF-8 message, parent chain, Ed25519 `VerifyChange` against
   the `author` key → `sig_invalid`.
3. Append the raw lines to `streams/<id>.jsonl` and fsync.
4. Rewrite `streams/<id>.json` with the new head via a crash-safe
   write-tmp-fsync-rename-fsync-dir cycle.

Nothing is appended unless the entire batch validates. Changes cross the
wire as raw JSONL bytes, verbatim — the server never re-serializes them,
so canonical bytes and signatures are trivially preserved.

## deposit carries detached lines (spec_rev 3)

A log may hold detached Changes — signed Changes of that stream that are
not on the head's first-parent chain, like a preserved recovery original
or work a merge's signed `merged` link names. `deposit` appends them
without moving the head: every `parent` must root in null, the log, the
stream's `forked_from.change`, or an earlier line in the same batch, and
a parent equal to the current head refuses `change_malformed` — that is
an `append`. Byte-identical resends skip (`stored` counts only new
lines), so an interrupted transfer reconciles by re-sending. Deposited
lines come back through an ordinary `read`.

## What the server refuses to do

- **No keygen, no signing, no `verify`.** Signature checks happen only as
  an `append` gate.
- **No merge logic, no workspaces, no key storage.** `ws/` and `keys/`
  are per-host client state; the server never writes them.
- **No TLS.** Loopback, LAN, or `--stdio` under an already-authenticated
  channel — the spec's stance, not an oversight.
- **No pipelining, no leases.** Connections are served serially; a loser
  of a head race sees `stale_head`, exactly the guest's single-writer
  semantics.

The normative text is `docs/flint-server-spec.md` in the repo. When it and
this page disagree, the spec wins.
