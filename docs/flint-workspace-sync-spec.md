# FLINT workspace-state sync — implementation spec

This is an additive delta to `docs/flint-server-spec.md` §2 and its
client deltas, which land in flint-client. The referenced client contracts
are `docs/flint-client-spec.md` and ADR 0049 §Store.

## 0. Identity and hard rules

- Binary and dependency rules are unchanged: Zig 0.17.0, stdlib only.
- This feature adds opt-in replication of one user's workspace state
  across hosts. It does not change the stream store or FLINT-SYNC/1's
  existing stream operations.
- The only synced artifacts are `WORKSPACE.json`, `ATOMS.jsonl`,
  `STAGE.jsonl`, and `MERGE.json`. Their bytes are opaque to the server;
  clients validate them and preserve their bytes without re-serialization.
- Source file bytes are never synced. They belong to the blob arc:
  `docs/flint-blobs-spec.md` in flint-client.
- Stream logs already replicate through `push`/`pull`; this spec does not
  alter them. Existing stores remain byte-compatible under `streams/`.
- A workspace is a per-user channel identified by `(stream id, ws name)`.
  Pick distinct names to avoid collisions; names are not user identities.
- `ws push` and `ws pull` use the existing `--auth-key` challenge when
  configured. `--allow-author` does not apply: these operations carry no
  signed Changes and make no author/signature trust decision.

## 1. Server deltas

### 1.1 Layout and persistence

The server adds a separate tree; it is not part of the ADR 0049 store:

```text
ws-sync/<stream-uuid>/<ws-name>/<artifact>
```

`<ws-name>` uses `[a-z0-9-]{1,32}`. `<artifact>` is exactly one of the
four names in §0. Every file is one channel record, emitted in this
field order:

```json
{"version":3,"body":"<lowercase hex>","updated":1781300000123}
```

`version` is a positive u64; `body` is the hex encoding of exact artifact
bytes; `updated` is the server's Unix-millisecond write time. There is no
separate version file. The record is rewritten with WriteFileSafe-style
semantics: write a unique temporary file, fsync it, rename over the
channel file, then fsync its containing directory. The body and version
therefore become visible together or not at all.

The serial-accept rule from the server spec applies to workspace
operations. Validate the request and version precondition before writing.
There is no transaction spanning multiple artifacts.

### 1.2 Bounds and refusals

- Decoded `body` is at most 1,800,000 bytes. This permits about 1.2 MiB
  for 4096 Atom lines at the existing ~300-byte estimate, while its
  3,600,000-byte hex form plus envelope stays below the existing 4 MiB
  NDJSON line bound. A longer decoded body refuses `change_too_large`.
- Hex must be lowercase and even-length. Invalid fields or hex refuse
  `usage`; the server does not parse or canonicalize artifact contents.
- The initial channel version is 1. An absent channel has current version
  0. A put must request `version = expected_version + 1`; it succeeds
  only when `expected_version` equals the stored version. Any mismatch,
  including u64 overflow, refuses `ws_conflict` and writes nothing.
- Unknown stream ids refuse existing `stream_missing`. A workspace is
  established by its `WORKSPACE.json` channel. Other artifact puts refuse
  `ws_missing` until that channel exists. Missing get channels refuse
  `ws_missing`; an empty `ws_list` result is success.
- `ws_conflict`, `ws_missing`, and `change_too_large` are wire refusal
  names. Refusals use the existing `{seq,ok:false,refuse,detail}` envelope.
  General request lines over 4 MiB retain `store_too_large`.
- `ws-sync/` is ignored by stream indexing and stream-store serialization.
  It does not change `streams/<id>.json` or `.jsonl`, and older
  implementations that scan only `streams/` ignore it.

## 2. Wire protocol deltas

Append these operations to the existing FLINT-SYNC/1 op table, in this
order: `ws_put`, `ws_get`, `ws_list`. They use the §2.1 envelope, u32
`seq`, one request in flight, and existing Go-compatible JSON escaping.
`artifact` is one of the exact filenames in §1.1.

| `op` | Request fields | Response fields | Refusals |
|---|---|---|---|
| `ws_put` | `stream`, `ws`, `artifact`, `version`, `expected_version`, `body` | `version` | `stream_missing`, `ws_missing`, `ws_conflict`, `change_too_large`, `usage` |
| `ws_get` | `stream`, `ws`, `artifact` | `version`, `body` | `stream_missing`, `ws_missing` |
| `ws_list` | `stream` | `workspaces:[{ws,version,updated},…]` | `stream_missing` |

Example request and success response:

```json
{"op":"ws_put","seq":8,"stream":"<uuid>","ws":"dogfood","artifact":"ATOMS.jsonl","version":4,"expected_version":3,"body":"7b7d0a"}
{"seq":8,"ok":true,"version":4}
```

The request's `version` is the proposed new channel version. It must be
exactly one greater than `expected_version`; the server echoes the accepted
version. The `body` string is lowercase hex for raw file bytes, not JSON
embedded directly in the envelope. No successful put partially changes a
channel.

```json
{"op":"ws_get","seq":9,"stream":"<uuid>","ws":"dogfood","artifact":"ATOMS.jsonl"}
{"seq":9,"ok":true,"version":4,"body":"7b7d0a"}
{"op":"ws_list","seq":10,"stream":"<uuid>"}
{"seq":10,"ok":true,"workspaces":[{"ws":"dogfood","version":4,"updated":1781300000123}]}
```

`ws_list.version` is the greatest current artifact-channel version for
that workspace; `updated` is the greatest stored channel `updated` time.
These are listing summaries, not put preconditions. Rows are sorted by
`ws` ascending. A workspace is listed only when it has a valid
`WORKSPACE.json` channel.

## 3. Client deltas

### 3.1 Verbs and version tracking

Add:

```text
flint ws push [--remote=<url>] [--ws=<n>] [--auth-key=<file>]
flint ws pull [--remote=<url>] [--ws=<n>] [--auth-key=<file>]
```

Workspace selection follows the existing workspace resolver. Remote
resolution is unchanged: `--remote` → `FLINT_REMOTE` → that workspace's
`REMOTE.json` → `remote_missing`. Auth-key resolution is unchanged.
Wire refusals print `flint: refuse <name>` without translation.

Keep per-artifact remote versions in an additive `ws_versions` object in
the local `REMOTE.json`, scoped to its `remote` and `stream`. It is client
metadata, not a synced artifact. A missing entry means version 0. After a
successful put or pull, persist the returned version; discard the map if
the configured remote or stream changes.

`ws push` reads and validates all local artifacts before writing remotely.
For each channel it compares the server version from `ws_get` with the
cached version (0 when absent). A mismatch refuses `ws_conflict`; it does
not silently refresh a stale writer. If bytes match, do not write that
channel. Otherwise put with `expected_version` equal to the cached
version and `version` one greater. A race after the read is refused by the
server's CAS. Send `WORKSPACE.json` first, then `ATOMS.jsonl`,
`STAGE.jsonl`, and `MERGE.json`. Earlier successful artifact puts are not
rolled back if a later put fails.

An absent local `STAGE.jsonl` or `MERGE.json` is encoded as the four
literal bytes `null` (`body:"6e756c6c"`), a sync tombstone. On pull,
`ws_missing` or this tombstone removes that optional local file; retain a
known channel version for a tombstone. Empty file bytes remain distinct
from a tombstone. `WORKSPACE.json` and `ATOMS.jsonl` are required; their
absence remotely refuses `ws_missing`.

### 3.2 Pull safety and output

Before any network request or write, `ws pull` checks the local
`STAGE.jsonl`. If its parsed stage contains any Op, refuse `stage_dirty`
and write nothing. A missing or empty stage is clean. On success, fetch
and validate all four channels before changing files; update
`WORKSPACE.json`, `ATOMS.jsonl`, and `MERGE.json`, and update
`STAGE.jsonl` only for the clean local stage. Apply each file using the
client's WriteFileSafe semantics; remove optional files for missing
channels or tombstones. A crash between file writes is not a multi-file
transaction.

Output lines:

- `flint: ws push ok ws=<n> artifacts=<written-count>` or
  `flint: ws push up to date`
- `flint: ws pull ok ws=<n> artifacts=<changed-count>` or
  `flint: ws pull up to date`
- Refusals use the existing `flint: refuse <name>` line and exit code 1.

Never retry a `ws_conflict` automatically. Source files are not downloaded,
rewritten, or inferred by these verbs.

## 4. Conformance suite

| Leg | Pass condition |
|---|---|
| Wire goldens | Golden NDJSON request/response legs cover successful `ws_put`, `ws_get`, `ws_list`, `ws_missing`, and stale `ws_put` → `ws_conflict`; bytes, field order, and escaping match. |
| Two-host journey | Host A pushes a workspace. Host B pulls it into a clean workspace, edits and commits, then pushes its stream. Host A pulls the stream and verifies the resulting history. |
| Dirty-stage refusal | With a non-empty local stage, `ws pull` refuses `stage_dirty`; byte-compare all workspace artifacts and prove none were written. |
| Portability | A server `ws-sync/` tree is ignored by an older server/client. Stream files remain byte-identical and pass existing store portability checks. |
| Bounds and CAS | A decoded body over 1,800,000 bytes refuses `change_too_large`; wrong `expected_version` refuses `ws_conflict` and preserves the prior channel record. |

## 5. Suggested card breakdown

| Card | Delivers | Suite legs |
|---|---|---|
| W1 | Server `ws-sync/` store, bounds, safe versioned writes, auth integration, three protocol ops | Wire goldens; bounds and CAS |
| W2 | Client `flint ws push/pull`, remote resolution, version metadata, stage guard | Two-host journey; dirty-stage refusal |
| W3 | Cross-version fixtures, byte-compatibility and complete end-to-end coverage | All legs |

All implementation remains Zig 0.17.0 stdlib-only. Client changes land in
flint-client; server changes land in flint-server.

## 6. Explicitly out of scope

- Source file bytes, content storage, checkout, and materialization; see
  `docs/flint-blobs-spec.md` in flint-client.
- Stream log replication changes; existing `push`/`pull` already own it.
- Multi-user shared workspaces. Channels are per-user by convention and
  keyed only by workspace name; collisions are avoided by choosing
  distinct names.
- Realtime sync, leases, and notifications.
- Conflict-free merge or automatic merging of stage state. A stale channel
  write refuses `ws_conflict`; a dirty local stage blocks pull.
- Workspace ACLs, per-workspace auth, author allowlisting, and server-side
  interpretation of workspace artifacts.
