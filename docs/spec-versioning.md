# Spec versioning — `SPECREV` and downstream pinning

FLINT's wire protocol, store format, and conformance corpus are consumed
verbatim by independent ports (a guest `FLINTD.ELF` serving §2 of
`docs/flint-server-spec.md` is the first). `SPECREV` gives those ports a
pin-able answer to "which protocol do you speak": a single integer that
bumps on every protocol-visible change, plus a tag + corpus story for
reproducing conformance runs.

This file mirrors `docs/spec-versioning.md` in
[drawmeanelephant/flint-client](https://github.com/drawmeanelephant/flint-client)
— the convention is shared, the counters are independent (§5).

## 1. The `SPECREV` file

The repo-root `SPECREV` file contains one decimal integer — the current
protocol-visible spec revision. `src/proto.zig`'s `SpecRev` constant must
equal it (`tools/tests/test_specrev.py` enforces the match), and `flintd`
announces it in every `hello` ok reply:

```json
{"seq":1,"ok":true,"proto":"FLINT-SYNC/1","server":"flintd","spec_rev":1}
```

`FLINT-SYNC/1` is the compatibility gate: a `proto` mismatch refuses
`proto_version` and nothing interoperates. `spec_rev` is a finer-grained
drift signal carried *inside* `/1` — two endpoints with the same `proto`
but different `spec_rev` interoperate, and the delta is exactly the
revision-history rows between the two revs.

## 2. What is protocol-visible

Bump `SPECREV` (+1, no skipping) when a change alters anything a
downstream port or a `flint` peer must reproduce:

- **Wire surface** — `FLINT-SYNC/1` ops, request/response field names
  and shapes, the refusal-name vocabulary, wire bounds (4 MiB lines,
  read limits), auth challenge semantics.
- **Byte contracts** — canonical bytes, domain separators, hash
  construction, Go-compatible JSON escaping, JSONL framing, store layout
  and record fields, crash-safety and torn-line recovery semantics a
  port must mirror.
- **Spec text** — normative changes to `docs/flint-server-spec.md` or
  any `docs/*-spec.md` section a port implements against. (Copied ADRs
  are upstream reference material, not this repo's revision surface.)
- **Corpus** — any change under `testdata/` that alters expected output
  (`sig/` vectors, `sync/` golden transcripts). Adding new fixtures
  counts; the corpus at rev N is the conformance artifact.

Do **not** bump for: internal refactors, test-only changes, CLI/log
wording that adds no wire-visible field, comment/typo fixes, tooling
under `tools/`, or performance work.

Every bump adds one row to the revision history below with the rev, the
change, and the issue/PR that drove it. One row per rev — a PR that
makes several protocol-visible changes still bumps once.

| Rev | Change | Ref |
|---|---|---|
| 1 | `SPECREV` convention; `hello` ok replies announce `spec_rev` | [#34](https://github.com/drawmeanelephant/flint-server/issues/34) |
| 2 | `store_io` refusal name for store filesystem failures (was `stream_malformed`) | [#36](https://github.com/drawmeanelephant/flint-server/issues/36) |
| 3 | `deposit` op; stream logs may carry detached Change lines | [#40](https://github.com/drawmeanelephant/flint-server/issues/40) |

## 3. The `hello` `spec_rev` field

`flintd` emits `spec_rev` as the last field of every `hello` success
reply — including the auth-challenge form, so an unauthenticated probe
can read the rev before answering the nonce challenge:

```json
{"seq":1,"ok":true,"proto":"FLINT-SYNC/1","server":"flintd","spec_rev":1}
{"seq":1,"ok":true,"proto":"FLINT-SYNC/1","server":"flintd","nonce":"<32 hex>","spec_rev":1}
```

The field is **optional and additive** for readers. Clients parse a
non-negative integer `spec_rev` when present and tolerate its absence
(and a non-integer value) as unannounced — never a refusal. `proto`
remains the only hard gate. The client half (`flint version --remote`,
tolerant `spec_rev` parsing) landed in
[flint-client#50](https://github.com/drawmeanelephant/flint-client/issues/50).

## 4. Pinning and the conformance corpus

A downstream port pins a spec revision by pinning a commit:

1. Pick the rev (e.g. `spec_rev=1`). The matching tag is `spec-r<rev>`
   — maintainers tag the commit that lands each bump.
2. Vendor or submodule the repo at that tag. The versioned artifact is
   the tag itself: `docs/` specs plus the full `testdata/` corpus.
3. Run the corpus verbatim — `testdata/sig/*` (Ed25519/sign-preimage
   vectors, copied verbatim from the Go implementation) and
   `testdata/sync/*.ndjson` (byte-exact golden transcripts replayed by
   `src/conformance_test.zig`). A port reimplements the legs, not the
   fixtures. §5 of `docs/flint-server-spec.md` is the acceptance bar.
4. Never modify fixtures locally — a corpus that needs editing to pass
   is a divergence report upstream, not a patch downstream.

Tags: `git tag spec-r<N> <merge-commit>` when `SPECREV` bumps. There is
no release machinery; a signed note on the tag is optional.

## 5. Both repos

`SPECREV` exists independently in `flint-server` and `flint-client`
([flint-client#50](https://github.com/drawmeanelephant/flint-client/issues/50)).
The two revs need not match — each tracks its own repo's
protocol-visible surface. A port pinning the pair records both.
