---
title: Testing and evidence
parent: index
status: published
summary: Golden transcripts, hostile sockets, and a dogfood loop that files its own issues.
---

# A passing process is not a passing protocol

The gate is `python3 tools/check.py`: formatting, Zig static analysis,
repository policy checks, tooling tests, the build, the test suite,
generated-document checks, and the sync journey — plus a real loopback TCP
server exercised with and without authentication. Run it before landing
anything.

```bash
zig build test --summary all          # unit + conformance suite
python3 tools/check.py                # the full gate
zig test src/store.zig --test-filter 'validators and UUID parsing'
```

## The conformance matrix

| Suite | Source | Pass condition |
|---|---|---|
| Signatures | `testdata/sig/` vectors, copied verbatim from the Go implementation | `append` accepts every `good` line, refuses `sig_invalid` on every `bad` line; recomputed `sig_msg` matches `preimage.hex` |
| Store | Ported `flint_test.go` legs | Record write/load, roll-forward, torn line → `stream_torn`, bounds → `store_too_large` |
| Protocol | Golden NDJSON transcripts in `testdata/sync/` | Request/response sessions replay byte-for-byte: field order, escaping, refusal envelopes |
| Portability | Fixture stores | A store produced by `flintd` is byte-loadable by the client, and vice versa |

Golden responses are byte-identical or the test fails. Fixture names stay
descriptive.

## Three journeys, three temperaments

- `tools/sync-journey` — replays signed push/pull fixtures over `--stdio`.
  Protocol conformance, no sockets, no client needed.
- `tools/e2e` — the spec §5 sync-journey leg. One focused journey, TAP
  output, exits on first failure.
- `tools/live-journey` — the dogfood harness. Broad scenario sweep against
  a live `flintd` over real TCP, keeps going past failures, and writes
  triage-ready findings to `.dogfood/<timestamp>/`.

## The dogfood loop

Scenarios live in `tools/live-journey.d/NNN-name.sh` — each a standalone
bash script on a fresh store, so several agents can add scenarios without
merge conflicts. Each exits `0` PASS, `42` KNOWN, or anything else FAIL.

KNOWN is the velocity feature: encode a known bug's current behavior once,
and the scenario flips to PASS when the fix ships — the harness doubles as
the regression suite. `tools/file-findings` dedupes FAIL findings against
open GitHub issues and drafts issue bodies; `--create` files them with the
`dogfood` label.

## Hostile input, on purpose

`tools/protocol-adversarial.py` sends malformed, out-of-order, oversized,
and racing requests straight at a live socket, then asserts the documented
refusal names, `seq` echo, and state integrity — and that the server keeps
serving afterwards. `tools/tcp-smoke.py` covers the happy path.

<Aside kind="tip">

CI repeats the suite to expose instability, not to mask failures. A flaky
green is a bug report, not a result — diagnose before retrying.

</Aside>
