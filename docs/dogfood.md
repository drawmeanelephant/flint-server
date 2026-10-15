# The dogfood loop

Live, two-instance testing for flintd + flint: real TCP, real client, real
refusals. The goal is discovery throughput — surface pain points fast, file
them, fix them, and let the same scenarios flip from KNOWN to PASS as fixes
land.

## Pieces

- `tools/live-journey` — the runner. Builds both binaries, runs every
  scenario in `tools/live-journey.d/`, and writes structured findings to
  `.dogfood/<timestamp>/` (`findings.jsonl` + `SUMMARY.md` + per-scenario
  logs).
- `tools/live-journey.d/NNN-name.sh` — scenarios. Each is a standalone bash
  script against a live `flintd` on a fresh store. New scenario = new file,
  so several agents can add scenarios in parallel without merge conflicts.
- `tools/file-findings` — triage. Dedupes FAIL findings against open GitHub
  issues and drafts issue bodies; `--create` files them with the `dogfood`
  label. Default is dry-run.

Relationship to the other test entry points: `tools/sync-journey` replays
golden NDJSON over `--stdio` (protocol conformance, no sockets), `tools/e2e`
is the spec §5 sync-journey conformance leg (one focused journey, TAP
output, exits on first failure), and `tools/live-journey` is the dogfood
harness (broad scenario sweep, keeps going past failures, produces
triage-ready findings). They complement rather than replace each other.

## Scenario contract

Scenarios source `tools/live-journey.d/lib.sh` and exit:

| exit | meaning | use |
|---|---|---|
| 0 | PASS | behavior matches spec |
| 42 | KNOWN | reproduces a tracked issue — call `lj_known "#9" expected actual` |
| other | FAIL | new finding — call `lj_fail expected actual` |

KNOWN is the velocity feature: encode a known bug's current behavior once,
and the scenario automatically flips to PASS when the fix ships, so the
harness doubles as the regression suite.

### Authoring notes (learned by calibration, don't relearn)

- The client prints **both** success and refusal lines to **stdout**
  (`flintd` prints its status/refusals to stderr). Use `lj_expect_ok` /
  `lj_expect_refuse`, which already know this.
- `clone` replays atoms into the workspace but **does not materialize
  source files** (issue #32). A cloned client's src dir must be seeded with
  the stream's head state out-of-band before `add` sees anything but
  deletions. `lj_seed_src` writes the two-atom baseline.
- Re-clone always targets a **new** `--name`; an existing ws name refuses
  `ws_exists` before any stream check runs. Fast-forward vs `fork_needed`
  is decided by the local log being a verified prefix of the remote log.
- Two atoms per fixture file: `add` counts atoms, so the first scan of the
  baseline is `new=2`, and editing one value is `modified=1`.

## Local run (loopback)

```sh
tools/live-journey                      # full sweep
tools/live-journey --scenario 020-divergence-reset
tools/file-findings .dogfood/<ts>       # draft issues
tools/file-findings .dogfood/<ts> --create
```

Per AGENTS.md, run `python3 tools/check.py` before landing scenario or
harness changes.

## Two-computer run (Droid Computers)

Droid Computers block inbound ports by default; do not open the firewall.
Use the relay tunnel instead — this also matches the FLINT spec's "no TLS,
run under an already-authenticated channel" stance:

```sh
# on the client computer:
droid computer port-forward flint-server 4748 &   # local 4748 → server's 4748
FLINT_REMOTE=tcp://127.0.0.1:4748 flint clone tcp://127.0.0.1:4748 ...
```

The harness itself is transport-agnostic: point a scenario's remote at the
forwarded port. To run the whole sweep across machines, start `flintd` on
the server computer, keep `port-forward` up on the client computer, and run
`tools/live-journey --no-build` there with scenarios' `lj_start_flintd`
swapped for the remote (a `LJ_REMOTE` override is the intended seam).

## Orchestration (one agent driving the fleet)

The Factory API exposes everything a controller agent needs:

1. **Fleet check** — Droid Computers API: list/wake `flint-server` and
   `flint-client`.
2. **Sync code** — Sessions API: one long-lived session per computer;
   message it `git pull && zig build` on both repos.
3. **Run** — message the client-computer session: `tools/live-journey`.
4. **Triage** — read `.dogfood/<ts>/findings.jsonl`, run `file-findings`,
   review drafts (this is the audit-model step), file with `--create`.
5. **Dispatch** — create a fresh session per filed issue with the fix
   prompt; each opens a PR. Cheap fix capacity means the loop is
   bottlenecked only by scenario coverage — so add scenarios.
6. **Regression** — re-run the sweep; KNOWN scenarios flip to PASS as fixes
   merge.

An Automation (schedule or webhook) targeting the Environment can run step
3–4 unattended once the loop is stable.
