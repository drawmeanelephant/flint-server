---
name: flint-qa
description: Validate flintd CLI, store, authentication, and sync protocol changes using isolated fixtures. Use after changing server behavior or diagnosing interoperability failures.
---

# FLINT server QA

1. Read AGENTS.md and the relevant section of docs/flint-server-spec.md.
2. Confirm `zig version` is 0.17.0. No external services or login are needed.
3. Run the focused inline regression test, then `python3 tools/check.py`.
4. The sync journey creates and cleans its own temporary store. Do not use a
   real server store and do not regenerate signature fixtures.
5. For live TCP validation, initialize `.local/store` once, start the README
   loopback command, and run `python3 tools/healthcheck.py`.
6. For auth changes, run the conformance auth tests and the Python probe tests.
   Never print keys, nonces, HMACs, raw requests, or signed user changes.
7. Check that protocol stdout remains byte-identical, including escaping,
   field order, refusal names, sequence echoes, and trailing newlines.
8. Report commands, exit status, passed tests, platform, and any skipped
   external-client or container check. Stop any server you started.
