# Contributing

Install Zig 0.17.0 and Python 3.11+, then follow the README quick start.
Development uses only the Zig and Python standard libraries.

1. Create a focused branch and reproduce the issue with a regression test.
2. Follow the naming, ownership, test-location, and compatibility rules in
   [AGENTS.md](AGENTS.md).
3. Run `python3 tools/check.py`. Attach the relevant result and explain any
   environment limitation in the pull request.
4. For protocol/storage changes, run the sync journey and review the normative
   spec, golden transcripts, and signature vectors together.

Install the optional staged-snapshot hook with `bash tools/install-hooks`.
It will refuse to replace an existing pre-commit hook.

## Work tracking

Use the issue forms for bugs and features. Maintainers classify each issue
with one `priority:*`, one `type:*`, and one or more `area:*` labels.
`type:debt` tracks known maintenance obligations; include the affected
invariant, impact, owner, and acceptance test. Link TODO/FIXME/HACK comments
to the tracking issue, for example `TODO(#123): explain the remaining work`.
The policy checker rejects unlinked source markers.

The quality gate rejects files over 1 MiB, Zig source files over 1000 lines,
exact clones of 40 significant lines, and unused declared build dependencies.
AST-based complexity is bounded to 50 decision points per function; retained
`quality.json` reports show the highest-complexity functions first. This is a
conservative branch budget (including catch/orelse, boolean short-circuiting,
and switch arms), not a claim to measure runtime paths. Prefer small helpers
when approaching the limit rather than raising it without a design review.

Do not close intermittent failures by enabling retries or skipping tests.
Open a `type:bug` issue with all three CI test-run reports, platform, seed or
fixture, and reproduction command. Fix the cause and add a regression test.

## Dependency and release changes

Wait at least seven days after a dependency, action, or Zig release before
adopting it. Pin actions to full commit SHAs and review upstream release notes.
The runtime remains standard-library-only unless an explicit design decision
changes that rule. Releases are tag-triggered, not automatic production deploys;
see [releases](docs/releases.md).
