# Releases and repository settings

## CI and reports

The CI workflow runs on pull requests and pushes to `main`, on Linux and macOS.
It uses a fixed Zig version, explicit cache configuration, a ten-minute job
deadline, and cancellation of superseded runs. Timing JSON and command logs
are retained as artifacts even on failure. Repeated test runs fail the job on
the first failure, rather than retrying until green.

To investigate, open the commit's **Actions → CI** run, compare `timings.json`
with the prior successful run on the same OS, and download the failing step's
log. These are build/test measurements, not a production monitoring dashboard.
Do not claim sub-ten-minute feedback until real run history confirms it.

## Tag-triggered releases

1. Land a reviewed change with CI green on both platforms.
2. Choose a version matching `build.zig.zon`; update it in a reviewed PR first.
3. Create and push a `vX.Y.Z` tag only with maintainer approval.
4. The release workflow checks version consistency, runs tests, builds all four
   host targets, and publishes archives, SHA-256 checksums, and generated
   GitHub release notes. It uses the scoped Actions token, not a committed PAT.
5. Download and verify the appropriate archive before deploying it.

There is no production deployment target in this repository. Publishing a
release does not demonstrate deployment frequency. Canary rollout, automatic
rollback, deploy dashboards, and production alerting require a concrete host
and operator-owned infrastructure.

## Maintainer setup checklist

These changes require explicit repository administration and are not applied
by local files:

- Protect `main`: require pull requests and owner review, require both CI jobs,
  block force pushes/deletion, and restrict direct pushes including admin bypass.
- Enable private vulnerability reporting and native secret scanning.
- Import the priority/type/area definitions in `.github/labels.json`.
  The manual labels workflow applies them only when an operator runs it.
- Verify CODEOWNERS resolves to an active maintainer.
- Protect `v*` tags so only release maintainers can trigger publication.
- Enable Dependabot alerts and review weekly action-update PRs after the
  seven-day waiting period described in SECURITY.md.
- Configure an automated review provider only after approving its source-code
  access, credentials, and fork-PR policy. No fake review bot is installed.

With a single maintainer, requiring approval from that same account can block
their own PRs. Add an independent reviewer or a reviewed emergency-access policy
before enforcing owner approval. Do not weaken checks silently to get a merge.

## Rollback

Keep the previous binary and a consistent store backup before deployment.
Stop the server before switching binaries or taking/restoring a file-level
backup; stores are single-writer. A binary rollback is safe only if it supports
the current wire/store format. Never truncate JSONL logs as a generic rollback.
Follow the [operations runbook](runbooks/operations.md) for verification.
