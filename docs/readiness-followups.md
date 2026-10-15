# Readiness follow-ups

Repository-side checks, documentation, hooks, CI, release packaging, redacted
request correlation, read-only probes, and development profiling are configured.
This is not a new scored readiness audit and does not assert deployed services.

## Needs maintainer action

- Review and merge the workflow files, then inspect real Linux/macOS run history.
  Local timings do not prove fast hosted CI or frequent deployment.
- Apply branch/tag protection and choose an independent reviewer before requiring
  CODEOWNER approval. Run the manual label workflow to create the taxonomy.
- Verify the devcontainer when a Docker daemon is available. Its configuration
  is not proof that a container was built here.
- Choose and authorize a PR/security-review provider, including source access,
  credentials, fork behavior, and where readable assessments are retained.
  Zig is not supported by every SAST provider; do not install an empty scan.

## Needs measured design work

- Add source coverage using a validated Zig-compatible tool on the target
  platform. Measure the baseline before selecting an enforced threshold.
  There is deliberately no invented coverage percentage or skip workaround.
- Define the real deployment host, log sink, secret manager, collector, paging
  destination, and rollback procedure. The probe exposes operational metrics,
  but no hosted dashboard, error tracker, or alert destination exists here.
- FLINT-SYNC/1 is TCP/stdio, so its actual JSON Schema is supplied rather than
  an OpenAPI document describing nonexistent HTTP endpoints.
- Add feature flags only for a real risky feature and its cleanup lifecycle.
  Do not change the v1 signing, authentication, or store contracts for a metric.
- Product analytics and error-to-issue exports require a privacy and operational
  decision. No user data or source-control metadata is sent to outside systems.

Release cadence, production observability, automated rollouts, contextual error
tracking, and actual review-bot activity cannot be established by local files
alone. Track each selected follow-up as a labeled issue with an owner and
measurable acceptance criteria.
