# Security and dependency policy

Report suspected vulnerabilities privately through GitHub's security advisory
reporting for this repository. If private reporting is unavailable, contact
the repository owner privately before opening a public issue. Do not include
keys, authentication transcripts, private changes, or production store copies.

## Threat boundary

FLINT-SYNC/1 provides signature integrity, not transport confidentiality.
Default TCP binding is `127.0.0.1:4748`. Keep that boundary or put the server
behind SSH or another authenticated encrypted tunnel. Do not bind publicly
without a reviewed deployment design. The server serializes connections;
untrusted clients can monopolize a session. Network timeouts and connection
limits must also be enforced by the deployment.

Use both an auth key and an author allowlist for shared deployments.
Provision a 32-byte random auth key through your deployment's secret manager
as a read-only, owner-readable file outside the repository and store, then
pass only its path with `--auth-key`. Do not use an Ed25519 signing seed as the
shared transport key. Rotate by distributing a new key through the secret
manager and restarting both peers during a maintenance window. Never commit
auth files or copy them into a container image.

The server holds no signing secrets. The RFC vectors in `testdata/sig/` are
public test material, not production credentials.

## Logging and data handling

Request logs may contain only the server-generated connection ID, sequence
number, allowlisted operation name, bounded event/outcome names, and counters.
Never log raw requests, commit messages, signed changes, author keys, nonces,
HMACs, auth keys, arbitrary client strings, or store paths. Keep stdout reserved
for the protocol. This allowlist is the log-scrubbing policy, not an assertion
that arbitrary data can safely be passed to a logger.

Stores can contain private source-control metadata. Restrict store, backup,
and diagnostic access to operators. There is no product analytics or tracking
export. Set log/backup retention according to the deployment's data policy;
do not send store contents to an issue tracker or third-party error service.

## Dependencies and supply chain

The runtime is standard-library-only. Wait **at least seven days after release**
before merging updates to Zig, development dependencies, or GitHub Actions.
Review upstream changes and security advisories; urgent exceptions require
an explicit maintainer security decision recorded in the PR.

Pin actions to full commit SHAs. Dependabot proposes action updates weekly;
the waiting period is a merge policy, not a claim that every bot enforces it.
Run all gates on both supported host platforms before upgrading Zig.
Do not add dependencies merely to satisfy readiness metrics.

## Repository controls

Maintainers should enable required pull requests, owner review, required CI
checks, blocked force pushes/deletion, and restricted direct pushes on `main`.
Use the settings checklist in docs/releases.md. Configuration files alone do
not enable GitHub branch protection or private security reporting.
