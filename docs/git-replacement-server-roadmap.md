# FLINT server end — roadmap for the git-replacement vision

Companion to the client-end vision
([git-replacement-roadmap](https://github.com/drawmeanelephant/flint-client/blob/main/docs/git-replacement-roadmap.md),
merged as flint-client PR #43). This document maps the same goal onto
**flintd**: what the server must grow to back a full Git replacement
that is far better for agent work. Status: **vision document** —
every arc becomes a spec PR for review before work starts.

Read with `docs/flint-server-spec.md` (§2.2 verbs, §2.3 `append`
semantics, §3.2 auth, §3.3 concurrency, §3.4 "does NOT do", §7 out of
scope), `docs/adr-0049.md`, and the merged wave-1 specs
([flint-blobs-spec](https://github.com/drawmeanelephant/flint-client/blob/main/docs/flint-blobs-spec.md)
§4, this repo's `docs/flint-workspace-sync-spec.md`).

## 0. Identity and hard rules

- Binary `flintd`, Zig 0.17.0, standard library only. One static
  binary; the server is optional in FLINT's model (signed patch
  bundles work without it).
- Primary platforms: **macOS, Linux**. VirelaiOS never needs to run
  the server (§6).
- The wire contract grows by **appending ops only**. Envelope, `seq`,
  one-request-in-flight, and the refusal vocabulary are contractual.
  A new client facing an old server maps its unknown-op refusal to
  `proto_version` and degrades, never fails — the degraded-mode rule
  the blobs spec §4 already prescribes. Old clients never send ops a
  server doesn't know, so they never see the refusal.
- No new dependencies for transport security: stdlib crypto only
  (HMAC-SHA256 auth exists; a Noise handshake is implementable from
  `std.crypto` primitives if flintd is ever exposed beyond tunnels).
- Server store rules unchanged: append-only logs, crash-safe writes,
  bounds enforced with contractual refusals. New state lives in new
  top-level dirs, keeping stores byte-portable (the blobs spec's
  portability legs apply by analogy).
- Logging rules from `AGENTS.md` are hard: never log request bodies,
  Changes, key material, HMACs, nonces, authors, or store paths.

## 1. The pitch

A git server today is either ssh + git-shell (OS accounts, shell
surface, per-host setup) or a hosted web product (weight, vendor
lock). flintd is one static binary with HMAC auth, an author
allowlist, bounded stores, and a serial accept loop that idle clients
cannot starve — reads are deadline-bounded, though a stalled reader
of a large `read` response can still hold the loop (writes carry no
deadline). For an agent fleet it adds what no git server has: signed
in-store proposals, per-stream policy, and a contractual machine
protocol. This document lists what flintd still needs to back the
client-end vision end to end.

## 2. Where flintd already beats git servers

| Git-server pain | flintd answer |
|---|---|
| ssh + git-shell: OS accounts, shell attack surface | one binary, no accounts; `--stdio` behind any tunnel (ssh arc T1–T3) |
| `git daemon` is unauthenticated by default | HMAC-SHA256 challenge at `hello` (`--auth-key`, §3.2) |
| No author-level gate | `--allow-author` allowlist enforced at `append` (`author_not_allowed`) |
| Idle connections starve all clients (our own #9) | `--read-timeout` bounds every read; serial accept by design (§3.3) |
| Stores grow forever, unverifiable | bounded logs (4 MiB / 4096 per stream), torn logs refuse, `verify --all` always available client-side |
| Health is guesswork | `tools/healthcheck.py` probes auth handshake, deadline, response hygiene (`--prometheus` mode); invalid-key refusal lives in `tools/tcp-smoke.py` / live-journey 040 |
| PRs live outside the VCS (GitHub/GitLab) | proposals as signed in-store objects (V6, wave 3) |
| Mirrors are fragile scripts | federation is the same append protocol (V7, wave 3) |

## 3. Server gap analysis

"Today" = the §2.2 verb table (`hello`, `auth`, `list`, `heads`,
`open`, `read`, `create`, `append`, `deposit`) plus `--listen` / `--stdio` /
`--auth-key` / `--allow-author` / `--read-timeout` — and a latent
`max_conns` param on `serveTcp` (`main.zig` passes `null`; no flag
exposes it).

Notably, spec §7 already names several gaps as v1 out-of-scope —
**per-stream ACLs, quotas, rate limits, discovery, multi-store
serving, TLS** — so the arcs below are pre-acknowledged future work,
not scope creep.

| Capability | Today | Arc |
|---|---|---|
| blob serving (`blob_put` / `blob_get` / `put_manifest` / `get_manifest`) | spec'd (blobs §4) | wave 1 |
| workspace-state channels (`ws_put` / `ws_get` / `ws_list`) | spec'd (W1–W3) | wave 1 |
| per-stream ACLs (who may push which stream) | `--allow-author` is global | V1 |
| stream namespaces (`team/stream`) | flat stream ids | V1 |
| per-author quotas / rate limits | global store bounds only | V2 |
| whole-store backup / export as a bundle | none | V8 (pairs P1–P2) |
| admin verbs (list streams, gc, backup, offline store audit — signature `verify` stays client-side per spec §3.4) | `init` / `serve` only | V9 |
| observability (structured logs, metrics) | healthcheck probe only | V10 |
| proposals hosting (`propose` / `proposals` / `approve`, signed) | none | V6 (pairs client proposals) |
| server-side policy hooks (wasm/QuickJS pre-append) | none | V12 (pairs G8) |
| federation / mirroring (flintd syncs flintd, discovery) | none | V7 |
| server-side gc scheduling | explicitly out of scope v1 (blobs §8) | V3 |
| archival serving (snapshot + roll-forward on clone) | none | V4 (pairs G5) |
| sparse manifest / blob range serving | `read` has `after`+`limit`; `get_manifest after=` spec'd; no blob ranges | V5 (pairs G9) |
| encrypted transport without a tunnel (Noise, stdlib crypto) | none; tunnels assumed (§7) | V11 |

## 4. Wave plan (server end)

**Wave 1 — foundations (spec'd).** Blob ops (blobs §4) and ws
channels (W1–W3) land server-side with their client arcs.

**Wave 2 — operable server.** V1 per-stream ACLs + namespaces · V2
quotas · V8 backup/export · V9 admin verbs · V10 observability.
Done = one operator can run flintd for a team, see everything, and
restore from a bundle.

**Wave 3 — agent-fleet server.** V6 proposals · V12 policy hooks ·
V7 federation. Done = agent fleets collaborate and review without
leaving the signed store.

**Wave 4 — scale and exposure.** V3 gc scheduling · V4 archival
serving · V5 sparse serving · V11 Noise transport. Done = flintd is
safe to expose and cheap to run at monorepo scale.

## 5. Design notes

### 5.1 Ops append only

New ops join the §2.2 table in order. Old servers refuse unknown
ops (`usage`); new clients map that refusal to `proto_version` and
degrade — never fail. Old clients never send the new ops, so they
never see it. No op is ever renamed or removed; refusal names are
contractual.

### 5.2 Auth model (V1)

The `--auth-key` HMAC challenge stays the transport gate. V1 adds a
per-stream author matrix evaluated at `append`, reusing the existing
`author_not_allowed` refusal — never a new name for the same
condition. Namespaces are a naming convention over stream ids
(`team/stream`); the wire is unchanged. ACL state lives beside the
store root (like `--auth-key`), keeping stores byte-portable; if we
later want signed ACLs, that is a new arc, not a patch.

### 5.3 Quotas (V2)

Enforced at `append` under a distinct refusal — `quota_exceeded`,
a proposed new contractual name the V2 spec assigns. Reusing
`store_too_large` would conflate a permanent bound with a policy
condition, and `change_too_large` is ws-spec-only so far. Per-author
counters live outside the store root (next to `--auth-key`). Quotas
bound abuse, not creativity: defaults off, operator-set.

### 5.4 Proposals (V6)

`proposals/<id>.jsonl` under the store root: a proposal is a signed
record naming a base Change and a target stream; approvals are
signed records by listed authors; merging into the stream is still
`append` — proposals are review surface, not a new history path. The
server validates signatures and field shape, never semantics —
consistent with §3.4's opaque-payload philosophy.

### 5.5 Federation (V7)

A mirror is a client of another flintd: existing `push`/`pull` over
tcp or ssh (T1–T3). V7 adds discovery — which streams a peer serves,
answered by `list` — and conflict policy (fast-forward only;
divergence is a human decision surfaced as a refusal). No new wire
ops unless the V7 spec finds `list` insufficient.

### 5.6 Observability (V10)

Structured JSON logs on stderr — refusals, append outcomes, auth
outcomes — through the dedicated logger's allowlisted fields only
(§0). Never request bodies, Changes, key material, HMACs, nonces,
authors, or store paths. A metrics op is added only if the
healthcheck probe proves log scraping insufficient.

### 5.7 Exposure (V11)

If flintd is ever served beyond loopback/LAN/tunnels, the answer is
a Noise handshake (X25519 + ChaCha20-Poly1305 from `std.crypto`) as
an optional transport mode — no TLS dependency, no protocol change
above the transport. Decided when someone actually needs it; not
before.

## 6. VirelaiOS note and proving ground

flintd targets macOS/Linux. VirelaiOS runs the **client** offline
with bundle sync (P1–P2); `serve --stdio` under a wasm runtime is a
possible embedded relay but not a goal. The dogfood fleet
(fl-sv001 / fl-cl001) is the proving ground: every server arc gets
live-journey scenarios (`tools/live-journey.d/`) before it merges,
and the fleet's flintd on fl-sv001 is upgraded as arcs land.

## 7. Non-goals

- Web UI, HTTP API, anything browser-shaped.
- Git wire-protocol compatibility (the G10 bridge converts at the
  boundary).
- TLS termination; V11 Noise is the exposure story if needed.
- Tenancy as a product: orgs, billing, teams-as-entities. Namespaces
  are naming, not tenancy.

## 8. Open questions

- ACL storage: beside the store root (portable, unsigned) vs inside
  it (signed, travels with the store). Signing favors inside; decide
  in the V1 spec.
- Should `approve` require the approver to pass the target stream's
  ACL? (Probably yes — decide in the V6 spec.)
- V11 Noise vs "always behind a tunnel": decide only when exposure is
  requested.
- Metrics op vs log scraping only: wait for V10 evidence.
- Does V3 (server-side gc) need operator opt-in per store, or a
  global flag? Opt-in feels safer; decide in the V3 spec.
