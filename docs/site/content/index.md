---
title: flintd
status: published
summary: A signed-change sync server. It verifies everything and signs nothing.
---

<p class="eyebrow">Field manual / FLINT-SYNC/1</p>

# Verify everything.<br>Sign nothing. {#welcome .hero-heading}

A standalone sync server for FLINT, the agent-native source-control system.
One static Zig binary — standard library only, zero dependencies — that
holds byte-compatible ADR 0049 stores and speaks newline-delimited JSON to
flint-client peers.

<div class="home-actions">
<a href="getting-started.html">Serve your first store</a>
<a href="protocol.html">Read the wire</a>
</div>

<div class="specimen-card">
<div class="specimen-card__header">One binary. No database. No signing keys.</div>
<div class="specimen-card__body">

```bash
zig build
zig-out/bin/flintd init --store=.local/store
zig-out/bin/flintd serve --store=.local/store --listen=127.0.0.1:4748
```

Loopback-only and unauthenticated by default. The server checks an Ed25519
signature on every inbound Change — and holds no keys of its own.

</div>
</div>

## Pick your path

<div class="feature-grid">
<div class="feature-card"><span class="edition-card__tag">01 / Operate</span><h3 id="serve-a-store">Serve a store</h3><p>Init, serve, healthcheck, and the optional auth key — a working loop in five commands.</p><a href="getting-started.html">Start here</a></div>
<div class="feature-card"><span class="edition-card__tag">02 / Wire</span><h3 id="the-wire-protocol">The wire protocol</h3><p>Seven verbs, one refusal vocabulary, raw Change bytes that never get re-serialized.</p><a href="protocol.html">FLINT-SYNC/1</a></div>
<div class="feature-card"><span class="edition-card__tag">03 / Break it</span><h3 id="feed-it-to-the-dogs">Feed it to the dogs</h3><p>Golden transcripts, adversarial sockets, and a dogfood loop that files its own issues.</p><a href="testing.html">Testing and evidence</a></div>
</div>

## The store is the contract

This is source-first software for **macOS and Linux**, built with
**Zig 0.17.0**. The on-disk layout — `streams/<id>.json` and
`streams/<id>.jsonl` — is byte-compatible with the Go reference
implementation in VirelaiOS. A store written here loads there, and
`flint verify` passes on it.

Changes cross the wire as raw JSONL line bytes, verbatim. The server never
re-serializes a Change, so canonical bytes and signatures survive transport
untouched. Its only trust decision is the signature.

- [[getting-started|Start here]] for a running server and a probe.
- [[protocol|Protocol overview]] for the envelope, verbs, and refusals.
- [[testing|Testing and evidence]] for the conformance matrix and dogfood loop.

No tracking, remote fonts, or application framework. This manual is compiled
to static files by [Boris](https://github.com/drawmeanelephant/boris).
