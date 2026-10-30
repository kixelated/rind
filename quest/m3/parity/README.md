# ring and aws-lc-rs parity

## Goal

A project on ring or aws-lc-rs can move to rind: rind covers ring's
algorithms with its own API, `rind-ring` offers ring's API for a drop-in
swap, rind-rustls matches aws-lc-rs's rustls provider, and a migration guide
maps each ring and aws-lc-rs item to rind's. aws-lc-rs-only algorithms are
listed and start only when a consumer asks.

This epic's own work, once its children land: the migration guide, a table
from each ring and aws-lc-rs item to rind's equivalent (or to the quest that
adds it, or the reason rind refuses it), linked from the README.

## Plan

Decided by the maintainer on 2026-10-30:

- m3: no named consumer yet beyond anyone who wants to switch.
- rind keeps its own API, shaped after aws-lc-rs by
  [the m1 API epic](/quest/m1/moq/api/README.md); exact name-for-name
  compatibility lives only in `rind-ring`.
- ring's algorithm set first. aws-lc-rs's extras wait for a consumer.
- Out of reach whatever the scope: FIPS validation, and anything that
  exposes C.
- Each new primitive follows `AGENTS.md`: a verified source where one
  exists, Wycheproof vectors, differential tests against aws-lc-rs, ctgrind,
  and a benchmark, on every backend.

## Required

- [PBKDF2](/quest/m3/parity/pbkdf2.md) - PBKDF2-HMAC with SHA-1, SHA-256, SHA-384, and SHA-512
- [SHA-512/256](/quest/m3/parity/sha512-256.md) - the truncated SHA-512 variant
- [Fixed-length ECDSA](/quest/m3/parity/ecdsa-fixed.md) - P1363 signatures and the cross-hash curve pairs
- [Legacy RSA verification](/quest/m3/parity/rsa-legacy.md) - SHA-1 PKCS#1, 1024-bit keys, and keys from their components
- [Constant-time comparison](/quest/m3/parity/constant-time.md) - a public slice comparison
- [QUIC header protection](/quest/m3/parity/quic-hp.md) - header-protection keys for direct QUIC users
- [P-521](/quest/m3/parity/p521.md) - ECDH and ECDSA on P-521
- [rustls provider parity](/quest/m3/parity/rustls.md) - rind-rustls offers what aws-lc-rs's provider does
- [rind-ring](/quest/m3/parity/rind-ring.md) - ring's API on rind, for a drop-in swap
- [Adapter survey](/quest/m3/parity/adapter-survey.md) - which crates with pluggable crypto need a `rind-*` adapter
- [aws-lc-rs extras on demand](/quest/m3/parity/aws-lc-extras.md) - waiting on a consumer for each aws-lc-rs-only algorithm
