# [M] Verification

## Goal

Every operation MoQ uses is proven on every backend before the release:
Wycheproof vectors run on x86_64, aarch64, and armv7, differential tests
against aws-lc-rs (a dev-dependency only) cover each primitive, each `rind-*`
adapter has a handshake or round-trip test against its consumer's aws-lc-rs
provider, and `rind-bench` compares every algorithm with aws-lc-rs.

## Plan

Settled (maintainer, 2026-10-26): verification belongs in rind's quests. Each
primitive and adapter quest lands its own tests; this quest closes the gaps
across the surface inherited from graviola and confirms CI runs all of it on
armv7.

Guidance:

- List each public operation against the Wycheproof files that cover it, and
  add a test for any file not yet run.
- Benchmarks feed [Re-measure accepted costs](/quest/m2/remeasure.md).

## Required

- [armv7 on libcrux](/quest/m1/moq/armv7/README.md) - the backend these must also run on
- [rind-rustls covers MoQ](/quest/m1/moq/rustls.md) - adapter under test
- [rind-str0m](/quest/m1/moq/str0m.md) - adapter under test
