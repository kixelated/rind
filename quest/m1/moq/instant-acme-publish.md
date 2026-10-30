# [XS] Publish rind-instant-acme

## Goal

`rind-instant-acme` depends on instant-acme 0.9 from crates.io instead of a
git revision, so release-plz publishes it.

## Plan

Split from [rind-instant-acme](/quest/m1/moq/instant-acme.md) on 2026-10-30
(maintainer), so the adapter lands before the release. Point the dependency
at the release, drop `publish = false` and the `deny.toml` git allowance, and
adapt to any provider change since the pinned revision.

## Required

- [instant-acme 0.9 is released](/quest/m1/moq/instant-acme-release.md) - the release this switches to
- [rind-instant-acme](/quest/m1/moq/instant-acme.md) - the adapter it publishes
