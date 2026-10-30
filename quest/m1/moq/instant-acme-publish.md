# [XS] Publish rind-instant-acme

## Goal

`rind-instant-acme` depends on instant-acme 0.9 from crates.io instead of a
git revision, so release-plz publishes it.

## Plan

The adapter landed on a pinned instant-acme git revision before the release
(maintainer, 2026-10-30). Point the dependency and dev-dependency at the
release, drop `publish = false`, the README's unpublished note, and the
`deny.toml` git allowance, and adapt to any provider change since the pinned
revision.

## Required

- [instant-acme 0.9 is released](/quest/m1/moq/instant-acme-release.md) - the release this switches to
