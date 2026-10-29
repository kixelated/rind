# [XS] rind-str0m on a str0m release

## Goal

`rind-str0m` depends on a str0m release from crates.io instead of a pinned
git revision, so release-plz publishes it and moq-rtc and moq-ice run WebRTC
media on rind.

## Plan

`rind-str0m` supplies str0m's whole provider, DTLS included through
`rind-dimpl`, against str0m's main branch on dimpl 0.9. Once a release
carries that interface:

- Point `str0m-proto` and the `str0m` and `str0m-aws-lc-rs` dev-dependencies
  at the release, and drop `publish = false`.
- Remove str0m from `allow-git` in `deny.toml`.
- Adapt to any provider change since the pinned revision.

Public API: none beyond the release's own changes.

## Required

- [str0m releases its dimpl 0.9 provider interface](/quest/m1/moq/str0m-release.md) - the release this switches to
