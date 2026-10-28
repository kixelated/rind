# [S] Release

## Goal

rind and every `rind-*` adapter MoQ uses are published on crates.io through
release-plz, and MoQ's
[covered.md](https://github.com/moq-dev/moq/blob/main/quest/m2/rind/covered.md)
condition holds.

## Plan

The maintainer reset the numbering: every published crate starts at 0.1.0
rather than continuing graviola's, so the first release publishes `rind` 0.1.0
over the 0.0.0 placeholder.

The release workflow authenticates as moq's GitHub App (`moq-bot`) with the
`APP_CLIENT_ID`, `APP_PRIVATE_KEY`, and `CARGO_REGISTRY_TOKEN` secrets, all
configured. The token can publish new crates, so release-plz creates each
`rind-*` adapter on its first release.

## Required

- [CPU check](/quest/m1/moq/cpu.md) - part of the release
- [SHA-1 and HMAC-SHA1](/quest/m1/moq/sha1.md) - part of the release
- [Raw ciphers](/quest/m1/moq/cipher.md) - part of the release
- [rind-instant-acme](/quest/m1/moq/instant-acme.md) - part of the release
- [Verification](/quest/m1/moq/verify.md) - every backend and adapter proven
