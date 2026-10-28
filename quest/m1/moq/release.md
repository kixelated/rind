# [S] Release

## Goal

rind and every `rind-*` adapter MoQ uses are published on crates.io through
release-plz, and MoQ's
[covered.md](https://github.com/moq-dev/moq/blob/main/quest/m2/rind/covered.md)
condition holds.

## Plan

The release workflow needs the GitHub App and `CARGO_REGISTRY_TOKEN` secrets
(see `.github/workflows/release.yml`). Reserve each `rind-*` crate name before
its first release if it is not yet taken.

## Required

- [CPU check](/quest/m1/moq/cpu.md) - part of the release
- [HKDF](/quest/m1/moq/hkdf.md) - part of the release
- [SHA-1 and HMAC-SHA1](/quest/m1/moq/sha1.md) - part of the release
- [Raw ciphers](/quest/m1/moq/cipher.md) - part of the release
- [rind-instant-acme](/quest/m1/moq/instant-acme.md) - part of the release
- [Verification](/quest/m1/moq/verify.md) - every backend and adapter proven
