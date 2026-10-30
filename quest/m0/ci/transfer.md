# [XS] Follow the move to moq-dev

## Goal

The repository moved to `moq-dev/rind` on 2026-10-29, and everything that
named `kixelated/rind` follows: crate `repository` fields, docs, quest links,
moq-dev/moq's references, the GitHub apps that review and benchmark it
(Codex, CodSpeed), and the secrets its workflows read.

## Plan

Decided by the maintainer on 2026-10-29, so rind can share moq's
self-hosted queue runner and the organization's runner limits.

- The maintainer transferred it. Installing apps and secrets on the
  organization is theirs; list what is missing and ask.
- Update references in this repository and in moq-dev/moq.
  GitHub redirects old URLs, but crate metadata and docs should name the
  new home before the first crates.io release.
- rind stays a fork of ctz/graviola after the move.
