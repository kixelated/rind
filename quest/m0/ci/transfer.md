# [XS] rind moves to moq-dev

## Goal

The repository lives at `moq-dev/rind`, and everything that named
`kixelated/rind` follows: crate `repository` fields, docs, quest links,
moq-dev/moq's references, the GitHub apps that review and benchmark it
(Codex, CodSpeed), and the secrets its workflows read.

## Plan

Decided by the maintainer on 2026-10-29, so rind can share moq's
self-hosted queue runner and the organization's runner limits.

- The transfer is the maintainer's: repository settings, then installing
  the apps and secrets on the organization. This quest waits until it is
  done; check with `gh repo view moq-dev/rind`.
- Then an agent updates references in this repository and in moq-dev/moq.
  GitHub redirects old URLs, but crate metadata and docs should name the
  new home before the first crates.io release.
- rind stays a fork of ctz/graviola after the move.
