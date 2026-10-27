# [S] Re-measure accepted costs

## Goal

The costs accepted to adopt rind are re-measured on rind's first release, and
each is either still acceptable, with the numbers recorded in the PR, or
becomes a quest to fix it.

## Plan

Accepted by the maintainer on 2026-10-26, from
[kixelated/rust2#13](https://github.com/kixelated/rust2/pull/13):

- ChaCha20-Poly1305 on graviola is 1.7-3x slower per packet than aws-lc. It
  matters only for peers without AES hardware.
- graviola's RSA key generation is not constant-time.

Measure with `rind-bench` against aws-lc-rs on x86_64 and aarch64, at QUIC
packet sizes, and check whether RSA key generation timing still varies with
the key.

## Required

- [Release](/quest/m1/moq/release.md) - the first release these are measured on
