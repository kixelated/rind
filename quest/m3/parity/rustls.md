# [M] rustls provider parity

## Goal

rind-rustls offers every cipher suite, key-exchange group, and signature scheme that aws-lc-rs's rustls provider does, including secp521r1, ECDSA P-521, and the SECP256R1MLKEM768 and MLKEM768 groups.

## Plan

Decided by the maintainer on 2026-10-30, planning ring and aws-lc-rs parity.

- Compare with the rustls version rind-rustls targets, and list anything
  aws-lc-rs offers only behind a feature.

## Required

- [P-521](/quest/m3/parity/p521.md) - secp521r1 and ECDSA P-521
