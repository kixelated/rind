# [L] rind-ring

## Goal

A `rind-ring` crate implements ring 0.17's public API on rind, name for name, so a project swaps it in with `use rind_ring as ring` or Cargo's `package` rename, without other code changes.

## Plan

Decided by the maintainer on 2026-10-30, planning ring and aws-lc-rs parity.

- A separate crate per the adapter rule, so a ring 0.18 shape bumps only
  `rind-ring` (maintainer, 2026-10-30).
- Test it with ring's own API tests or examples where their license allows,
  and list any item it cannot offer and why.

## Required

- [PBKDF2](/quest/m3/parity/pbkdf2.md) - ring's `pbkdf2`
- [SHA-512/256](/quest/m3/parity/sha512-256.md) - ring's `digest::SHA512_256`
- [Fixed-length ECDSA](/quest/m3/parity/ecdsa-fixed.md) - ring's fixed and cross-hash ECDSA
- [Legacy RSA verification](/quest/m3/parity/rsa-legacy.md) - ring's legacy RSA
- [Constant-time comparison](/quest/m3/parity/constant-time.md) - ring's `constant_time`
- [QUIC header protection](/quest/m3/parity/quic-hp.md) - ring's `aead::quic`
