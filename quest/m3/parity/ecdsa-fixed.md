# [S] Fixed-length ECDSA

## Goal

rind signs and verifies ECDSA in the fixed-length (P1363, r || s) encoding as well as ASN.1, and covers ring's cross-hash pairs: P-256 with SHA-384, and P-384 with SHA-256.

## Plan

Decided by the maintainer on 2026-10-30, planning ring and aws-lc-rs parity.

- Wycheproof has P1363 vectors for both curves.
- Fit the m1 API epic's signature constants (`ECDSA_P256_SHA256_FIXED` and
  so on).
