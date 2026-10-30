# [S] Legacy RSA verification

## Goal

rind verifies what ring verifies for compatibility: PKCS#1 v1.5 with SHA-1, 1024-bit moduli for verification only, and a public key given as its `(n, e)` components rather than DER.

## Plan

Decided by the maintainer on 2026-10-30, planning ring and aws-lc-rs parity.

- Verification only; signing keeps rind's 2048-bit floor.
- Name the legacy items as ring does (`..._FOR_LEGACY_USE_ONLY`) so they read
  as discouraged.
