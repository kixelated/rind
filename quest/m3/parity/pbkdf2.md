# [S] PBKDF2

## Goal

rind derives keys with PBKDF2-HMAC over SHA-1, SHA-256, SHA-384, and SHA-512, with derive and constant-time verify, as ring's `pbkdf2` module does.

## Plan

Decided by the maintainer on 2026-10-30, planning ring and aws-lc-rs parity.

- Build on rind's HMAC; Wycheproof has PBKDF2 vectors.
- Refuse a zero iteration count or an empty output rather than panicking.
