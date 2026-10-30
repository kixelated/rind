# [S] ctgrind on aarch64

## Goal

`admin/ctgrind` runs on aarch64 in CI, debug and release, so graviola's
aarch64 backend and the adapters are checked for secret-dependent branches and
lookups the way x86_64 is.

## Plan

Decided by the maintainer on 2026-10-29, from the follow-ups of
[kixelated/rind#35](https://github.com/kixelated/rind/pull/35).

- Add an `ubuntu-24.04-arm` debug and release pair to
  `.github/workflows/ctgrind.yml`. Valgrind runs the ARMv8 AES, SHA2, and
  PMULL instructions the backend needs.
- Fix any leak it finds in the same PR, as
  [kixelated/rind#19](https://github.com/kixelated/rind/pull/19) did;
  report one in upstream assembly to graviola or s2n-bignum without blocking
  on the fix.
- Its job checks the marks [kixelated/rind#39](https://github.com/kixelated/rind/pull/39)
  added on the aarch64 backend.
