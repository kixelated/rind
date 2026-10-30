# [M] Verified AES-GCM on aarch64

## Goal

rind's aarch64 AES-GCM runs s2n-bignum's formally verified implementation
instead of graviola's unverified one, with no loss of speed against aws-lc-rs.

## Plan

Decided by the maintainer on 2026-10-30, from the survey in
[moq-dev/rind#84](https://github.com/moq-dev/rind/pull/84), which found that
s2n-bignum now has verified AES-GCM for AArch64. The `AGENTS.md` preference
for verified sources favors it.

- Import it through `admin/parse-asm` like rind's other s2n-bignum code, and
  check its interface covers what `mid::aes_gcm` needs (key sizes, in-place
  operation, tag handling).
- Benchmark against the current code and aws-lc-rs, and run Wycheproof, the
  aws-lc-rs cross-checks, and ctgrind on aarch64.
