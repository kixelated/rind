# [S] armv7 RSA verify

## Goal

On armv7, RSA-2048 signature verification is within 2x of aws-lc-rs, from
17x today (1.31 ms against 76 µs). A TLS certificate chain verifies two or
three RSA signatures per handshake.

## Plan

Decided by the maintainer on 2026-10-30, from the measurements in
[moq-dev/rind#99](https://github.com/moq-dev/rind/pull/99) (bench run
41131143351, a Neoverse-N2 running the 32-bit build).

`rind/src/mid/arm/rsa_pub.rs` calls HACL\*'s `bignum64::mod_exp_vartime` on
every verify. Two likely costs, to confirm with a profile before changing
anything:

- 64-bit limbs on a 32-bit core. HACL\* also ships `bignum32`.
- The Montgomery setup (R² mod n) recomputed per call. HACL\*'s `_precomp`
  variants take it precomputed, so a parsed public key could compute it once.

Stay on HACL\*'s verified bignum, and don't hand-write arithmetic. Measure
with the `bench` workflow's `armv7` job, and keep the zeroing, ctgrind, and
Wycheproof coverage.
