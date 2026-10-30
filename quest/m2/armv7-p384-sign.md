# [S] armv7 P-384 signing

## Goal

On armv7, ECDSA P-384 signing is within 1.5x of aws-lc-rs, from 3x today
(2.05 ms against 0.69 ms).

## Plan

Decided by the maintainer on 2026-10-30, from the measurements in
[moq-dev/rind#99](https://github.com/moq-dev/rind/pull/99) (bench run
41131143351, a Neoverse-N2 running the 32-bit build).

armv7 P-384 is fiat-crypto's field and scalar arithmetic under rind's point
formulas, inversion, and table lookup, and Graviola's scalar multiplication
(see the README's algorithm table). Profile first to find which layer costs
the time. Prefer fixes that keep fiat-crypto's verified field arithmetic
(already its 32-bit backend, in `low/generic/p384.rs`), such as a
fixed-base table for the generator. Measure with the `bench` workflow's `armv7` job,
and keep the ctgrind and Wycheproof coverage. ECDH and verify use the same
layers, so report their numbers too.
