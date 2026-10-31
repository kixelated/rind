# [S] Measure x86_64 ML-KEM's AVX-512 sampling

## Goal

x86_64 ML-KEM-768 keeps Graviola's AVX-512 rejection sampling only if it
measures faster than the path rind runs without AVX-512, which samples with
s2n-bignum's verified `mlkem_rej_uniform` and 4-way Keccak-f. Then the README
marks it ⚡, or the code is deleted.

## Plan

No host measured so far has AVX-512 VBMI2: neither the i7-8700 nor the `bench`
workflow's EPYC 7763. On one that does (a recent Xeon, or AMD Zen 4 or
later), time `mlkem768-*` for rind with the AVX-512 path and without it. The
`RIND_CPU_DISABLE_*` toggle only works in debug builds, so deny it with a
temporary release-build switch on a `bench-tmp/` branch.
