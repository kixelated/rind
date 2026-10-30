# [M] armv7 crypto instructions

## Goal

On armv7, rind uses the ARMv8 AArch32 AES, PMULL, and SHA-1/SHA-256
instructions when the CPU has them, as most 32-bit Android devices and
GitHub's arm64 runners do, and keeps its portable code for cores without
them (Raspberry Pi 4, CM4, Zero 2 W).

## Plan

Decided by the maintainer on 2026-10-30, from
[moq-dev/rind#66](https://github.com/moq-dev/rind/pull/66)'s benchmarks,
where aws-lc-rs ran 10x to 100x faster on AES and SHA-256 using those
instructions.

- Decide the path once at setup from detected capabilities; never try one
  path and fall back within a call. Check
  `rind::cpu` and the "exactly one backend per arch" rule, and propose how
  this fits before writing code.
- Prefer verified sources (s2n-bignum or aws-lc's AArch32 routines, if any)
  over new assembly, and say where correctness comes from.
- Measure on the hosted arm64 runner's armv7 bench job. No dedicated board
  for now (maintainer, 2026-10-30).
