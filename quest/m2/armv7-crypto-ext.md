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
  path and fall back within a call.
- Prefer verified sources over new assembly, and say where correctness
  comes from.
- Measure on the hosted arm64 runner's armv7 bench job. No dedicated board
  for now (maintainer, 2026-10-30).

Proposed in [moq-dev/rind#84](https://github.com/moq-dev/rind/pull/84),
whose `Decisions needed` the maintainer still owns:

- **Sources.** No formally verified AArch32 code exists: s2n-bignum and its
  HOL Light model are AArch64 and x86_64 only (its verified AES-GCM is
  AArch64), and libcrux has hardware AES only for AArch64 and x86_64. The
  proposed source is aws-lc's AArch32 perlasm (`aesv8-armx`, `ghashv8-armx`,
  and the `_hw` routines of `sha1-armv4-large` and `sha256-armv4`), Apache-2.0
  like the libcrux files already in the arm backend. Its correctness rests on
  its deployment in OpenSSL, BoringSSL, and aws-lc, plus rind's Wycheproof,
  CAVP, and differential tests run against both paths.
- **Toolchain.** Stable Rust gates AArch32 crypto intrinsics, `arm` target
  features, and `is_arm_feature_detected!`. An `asm!` block that opens with
  `.arch armv8-a` and `.fpu crypto-neon-fp-armv8` assembles them on stable,
  in ARM and Thumb mode, without leaking the directive into other blocks.
- **Detection.** `getauxval(AT_HWCAP)` NEON and `getauxval(AT_HWCAP2)` AES,
  PMULL, SHA1, and SHA2, read once on Linux and Android; any other OS, or a
  kernel that omits `AT_HWCAP2`, gets the portable path.
- **Selection.** The arm backend stays the one backend and gains a
  capability token, as x86_64 has for AVX-512 and SHA-NI: AES and AES-GCM
  keys pick hardware or portable when built, and SHA compression checks the
  cached token. `cpu::check()` still requires nothing on armv7.
- **Tests.** CI's armv7 job runs the suite twice, as x86_64 does with
  `RIND_CPU_DISABLE_sha`: once under qemu with a crypto-capable CPU
  (`QEMU_CPU=max`), and once with the features disabled. ctgrind covers the
  hardware key setup.
