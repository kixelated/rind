# [S] CPU check

## Goal

rind exposes a public check that reports whether the host CPU has every
feature rind's backend needs, and names the first missing one, so MoQ fails at
startup with that name instead of panicking on its first handshake. This is
the shape asked for in
[ctz/graviola#227](https://github.com/ctz/graviola/issues/227).

## Plan

Settled (maintainer, 2026-10-26):

- Unsupported is refused, never a fallback. x86_64 needs aes, ssse3, avx,
  avx2, adx, bmi2, and pclmulqdq; aarch64 needs aes, sha2, pmull, and neon.
- Some VPS hypervisors mask ADX
  ([ctz/graviola#222](https://github.com/ctz/graviola/issues/222)); those hosts
  are refused. aarch64 boards without crypto extensions (Raspberry Pi 4, CM4,
  Zero 2 W) are refused too; they run the armv7 build instead.

Guidance:

- graviola already detects these features and panics in
  `verify_cpu_features`; make that one source of truth for both the panic and
  the public check, so they cannot disagree.
- Return an error type whose `Display` names the feature and the arch, so a
  consumer can surface it as is. Keep the feature list private unless a
  consumer needs it.
- The armv7 backend needs no CPU features, so the check always passes there;
  the same call compiles on every supported arch.
- Test with the `RIND_CPU_DISABLE_*` toggles graviola's tests already use.

Public API: a new CPU check function and its error type.
