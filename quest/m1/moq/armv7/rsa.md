# [M] RSA key generation on armv7

## Goal

On armv7, rind generates RSA keys through the same `SigningKey::generate` and
`KeySize` API as the other arches, so tools that mint RSA keys work on the
armv7 release.

## Plan

Settled (maintainer, 2026-10-27): rind adds RSA key generation on armv7
rather than excluding it.

armv7 already signs and verifies RSA-PSS and PKCS#1 v1.5: its `mid` RSA runs
the raw RSA operations over HACL*'s `Bignum64` (from `libcrux-hacl-rs`), and
graviola's padding in `high` is shared. What remains is key generation, whose
graviola version (`mid/rsa_priv/generate.rs`) runs on `low::PosInt`
arithmetic that armv7's slim `PosInt` does not carry.

Guidance:

- Build prime generation over the same `Bignum64` operations (modular
  exponentiation for Miller-Rabin, `mod`, `mul`), not new bignum arithmetic.
  `Bignum64` has no general modular inverse or GCD; derive `d` and the CRT
  exponents from what it offers, and say where each step's correctness comes
  from.
- graviola's RSA key generation is not constant-time, an accepted cost (see
  [Re-measure accepted costs](/quest/m2/remeasure.md)); armv7's should be no
  weaker. Match graviola's key sizes and public exponent.
- Re-enable the armv7-gated tests: `rind/tests/crosschecks.rs`'s key
  generation round-trips through aws-lc-rs, `high::rsa`'s key generation smoke
  test, and the `SigningKey` doc example.
