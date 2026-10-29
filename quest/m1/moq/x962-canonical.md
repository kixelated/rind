# [S] Reject non-canonical curve points

## Goal

P-256 and P-384 `from_x962_uncompressed` refuse a point whose x or y
coordinate is not below the field prime, on every backend, as SEC1 requires,
so a peer-supplied key or ECDH share has exactly one encoding.

## Plan

Found by [kixelated/rind#23](https://github.com/kixelated/rind/pull/23):
today a coordinate written as x + p is accepted and re-encoded canonically,
on every arch (reproduced on x86_64 with P-384 x = 2 and P-256 x = 5). It is
inherited from graviola. Planned for m1 by the maintainer (2026-10-28): keys
and shares arrive from untrusted peers, so rind refuses rather than
normalizes.

- Fix it in the shared decoding (`mid::p256`, `mid::p384`) and in armv7's
  libcrux P-256 path (`mid::arm::p256`) if it differs, with an error, before
  the on-curve check.
- The comparison against p is on public input, so it need not be constant
  time.
- Test x and y each equal to p and to p + small for both curves on every
  backend, including armv7 under qemu, alongside the existing Wycheproof
  vectors.
- Ask the maintainer before reporting it to graviola.
