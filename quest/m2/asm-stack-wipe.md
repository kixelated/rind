# [M] Verified assembly leaves no secrets on the stack

## Goal

rind's verified assembly from s2n-bignum and graviola stops leaving secret
state in its own stack frames after returning: Keccak's saved state (208
bytes on x86_64, 768 for the four-way version, a few values on aarch64), and
any other routine that spills a secret, such as x25519.

## Plan

Decided by the maintainer on 2026-10-29, from the follow-ups of
[moq-dev/rind#52](https://github.com/moq-dev/rind/pull/52): m2, since it goes
beyond what aws-lc-rs and other libraries do.

- Inventory which routines spill secrets, per arch, before changing any.
- The issue is reported upstream to s2n-bignum. Prefer an upstream fix
  re-imported through `admin/parse-asm`; don't block on it.
- If rind clears the frames itself, do it outside the verified routines
  (a `low` wrapper that wipes after the call), so the proofs still apply,
  and measure the cost.
- Related: [Scrub the stack after keyed hashing](/quest/m2/stack-scrub.md).
