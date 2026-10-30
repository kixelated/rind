# [S] Wipe ML-KEM intermediates on armv7

## Goal

armv7's libcrux backend (`mid::arm::mlkem768`) erases ML-KEM-768's
intermediate secrets before they are freed, as the x86_64/aarch64 backend
(`mid::mlkem768`) does: the `G` outputs, the noise seeds and PRF outputs,
the secret polynomials, the re-encryption, and the SHA-3 state.

libcrux-ml-kem 0.0.11 erases none of these, and they live in its own stack
frames, out of rind's reach. Check
[celabshq/libcrux#1332](https://github.com/celabshq/libcrux/pull/1332)
(an opt-in `zeroize` feature for the private key and polynomials, not the
seeds or hash state),
[celabshq/libcrux#1643](https://github.com/celabshq/libcrux/issues/1643)
(the erasure contract), and libcrux-ml-kem's releases; once a release covers
the intermediates, enable it here.

## Plan

Decided by the maintainer on 2026-10-29, from the review of
[kixelated/rind#39](https://github.com/kixelated/rind/pull/39): ML-KEM's
wiping covers both backends.
[moq-dev/rind#52](https://github.com/moq-dev/rind/pull/52) did the
x86_64/aarch64 backend, the SHA-3 contexts, and the buffers rind owns on
armv7; this is the libcrux remainder.

Open, for the maintainer: if upstream stalls, scrub the stack below each
libcrux ML-KEM call instead. The scrub depth would be a measured constant
that stops covering libcrux's frames silently when they grow, so prefer the
upstream fix.
