# Fastest source per cell

## Goal

Every cell of the README's algorithm table runs the fastest source for that
primitive on that backend, preferring a formally verified one when it is as
fast within noise, as `AGENTS.md` requires. Each child is a cell where the
audit found rind off that rule: unverified code slower than or level with a
verified alternative, or code slower than another source.

## Plan

The audit's per-cell numbers are in the PR that created this epic. Each child
re-measures on one head before switching, and updates the README's markers
(✓ verified, ⚡ unverified and measured faster than a verified alternative)
with the code.

## Required

- [ChaCha20-Poly1305 on armv7](/quest/m2/fastest/armv7-chacha20poly1305.md) - aws-lc's NEON assembly, about 3x faster than HACL*'s, for the cipher armv7 without AES hardware prefers
- [SHA-384 and SHA-512](/quest/m2/fastest/sha512.md) - HACL* is 1.25-1.5x faster than Graviola on aarch64 and armv7, and aws-lc faster still
- [P-256 and P-384 scalar multiplication](/quest/m2/fastest/ec-scalar-mul.md) - s2n-bignum's verified routines are as fast as Graviola's on x86_64 and aarch64
- [aarch64 AES-GCM in place](/quest/m2/fastest/aarch64-aes-gcm-in-place.md) - drop the stack copy that keeps s2n-bignum's kernels inside their proof, 7-9% faster
- [x86_64 AES-GCM](/quest/m2/fastest/x86-aes-gcm.md) - aws-lc's is 1.3-1.5x faster without VAES
- [armv7 X25519 and Ed25519](/quest/m2/fastest/armv7-curve25519.md) - dalek is 1.3x faster than HACL* at X25519 and 3.4x at Ed25519 signing
- [armv7 RSA](/quest/m2/fastest/armv7-rsa.md) - aws-lc's Montgomery multiplication, about twice HACL*'s speed
- [ChaCha20 header protection](/quest/m2/fastest/chacha20-block.md) - HACL*'s block function is as fast for one block
