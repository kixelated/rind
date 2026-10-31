# m2: later work

## Goal

Work that follows the release MoQ switches to: re-checking the costs accepted
to get there, and the speed and armv7 work that does not block it.

## Required

- [Re-measure accepted costs](/quest/m2/remeasure.md) - ChaCha20-Poly1305 throughput and RSA key generation timing on rind's first release
- [Fastest source per cell](/quest/m2/fastest/README.md) - every algorithm cell runs its fastest source, verified when as fast
- [Check in-place kernels on every s2n-bignum bump](/quest/m2/in-place-check.md) - CI re-runs the aliasing and constant-time walker over aarch64 AES-GCM
