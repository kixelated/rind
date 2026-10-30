# m2: later work

## Goal

Work that follows the release MoQ switches to: re-checking the costs accepted
to get there, and API changes deferred past it.

## Required

- [Close measured speed gaps](/quest/m2/perf/README.md) - each speed gap the m1 PRs found is closed or shown not to matter
- [Re-measure accepted costs](/quest/m2/remeasure.md) - ChaCha20-Poly1305 throughput and RSA key generation timing on rind's first release
- [Learn from aws-lc-rs's API](/quest/m2/aws-lc-api.md) - misuse-resistant, reuse-friendly shapes, starting with `aead`
- [Scrub the stack after keyed hashing](/quest/m2/stack-scrub.md) - no spilled chaining value outlives an HMAC call
- [Verified assembly leaves no secrets on the stack](/quest/m2/asm-stack-wipe.md) - Keccak and other s2n-bignum routines clear their frames
- [ctgrind on Keccak's SHA3 path](/quest/m2/keccak-ctgrind.md) - the aarch64 SHA3 instructions run under ctgrind
