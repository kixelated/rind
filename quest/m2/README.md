# m2: later work

## Goal

Work that follows the release MoQ switches to: re-checking the costs accepted
to get there, and the speed and armv7 work that does not block it.

## Required

- [Close measured speed gaps](/quest/m2/perf/README.md) - each speed gap the m1 PRs found is closed or shown not to matter
- [Re-measure accepted costs](/quest/m2/remeasure.md) - ChaCha20-Poly1305 throughput and RSA key generation timing on rind's first release
- [armv7 crypto instructions](/quest/m2/armv7-crypto-ext.md) - armv7 uses ARMv8 AES, PMULL, and SHA where the CPU has them
- [Verified AES-GCM on aarch64](/quest/m2/aarch64-aes-gcm-verified.md) - s2n-bignum's verified AES-GCM replaces graviola's
- [rind-rustls prefers ChaCha20-Poly1305 without AES](/quest/m2/rustls-armv7-chacha.md) - armv7 cores without the crypto extension pick ChaCha first
