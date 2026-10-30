# m2: later work

## Goal

Work that follows the release MoQ switches to: re-checking the costs accepted
to get there, and API changes deferred past it.

## Required

- [Close measured speed gaps](/quest/m2/perf/README.md) - each speed gap the m1 PRs found is closed or shown not to matter
- [Re-measure accepted costs](/quest/m2/remeasure.md) - ChaCha20-Poly1305 throughput and RSA key generation timing on rind's first release
- [Learn from aws-lc-rs's API](/quest/m2/aws-lc-api.md) - misuse-resistant, reuse-friendly shapes, starting with `aead`
- [armv7 crypto instructions](/quest/m2/armv7-crypto-ext.md) - armv7 uses ARMv8 AES, PMULL, and SHA where the CPU has them
