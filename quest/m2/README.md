# m2: later work

## Goal

Work that follows the release MoQ switches to: re-checking the costs accepted
to get there, and the speed and armv7 work that does not block it.

## Required

- [Close measured speed gaps](/quest/m2/perf/README.md) - each speed gap the m1 PRs found is closed or shown not to matter
- [Re-measure accepted costs](/quest/m2/remeasure.md) - ChaCha20-Poly1305 throughput and RSA key generation timing on rind's first release
- [Verified AES-GCM setup on aarch64](/quest/m2/aarch64-aes-key-verified.md) - the key schedule and H powers come from verified code, or the gap is recorded
- [armv7 tests in the dev shell](/quest/m2/armv7-test-toolchain.md) - lint and run the armv7 tests locally, as nightly CI does
