# m2: later work

## Goal

Work that follows the release MoQ switches to: re-checking the costs accepted
to get there, and API changes deferred past it.

## Required

- [Close measured speed gaps](/quest/m2/perf/README.md) - each speed gap the m1 PRs found is closed or shown not to matter
- [Re-measure accepted costs](/quest/m2/remeasure.md) - ChaCha20-Poly1305 throughput and RSA key generation timing on rind's first release
- [AEAD keys bound to an algorithm](/quest/m2/aws-lc-aead.md) - `aead` and `cipher` keys take an algorithm constant, with `LessSafeKey` and a randomized-nonce key
- [Nameable key errors](/quest/m2/aws-lc-error.md) - every `rind::Error` payload is a type a caller can name
- [Digest constants](/quest/m2/aws-lc-digest.md) - `digest::SHA256` and friends replace the `Hash` trait and its duplicate contexts
- [Reusable HMAC keys](/quest/m2/aws-lc-hmac.md) - an `hmac::Key` built once, with contexts, `sign`, and `verify`
- [Typed HKDF output](/quest/m2/aws-lc-hkdf.md) - `hkdf::Salt`, `Prk`, and an `Okm` whose length matches the key it becomes
- [Key agreement and KEM constants](/quest/m2/aws-lc-agreement.md) - ephemeral ECDH and ML-KEM-768 behind `agreement` and `kem`
- [Signature key pairs](/quest/m2/aws-lc-signature.md) - ECDSA, RSA, and Ed25519 key pairs and verification algorithms bound to constants
- [Learn from aws-lc-rs's API](/quest/m2/aws-lc-api.md) - the module quests above land as one breaking release, then `rand` and the README follow
- [armv7 crypto instructions](/quest/m2/armv7-crypto-ext.md) - armv7 uses ARMv8 AES, PMULL, and SHA where the CPU has them
