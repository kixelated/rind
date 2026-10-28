# [M] RSA PKCS#1 v1.5 and key generation on armv7

## Goal

On armv7, rind signs and verifies RSA PKCS#1 v1.5 and generates RSA keys
through the same API as the other arches, so moq-auth's RS256/384/512 tokens,
moq-cli's default GCS storage, and RSA TLS keys work on the armv7 release.

## Plan

Settled (maintainer, 2026-10-27): libcrux offers only RSA-PSS, so rind adds
PKCS#1 v1.5 signing and verification as padding over the same HACL RSA
operations RSA-PSS uses, and RSA key generation, rather than excluding RSA
PKCS#1 from armv7.

Guidance:

- Padding is encoding over the verified modular exponentiation; reuse
  graviola's PKCS#1 v1.5 encoding in `mid` if it is backend-independent.
- Verification compares the full encoded message, never parses it.
- graviola's RSA key generation is not constant-time, an accepted cost (see
  [Re-measure accepted costs](/quest/m2/remeasure.md)); armv7's should be no
  weaker. Match graviola's key sizes and public exponent.
- Test with Wycheproof's RSA PKCS#1 v1.5 vectors under qemu, and keys
  generated here round-trip through aws-lc-rs.

## Required

- [libcrux backend](/quest/m1/moq/armv7/backend.md) - the armv7 backend this extends
