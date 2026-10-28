# [M] SHA-1 and raw ciphers on armv7

## Goal

On armv7, rind offers SHA-1, HMAC-SHA1, the raw AES block, ChaCha20, and
AES-CTR through the same API the graviola backend gained, so QUIC header
protection, DTLS record number protection, SRTP, and STUN work on the armv7
release.

## Plan

Settled (maintainer, 2026-10-27): libcrux lacks these, so rind adds them over
libcrux's constant-time primitives rather than excluding WebRTC or QUIC header
protection from armv7.

Guidance:

- The AES block and ChaCha20 should come from the same libcrux code its
  AES-GCM and ChaCha20-Poly1305 use, not a second implementation.
- Run the vectors the graviola-backend quests added for these, under qemu.

## Required

- [libcrux backend](/quest/m1/moq/armv7/backend.md) - the armv7 backend this extends
- [SHA-1 and HMAC-SHA1](/quest/m1/moq/sha1.md) - the API and vectors this matches
- [Raw ciphers](/quest/m1/moq/cipher.md) - the API and vectors this matches
