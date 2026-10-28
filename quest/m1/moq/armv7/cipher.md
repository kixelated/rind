# [M] Raw ciphers on armv7

## Goal

On armv7, rind offers the raw AES block, ChaCha20, and AES-CTR through the
same API the graviola backend gained, so QUIC header protection, DTLS record
number protection, and SRTP work on the armv7 release.

## Plan

Settled (maintainer, 2026-10-27): libcrux lacks these, so rind adds them over
libcrux's constant-time primitives rather than excluding WebRTC or QUIC header
protection from armv7.

Until this lands, armv7 compiles out `rind::cipher` and its tests with
`cfg(not(target_arch = "arm"))`; remove those gates here.

Guidance:

- The AES block and ChaCha20 should come from the same libcrux code its
  AES-GCM and ChaCha20-Poly1305 use, not a second implementation. As
  published, libcrux-aes 0.0.10 keeps its AES block and CTR modules private,
  and libcrux-chacha20poly1305 0.0.10 keeps HACL*'s ChaCha20 private, so this
  needs libcrux to export them first.
- Run the vectors the graviola-backend quests added for these, under qemu.
