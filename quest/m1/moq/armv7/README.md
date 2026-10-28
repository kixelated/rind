# armv7 on libcrux

## Goal

rind builds for `armv7-linux-androideabi` and `armv7-unknown-linux-gnueabihf`
on a libcrux backend that runs every operation the x86_64 and aarch64 backend
does, behind the same public API, so no adapter or MoQ feature carries a
per-target exclusion.

## Plan

Settled with the maintainer (2026-10-26 and 2026-10-27):

- armv7 (Android and Linux gnueabihf) runs libcrux's verified portable Rust:
  AES-GCM, ChaCha20-Poly1305, SHA-2, HMAC, HKDF, X25519, Ed25519, ECDSA P-256,
  RSA-PSS, ML-KEM-768. armv7 is a phone client or a small board publishing a
  few Mbps, so portable AEAD speed is enough; importing aws-lc's armv7
  assembly and porting its C was rejected as far more unverified code for
  throughput the role does not need. libcrux is 0.0.x and only armv7 depends
  on it.
- Exactly one backend compiles per arch, never both in one binary.
- armv7 covers every operation the other arches do, so no adapter or MoQ
  feature carries a per-target exclusion (maintainer, 2026-10-27). Where
  libcrux lacks one, rind adds it over libcrux's constant-time primitives:
  - RSA key generation (PKCS#1 v1.5 signing and verification already share
    graviola's padding over the HACL bignum operations armv7's RSA uses);
  - ECDSA P-384 signing, verification, and key generation over libcrux-p384's
    field and scalar arithmetic, with RFC 6979 nonces and constant-time
    inversion;
  - SHA-1, and the raw AES block, ChaCha20, and AES-CTR that QUIC header
    protection and SRTP need.

  These keep moq-auth's RS* and ES384 tokens, moq-cli's default GCS storage,
  and RSA or P-384 TLS keys working on the armv7 release.
- Raspberry Pi 4, CM4, and Zero 2 W lack aarch64 crypto extensions, so they
  run this armv7 build.
- graviola's operations that no adapter or MoQ uses, SHA-3 and SHAKE, are
  not built on armv7 and fail to compile there (maintainer, 2026-10-27).
  Nothing consumes them, and each would be more unverified code over libcrux;
  add one only when a consumer needs it. XChaCha20-Poly1305 is built, from
  libcrux, because `rind-rustls`'s `Ticketer` uses it.

## Required

- [RSA key generation](/quest/m1/moq/armv7/rsa.md) - over the HACL bignum armv7's RSA signing uses
- [ECDSA P-384](/quest/m1/moq/armv7/p384.md) - signing, verification, and key generation over libcrux-p384's arithmetic
- [SHA-1 and raw ciphers](/quest/m1/moq/armv7/cipher.md) - SHA-1, HMAC-SHA1, the AES block, ChaCha20, and AES-CTR on armv7
