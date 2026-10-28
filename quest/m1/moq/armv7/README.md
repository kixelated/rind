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
  - RSA PKCS#1 v1.5 signing and verification, as padding over the same HACL
    RSA operations RSA-PSS uses, and RSA key generation;
  - ECDSA P-384 signing, verification, and key generation over libcrux-p384's
    field and scalar arithmetic, with RFC 6979 nonces and constant-time
    inversion;
  - SHA-1, and the raw AES block, ChaCha20, and AES-CTR that QUIC header
    protection and SRTP need.

  These keep moq-auth's RS* and ES384 tokens, moq-cli's default GCS storage,
  and RSA or P-384 TLS keys working on the armv7 release.
- Raspberry Pi 4, CM4, and Zero 2 W lack aarch64 crypto extensions, so they
  run this armv7 build.

Open question for the backend quest: graviola's API also offers operations MoQ
does not use, such as XChaCha20-Poly1305, SHA-3, and SHAKE. "Every operation
the other arches do"
reads as all of them; recommend covering the whole public API so rind's API
is identical on every arch, and ask the maintainer before excluding any.

## Required

- [libcrux backend](/quest/m1/moq/armv7/backend.md) - armv7 builds and passes rind's tests on libcrux's primitives
- [RSA PKCS#1 v1.5 and key generation](/quest/m1/moq/armv7/rsa.md) - over the HACL RSA operations RSA-PSS uses
- [ECDSA P-384](/quest/m1/moq/armv7/p384.md) - signing, verification, and key generation over libcrux-p384's arithmetic
- [SHA-1 and raw ciphers](/quest/m1/moq/armv7/cipher.md) - SHA-1, HMAC-SHA1, the AES block, ChaCha20, and AES-CTR on armv7
