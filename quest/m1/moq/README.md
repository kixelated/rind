# rind covers MoQ

## Goal

A rind release on crates.io carries everything
[MoQ](https://github.com/moq-dev/moq) needs to take all its cryptography from
rind, so no MoQ build compiles C crypto: the new primitives, the CPU check, the
armv7 backend, and every `rind-*` adapter. Each adapter's operations pass
rind's tests on x86_64, aarch64, and armv7 alike; an operation missing on one
arch does not count as covered.

MoQ's side waits on this epic:
[moq-dev/moq `quest/m2/rind/covered.md`](https://github.com/moq-dev/moq/blob/main/quest/m2/rind/covered.md)
checks this directory for remaining quests and crates.io for the release.

## Plan

Decided with the maintainer on 2026-10-26 and 2026-10-27, in MoQ's planning
interview and its rind bootstrap. These are settled; don't ask them again.

Why rind exists: MoQ moves every crate off aws-lc-rs, ring, and the RustCrypto
`hmac`/`sha1`/`sha2`/`p256`/`p384` crates so no build compiles C, including
armv7 Android. Upstream graviola lacks primitives MoQ needs and runs only on
x86_64 and aarch64, so rind owns those gaps. MoQ uses rind's own API plus its
adapter crates, never a ring facade through `[patch.crates-io]`, so a published
crate built with `cargo install` also compiles no C.

Repo:

- A GitHub fork, keeping graviola's history for a later rebase or upstreaming.
  Fork only: no upstream PRs until rind carries MoQ, then revisit
  ([Revisit upstreaming](/quest/m3/upstream.md)).
- Adapters are separate crates named `rind-<consumer>`, so a third-party major
  bump never forces a rind major bump. The prefix keeps them grouped under
  rind's own name rather than borrowing the consumer's.

Targets, refused rather than falling back:

- Exactly one backend compiles per arch, never both in one binary
  (maintainer, 2026-10-26).
- x86_64 and aarch64 run graviola's backend. x86_64 needs aes, ssse3, avx,
  avx2, adx, bmi2, and pclmulqdq; aarch64 needs aes, sha2, pmull, and neon.
- rind exposes a CPU check that names the missing feature
  ([CPU check](/quest/m1/moq/cpu.md)), so MoQ fails at startup instead of
  panicking on its first handshake. Hosts missing a feature are refused, as are
  aarch64 boards without crypto extensions (Raspberry Pi 4, CM4, Zero 2 W),
  which run the armv7 build instead.
- armv7 (Android and Linux gnueabihf) runs libcrux's verified portable Rust
  ([armv7](/quest/m1/moq/armv7/README.md)). armv7 is a phone client or a small
  board publishing a few Mbps, so portable AEAD speed is enough; importing
  aws-lc's armv7 assembly and porting its C was rejected as far more
  unverified code for throughput the role does not need.
- armv7 covers every operation the other arches do, so no adapter or MoQ
  feature carries a per-target exclusion (maintainer, 2026-10-27).
- Every other target fails to compile. wasm32 does not build rind; nothing in
  MoQ needs native crypto there.

Each quest lands the tests for what it adds: Wycheproof vectors where they
exist, differential tests against aws-lc-rs as a dev-dependency, and a
benchmark against aws-lc-rs. [Verification](/quest/m1/moq/verify.md) closes
the gaps across the inherited surface and every backend.

These quests cover every gap MoQ's 2026-10-26 inventory found. If a MoQ area
quest turns up another, add a quest here rather than letting MoQ keep a C or
RustCrypto dependency.

## Required

- [CPU check](/quest/m1/moq/cpu.md) - a public check naming the missing CPU feature, so MoQ refuses at startup
- [HKDF](/quest/m1/moq/hkdf.md) - HKDF-SHA256/384 in rind's API for QUIC tokens, stateless resets, and moq-e2ee
- [SHA-1 and HMAC-SHA1](/quest/m1/moq/sha1.md) - for STUN MESSAGE-INTEGRITY and SRTP AES-CM-HMAC-SHA1-80
- [Raw ciphers](/quest/m1/moq/cipher.md) - the AES block, ChaCha20, and AES-CTR for QUIC and DTLS header protection and SRTP
- [armv7 on libcrux](/quest/m1/moq/armv7/README.md) - armv7 Android and Linux run every operation the other arches do
- [rind-rustls covers MoQ](/quest/m1/moq/rustls.md) - TLS 1.2 and 1.3, every key type MoQ loads, and rustls's QUIC keys
- [rind-rcgen](/quest/m1/moq/rcgen.md) - rcgen's `SigningKey` for self-signed and DTLS certificates
- [rind-object-store](/quest/m1/moq/object-store.md) - object_store's `CryptoProvider` for S3, Azure, and GCS
- [rind-str0m](/quest/m1/moq/str0m.md) - str0m's SRTP, fingerprints, and STUN integrity
- [rind-dimpl](/quest/m1/moq/dimpl.md) - dimpl's DTLS 1.2 and 1.3 suites, key exchange, and record number protection
- [instant-acme 0.9 is released](/quest/m1/moq/instant-acme-release.md) - waiting on the release with a pluggable `CryptoProvider`
- [rind-instant-acme](/quest/m1/moq/instant-acme.md) - instant-acme 0.9's `CryptoProvider`
- [Verification](/quest/m1/moq/verify.md) - Wycheproof, aws-lc-rs differential tests, adapter handshakes, and benchmarks on every backend
- [Release](/quest/m1/moq/release.md) - publish the rind release MoQ switches to
