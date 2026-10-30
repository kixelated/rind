# Learn from aws-lc-rs's API

## Goal

rind's public API takes what works from aws-lc-rs's: shapes that steer a
caller away from misuse and toward reusing expensive setup. Each module is
compared against its aws-lc-rs counterpart, and the changes worth making land
before rind's first release; the rest are recorded as rejected, with the
reason.

This quest's own work, once every module quest below has merged: rename
`rind::random` to `rind::rand`, make sure each deviation listed below carries
its reason in the docs of the item that deviates, and update the README's
description of the public API.

## Plan

Decided by the maintainer on 2026-10-29, while planning `AesGcm::new`'s
key-length error: they like aws-lc-rs's API because, while confusing at first,
it avoids misuse and promotes reuse.

Decided by the maintainer on 2026-10-30 in
[moq-dev/rind#72](https://github.com/moq-dev/rind/pull/72), which holds the
module-by-module comparison:

- m1, before rind's first release, so MoQ ports to rind once.
- Algorithm constants in every module, one key type per role.
- aws-lc-rs's module names.
- AEAD keys as `UnboundKey`, `LessSafeKey`, and `RandomizedNonceKey`, with
  the randomized-nonce key on XChaCha20-Poly1305.
- HKDF's typed `Okm`, which also accepts a plain length.
- `rind::Error` stays, with an exported `KeyRejected` payload.

### Shared shape

- **Algorithm constants.** Each module takes an aws-lc-rs-style
  `&'static Algorithm` (`aead::AES_128_GCM`, `agreement::X25519`,
  `signature::ECDSA_P256_SHA256_ASN1`, `digest::SHA256`, ...) and has one key
  type per role. The constant fixes the key length and parameters, so a
  16-byte key can no longer select AES-128 in a suite that negotiated
  AES-256, and adapters that pick an algorithm at runtime drop their own
  per-algorithm enums (`rind-dimpl`'s `Aead` and `Private`). The cost: a key
  and a peer key built from two different constants is a runtime error
  rather than a compile error, and each call matches on the algorithm once.
- **aws-lc-rs's module names**: `aead`, `cipher`, `agreement`, `kem`,
  `signature`, `digest`, `hmac`, `hkdf`, `rand`. MoQ's direct callers come
  from aws-lc-rs, so most of their port becomes a path change. `cpu` stays.
- **A facade, not a rewrite.** The new modules wrap the existing `mid` and
  `high` types, which keep graviola's layout and become crate-private, so
  upstream merges still apply.
- **Each module quest migrates every `rind-*` adapter, rind-bench, and fuzz
  in the same PR**, deletes the API it replaces with no shim, and keeps the
  Wycheproof, differential, ctgrind, and zeroing tests passing on the new
  surface.
- **The first release carries it all.** [Release](/quest/m1/moq/release.md)
  waits on this epic, so no published version has the old API.

### Where rind keeps its own shape

Each is a deviation to document on the item:

- No random-source parameters. aws-lc-rs takes `&dyn SecureRandom` and ignores
  it (`_rng` in `EphemeralPrivateKey::generate`, `EcdsaKeyPair::sign`,
  `Ed25519KeyPair::generate_pkcs8`), a leftover of ring's API.
- No KDF closure in key agreement. aws-lc-rs's `agree_ephemeral` passes the
  secret to a closure so it never escapes; rind avoids callback parameters and
  returns a `SharedSecret` that wipes itself on drop instead.
- `rind::Error` stays a matchable enum instead of aws-lc-rs's opaque
  `Unspecified` and `KeyRejected`; see
  [Nameable key errors](/quest/m1/moq/api/error.md).
- Key encodings write into a caller's buffer, as today, instead of aws-lc-rs's
  allocated `Document`s: rind's API does not allocate.
- ML-KEM decapsulation consumes its key, like ephemeral ECDH, where
  aws-lc-rs's `decapsulate` borrows it: rind's only consumer is a TLS key
  share, used once.
- XChaCha20-Poly1305, which aws-lc-rs lacks, backs rind's
  randomized-nonce key, so random nonces carry no birthday bound.

### Rejected

aws-lc-rs shapes with no consumer, kept out until one appears:

- `SealingKey`, `OpeningKey`, `BoundKey`, and `NonceSequence`: every consumer
  derives its nonce from protocol state it already owns (TLS and QUIC
  sequence numbers, SRTP indices, MoQ group and frame).
- `TlsRecordSealingKey` and `TlsRecordOpeningKey`: aws-lc's TLS-specific GCM
  modes check nonces for FIPS 140-3, which rind does not target, and rustls
  already owns the sequence number.
- aws-lc-rs's `cipher` contexts (`EncryptingKey`, `DecryptingKey`) and
  `aead::quic::HeaderProtectionKey`: rind's bare `Aes`, `AesCtr`, and
  `ChaCha20` are already the narrowest shapes `rind-rustls`, `rind-dimpl`, and
  `rind-str0m` need, and dimpl wants a 16-byte mask where
  `HeaderProtectionKey` returns 5 bytes.
- `agreement::PrivateKey` (a static ECDH key) and `agree`: no consumer uses a
  key twice. rind's `StaticPrivateKey` types become private.
- SHA-3 and SHAKE digests, `hmac::Key::generate`, `hkdf::Prk::new_less_safe`,
  and `Salt`/`Prk` from `Okm`: no consumer.

### Consumers

`rind-rustls`, `rind-dimpl`, `rind-str0m`, `rind-jsonwebtoken`,
`rind-object-store`, `rind-rcgen`, and the planned `rind-instant-acme`. MoQ
(moq-dev/moq at `80cafb3`) does not call rind yet; its direct aws-lc-rs and
RustCrypto callers are the planned ones: moq-e2ee (AES-128-GCM, HKDF, HMAC),
moq-quic (Retry integrity and token AEADs, HKDF, HMAC), moq-auth (key
generation and import for HMAC, RSA, ECDSA, Ed25519; `rand`), moq-relay and
moq-hls (SHA-256), moq-rtmp and moq-tokio (HMAC-SHA256), and moq-rtc
(HMAC-SHA1). Since this lands before rind's first release, MoQ ports once,
onto this shape.

## Required

- [AEAD keys bound to an algorithm](/quest/m1/moq/api/aead.md) - `aead` and `cipher` keys take an algorithm constant, with `LessSafeKey` and a randomized-nonce key
- [Nameable key errors](/quest/m1/moq/api/error.md) - every `rind::Error` payload is a type a caller can name
- [Digest constants](/quest/m1/moq/api/digest.md) - `digest::SHA256` and friends replace the `Hash` trait and its duplicate contexts
- [Reusable HMAC keys](/quest/m1/moq/api/hmac.md) - an `hmac::Key` built once, with contexts, `sign`, and `verify`
- [Typed HKDF output](/quest/m1/moq/api/hkdf.md) - `hkdf::Salt`, `Prk`, and an `Okm` whose length matches the key it becomes
- [Key agreement and KEM constants](/quest/m1/moq/api/agreement.md) - ephemeral ECDH and ML-KEM-768 behind `agreement` and `kem`
- [Signature key pairs](/quest/m1/moq/api/signature.md) - ECDSA, RSA, and Ed25519 key pairs and verification algorithms bound to constants
