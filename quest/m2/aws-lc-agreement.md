# [M] Key agreement and KEM constants

## Goal

`rind::agreement` runs ephemeral X25519, P-256, and P-384 ECDH through one key
type picked by an algorithm constant, and `rind::kem` runs ML-KEM-768 the
same way, replacing `rind::key_agreement`'s per-curve modules. An ephemeral
key is still consumed by its one agreement, and the shared secret is no
longer a public field.

## Plan

Part of [Learn from aws-lc-rs's API](/quest/m2/aws-lc-api.md); decisions 1 and
2 of [moq-dev/rind#72](https://github.com/moq-dev/rind/pull/72) shape it.
A sketch following aws-lc-rs:

```rust
pub mod agreement {
    pub struct Algorithm { .. }
    pub static X25519: Algorithm;
    pub static ECDH_P256: Algorithm;
    pub static ECDH_P384: Algorithm;

    pub struct EphemeralPrivateKey { .. } // wiped on drop
    impl EphemeralPrivateKey {
        pub fn generate(algorithm: &'static Algorithm) -> Result<Self, Error>;
        pub fn compute_public_key(&self) -> PublicKey;
    }
    pub struct PublicKey { .. } // AsRef<[u8]>: 32 bytes, or X9.62 uncompressed
    pub struct UnparsedPublicKey<B: AsRef<[u8]>> { .. } // new(algorithm, bytes)
    pub struct SharedSecret { .. } // AsRef<[u8]>, wiped on drop, redacted Debug

    pub fn agree_ephemeral<B: AsRef<[u8]>>(
        my_private_key: EphemeralPrivateKey,
        peer_public_key: &UnparsedPublicKey<B>,
    ) -> Result<SharedSecret, Error>;
}

pub mod kem {
    pub struct Algorithm { .. }
    pub static ML_KEM_768: Algorithm;
    pub struct DecapsulationKey { .. } // generate(alg), encapsulation_key(), decapsulate(self, &Ciphertext)
    pub struct EncapsulationKey { .. } // new(alg, bytes), key_bytes(), encapsulate(&self) -> Result<(Ciphertext, SharedSecret), Error>
    pub struct Ciphertext { .. }
    pub struct SharedSecret { .. }
}
```

- Peer keys are parsed at agreement, against the constant, so a malformed or
  off-curve point and X25519's all-zero output stay errors. A peer key for a
  different constant than the private key is an error too.
- `agree_ephemeral` returns the secret instead of taking aws-lc-rs's KDF
  closure, and `decapsulate` consumes its key; the epic records both
  deviations.
- `x25519`, `p256`, and `p384`'s `StaticPrivateKey` become crate-private, still
  backing ECDSA; no consumer reuses an ECDH key.
- ML-KEM's `#[doc(hidden)]` `keygen_internal`, `encaps_internal`,
  `decaps_internal`, and `Message` leave the public API: a caller-chosen
  encapsulation seed is the misuse they enable. Their Wycheproof and bench
  callers move inside the crate, or behind a test-only path the
  implementation picks.

Migration: `x25519::PrivateKey::new_random()` becomes
`EphemeralPrivateKey::generate(&X25519)`; `public_key()` and
`public_key_uncompressed()` become `compute_public_key()`;
`key.diffie_hellman(&peer)` becomes
`agree_ephemeral(key, &UnparsedPublicKey::new(&X25519, peer_bytes))`, and
`.0` becomes `.as_ref()`. `mlkem768::DecapKey::generate()` becomes
`kem::DecapsulationKey::generate(&ML_KEM_768)`, and so on.

Consumers: `rind-rustls` (`kx.rs` and the X25519MLKEM768 hybrid in
`kx/mlkem.rs`) and `rind-dimpl` (`kx.rs`, which drops its `Private` enum). MoQ
has no direct caller.
