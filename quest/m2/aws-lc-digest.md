# [S] Digest constants

## Goal

`rind::digest` hashes through an algorithm constant, a cloneable `Context`,
and a `Digest` value, replacing `rind::hashing`'s `Hash` and `HashContext`
traits, its `HashOutput` enum, and the second set of raw contexts under
`hashing::sha2` and `hashing::sha3`.

## Plan

Part of [Learn from aws-lc-rs's API](/quest/m2/aws-lc-api.md); decisions 1 and
2 of [moq-dev/rind#72](https://github.com/moq-dev/rind/pull/72) shape it.
A sketch following aws-lc-rs:

```rust
pub mod digest {
    pub struct Algorithm { .. } // output_len(), block_len()
    pub static SHA1_FOR_LEGACY_USE_ONLY: Algorithm;
    pub static SHA256: Algorithm;
    pub static SHA384: Algorithm;
    pub static SHA512: Algorithm;

    pub fn digest(algorithm: &'static Algorithm, data: &[u8]) -> Digest;

    #[derive(Clone)] // a clone forks the computation, as rustls's fork() needs
    pub struct Context { .. } // new(algorithm), update(&mut self, data), finish(self) -> Digest
    #[derive(Clone)]
    pub struct Digest { .. } // AsRef<[u8]>, algorithm()
}
```

- `SignatureHash` goes: signature algorithms become constants that name their
  hash ([Signature key pairs](/quest/m2/aws-lc-signature.md)), and none names
  SHA-1, so SHA-1 still cannot reach a signature. Until that quest lands, the
  generic ECDSA API keeps naming hashes through the crate-private trait.
- `HashOutput::ct_equal` and `verify_truncated` have no consumer; tag checks
  go through `hmac::verify`.
- SHA-3 and SHAKE stay crate-private for ML-KEM: no consumer hashes with them.
- The `high::hash` generics stay crate-private underneath, and
  [Reusable HMAC keys](/quest/m2/aws-lc-hmac.md),
  [Typed HKDF output](/quest/m2/aws-lc-hkdf.md), and the signature quest map
  their constants onto them. This also retires two unnameable public types,
  `HashBlock` and `high::hash`'s `Sha256Context`, which shares its name with
  `hashing::sha2::Sha256Context`.
- `Context::update` now matches on the algorithm per call; extend the hashing
  bench with small updates to show it costs nothing measurable.

Migration: `Sha256::hash(data)` becomes `digest::digest(&digest::SHA256, data)`;
`Sha256::new()` or `sha2::Sha256Context::new()` becomes
`digest::Context::new(&digest::SHA256)`; `HashOutput` becomes `Digest`.

Consumers: `rind-rustls` (`hash.rs`), `rind-dimpl` (`digest.rs`),
`rind-object-store`, `rind-str0m` (SHA-1 and SHA-256), and MoQ's moq-relay
ACME cache and certificate fingerprint and moq-hls segment names.
