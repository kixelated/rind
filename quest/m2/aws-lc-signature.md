# [L] Signature key pairs

## Goal

`rind::signature` signs and verifies through constants that bind the curve or
padding, the hash, and the signature encoding, replacing
`rind::signing`'s generic `SigningKey<C>::sign::<H>`, its `sign_asn1`
variants, and RSA's method per padding and hash. A key pair is bound to its
signing algorithm when loaded, and no key exposes its curve-level key, so an
ECDSA key can no longer be reused for ECDH through its public `private_key`
field.

## Plan

Part of [Learn from aws-lc-rs's API](/quest/m2/aws-lc-api.md); decisions 1 and
2 of [moq-dev/rind#72](https://github.com/moq-dev/rind/pull/72) shape it.
A sketch following aws-lc-rs:

```rust
pub mod signature {
    // Verification: one sealed trait, one constant per combination a consumer uses.
    pub trait VerificationAlgorithm: Sync + Sealed { .. }
    pub static ECDSA_P256_SHA256_ASN1: EcdsaVerificationAlgorithm; // and P256 x {SHA384, SHA512},
    pub static ECDSA_P384_SHA384_ASN1: EcdsaVerificationAlgorithm; // P384 x {SHA256, SHA512}, both _FIXED
    pub static RSA_PKCS1_2048_8192_SHA256: RsaParameters;          // and SHA384, SHA512, RSA_PSS_2048_8192_*
    pub static ED25519: EdDSAParameters;
    pub struct UnparsedPublicKey<B: AsRef<[u8]>> { .. }
    impl<B: AsRef<[u8]>> UnparsedPublicKey<B> {
        pub fn new(algorithm: &'static dyn VerificationAlgorithm, bytes: B) -> Self;
        pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error>;
    }

    // Signing.
    pub trait KeyPair { type PublicKey: AsRef<[u8]>; fn public_key(&self) -> &Self::PublicKey; }
    pub static ECDSA_P256_SHA256_ASN1_SIGNING: EcdsaSigningAlgorithm; // and _FIXED_SIGNING, P384 SHA384
    pub struct EcdsaKeyPair { .. } // generate(alg), from_pkcs8(alg, der), from_private_key_der(alg, sec1),
                                   // from_private_key_and_public_key(alg, d, q), sign(&self, msg) -> Result<Signature, Error>
    pub static RSA_PKCS1_SHA256: RsaSignatureEncoding;                 // and SHA384, SHA512, RSA_PSS_*
    pub struct RsaKeyPair { .. }   // generate(KeySize), from_pkcs8(der), from_der(pkcs1), public_modulus_len(),
                                   // sign(&self, padding: &'static RsaSignatureEncoding, msg, out: &mut [u8])
    pub struct Ed25519KeyPair { .. } // generate(), from_pkcs8(der), from_seed_unchecked(seed),
                                     // from_seed_and_public_key(seed, pk), seed(), sign(&self, msg) -> Signature
    pub struct Signature { .. } // AsRef<[u8]>
}
```

- Constants carry exactly the combinations consumers use: rustls's webpki
  list (P-256 and P-384 with SHA-256, SHA-384, and SHA-512, ASN.1),
  dimpl's, JWT's ES256 and ES384 (fixed), RSA PKCS#1 and PSS with SHA-256,
  SHA-384, and SHA-512, and Ed25519. No constant names SHA-1, so SHA-1 never
  reaches a signature, as `SignatureHash` ensures today.
- ECDSA and Ed25519 return a `Signature` value instead of filling a caller's
  buffer, removing the too-short-buffer error. RSA follows aws-lc-rs and
  writes `public_modulus_len()` bytes into the caller's buffer, since an
  8192-bit signature is large for the stack.
- The ECDSA message becomes one `&[u8]` as in aws-lc-rs: every consumer
  passes `&[message]`.
- `from_seed_unchecked` names what today's `Ed25519SigningKey::from_bytes`
  skips, and `from_seed_and_public_key` checks a JWK's `x` against its `d`, as
  moq-auth relies on.
- Encodings keep rind's caller-buffer methods (`to_pkcs8_der`,
  `to_spki_der`, `to_pkcs1_der`) on the key pairs. moq-auth also needs the
  ECDSA private scalar to write a JWK's `d`; expose it under aws-lc-rs's name
  for it, `private_key().as_be_bytes()`, or a plainer one the implementation
  argues for.
- `ecdsa::Curve`, `P256`, `P384`, and the public `private_key` and
  `public_key` fields leave the public API.

Migration: `ecdsa::SigningKey::<P256>::from_pkcs8_der(der)` becomes
`EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der)`, and
`sign_asn1::<Sha256>(&[msg], &mut buf)` becomes `sign(msg)`;
`VerifyingKey::<P256>::from_x962_uncompressed(pk)?.verify_asn1::<Sha256>(&[msg], sig)`
becomes `UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pk).verify(msg, sig)`;
`rsa::SigningKey::sign_pss_sha256(&mut buf, msg)` becomes
`RsaKeyPair::sign(&RSA_PSS_SHA256, msg, &mut buf)`;
`Ed25519SigningKey` becomes `Ed25519KeyPair`.

Consumers: `rind-rustls` (`sign.rs`, `verify.rs`), `rind-jsonwebtoken`,
`rind-object-store` (RSA PKCS#1 SHA-256), `rind-rcgen` (P-256), `rind-dimpl`
(`sign.rs`), and the planned `rind-instant-acme`. MoQ: moq-auth's key
generation and JWK import for RSA-2048, P-256, P-384, and Ed25519, which today
mixes aws-lc-rs with the `p256` and `p384` crates.
