// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
#![doc = include_str!("../README.md")]
#![allow(
    clippy::new_without_default,
    clippy::result_unit_err,
    clippy::too_many_arguments
)]
#![forbid(unused_must_use)]
#![warn(
    clippy::alloc_instead_of_core,
    clippy::let_underscore_must_use,
    clippy::ptr_as_ptr,
    clippy::ptr_cast_constness,
    clippy::std_instead_of_core,
    clippy::undocumented_unsafe_blocks,
    clippy::upper_case_acronyms,
    clippy::use_self,
    elided_lifetimes_in_paths,
    missing_docs,
    trivial_numeric_casts,
    unreachable_pub,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

/// Low level operations.
///
/// `unsafe` is allowed only here.
///
/// Examples: elliptic curve field operations,
/// bignum arithmetic.
mod low;

/// Mid-level APIs.
///
/// Examples: elliptic curve group operations.
mod mid;

/// High-level APIs.
///
/// Examples: key encodings, high-level constructions.
mod high;

/// Errors.  Common to all layers.
mod error;

/// Test infrastructure.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod test;

// vvv Public API
pub use error::{Error, KeyRejected};

/// Non-API documentation
#[cfg(doc)]
pub mod doc {
    pub use super::low::inline_assembly_safety;
}

/// Ephemeral key agreement: X25519, and ECDH on P-256 and P-384.
///
/// ```
/// use rind::agreement::*;
///
/// let alice = EphemeralPrivateKey::generate(&X25519).unwrap();
/// let bob = EphemeralPrivateKey::generate(&X25519).unwrap();
///
/// let alice_pub = alice.compute_public_key();
/// let bob_pub = bob.compute_public_key();
///
/// let alice_secret = agree_ephemeral(alice, &UnparsedPublicKey::new(&X25519, bob_pub))
///     .expect("bob gave an invalid public key");
/// let bob_secret = agree_ephemeral(bob, &UnparsedPublicKey::new(&X25519, alice_pub))
///     .expect("alice gave an invalid public key");
///
/// assert_eq!(alice_secret.as_ref(), bob_secret.as_ref());
/// ```
pub mod agreement {
    pub use crate::high::agreement::{
        Algorithm, ECDH_P256, ECDH_P384, EphemeralPrivateKey, PublicKey, SharedSecret,
        UnparsedPublicKey, X25519, agree_ephemeral,
    };
}

/// Key encapsulation: ML-KEM-768.
///
/// ```
/// # fn main() -> Result<(), rind::Error> {
/// use rind::kem::*;
///
/// // The recipient generates a key pair, and sends the encapsulation key to
/// // the sender.
/// let decapsulation_key = DecapsulationKey::generate(&ML_KEM_768)?;
/// let encapsulation_key = decapsulation_key.encapsulation_key();
///
/// // The sender parses the encapsulation key, encapsulates a fresh secret,
/// // and sends the ciphertext back to the recipient.
/// let peer_key = EncapsulationKey::new(&ML_KEM_768, encapsulation_key.key_bytes())?;
/// let (ciphertext, sender_secret) = peer_key.encapsulate()?;
///
/// // The recipient decapsulates the ciphertext, recovering the same secret.
/// let recipient_secret = decapsulation_key.decapsulate(Ciphertext::from(ciphertext.as_ref()))?;
///
/// assert_eq!(sender_secret.as_ref(), recipient_secret.as_ref());
/// # Ok(())
/// # }
/// ```
pub mod kem {
    pub use crate::high::kem::{
        Algorithm, Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768, SharedSecret,
    };
}

/// Public key signatures: ECDSA on P-256 and P-384, RSA, and Ed25519.
///
/// A key pair is bound to its signing algorithm when loaded, and a peer's
/// public key is verified against a verification algorithm constant:
///
/// ```
/// # fn main() -> Result<(), rind::Error> {
/// use rind::signature::*;
///
/// let key_pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)?;
/// let signature = key_pair.sign(b"hello")?;
///
/// let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key_pair.public_key());
/// public_key.verify(b"hello", signature.as_ref())?;
/// # Ok(())
/// # }
/// ```
pub mod signature {
    pub use crate::high::signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED,
        ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P256_SHA384_ASN1, ECDSA_P256_SHA512_ASN1,
        ECDSA_P384_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING,
        ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING, ECDSA_P384_SHA512_ASN1, ED25519,
        EcdsaKeyPair, EcdsaPublicKey, EcdsaSigningAlgorithm, EcdsaVerificationAlgorithm,
        Ed25519KeyPair, Ed25519PublicKey, EdDSAParameters, KeyPair, KeySize, ParsedPublicKey,
        RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
        RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_2048_8192_SHA256,
        RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384,
        RSA_PSS_SHA512, RsaKeyPair, RsaParameters, RsaSignatureEncoding, RsaSubjectPublicKey,
        Signature, UnparsedPublicKey, VerificationAlgorithm,
    };
}

/// Cryptographic hash functions.
///
/// ```
/// use rind::digest;
///
/// let mut ctx = digest::Context::new(&digest::SHA256);
/// ctx.update(b"hello, ");
/// ctx.update(b"world");
/// assert_eq!(
///     ctx.finish().as_ref(),
///     digest::digest(&digest::SHA256, b"hello, world").as_ref(),
/// );
/// ```
pub mod digest {
    pub use super::high::digest::{
        Algorithm, Context, Digest, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512, digest,
    };
}

/// Message authentication with HMAC.
///
/// A [`hmac::Key`] precomputes its keyed hash states once; each message then
/// signs through a [`hmac::Context`] started from it, or the one-shot
/// [`hmac::sign`] and [`hmac::verify`].
///
/// ```
/// use rind::hmac;
///
/// let key = hmac::Key::new(hmac::HMAC_SHA256, b"secret");
///
/// let mut ctx = hmac::Context::with_key(&key);
/// ctx.update(b"hello, ");
/// ctx.update(b"world");
/// let tag = ctx.sign();
///
/// hmac::verify(&key, b"hello, world", tag.as_ref()).unwrap();
/// ```
pub mod hmac {
    pub use super::high::hmac::{
        Algorithm, Context, HMAC_SHA1_FOR_LEGACY_USE_ONLY, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512,
        Key, Tag, sign, verify,
    };
}

/// Key derivation with HKDF.
///
/// A [`hkdf::Salt`] extracts a [`hkdf::Prk`] from a secret, which then expands
/// into any number of keys, each exactly as long as what it becomes.
///
/// ```
/// use rind::{aead, hkdf, hmac};
///
/// let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"salt").extract(b"input key material");
///
/// let aead_key = aead::UnboundKey::from(prk.expand(&[b"aead".as_slice()], &aead::AES_256_GCM).unwrap());
/// let hmac_key = hmac::Key::from(prk.expand(&[b"hmac".as_slice()], hmac::HMAC_SHA256).unwrap());
///
/// let info: [&[u8]; 2] = [b"label", b"context"];
/// let mut bytes = [0u8; 16];
/// prk.expand(&info, bytes.len()).unwrap().fill(&mut bytes).unwrap();
/// ```
pub mod hkdf {
    pub use super::high::hkdf::{Algorithm, HKDF_SHA256, KeyType, Okm, Prk, Salt};
}

/// Authenticated encryption.
///
/// A key is built from an algorithm constant and key bytes, then bound to a
/// nonce policy: [`aead::LessSafeKey`] seals with the caller's nonces, which
/// must never repeat under one key, and [`aead::RandomizedNonceKey`] picks its
/// own.
///
/// ```
/// use rind::aead::*;
///
/// let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &[0x42; 16]).unwrap());
///
/// let mut in_out = b"hello".to_vec();
/// let nonce = || Nonce::assume_unique_for_key([0; 12]);
/// key.seal_in_place_append_tag(nonce(), Aad::from(b"header"), &mut in_out)
///     .unwrap();
///
/// let plaintext = key
///     .open_in_place(nonce(), Aad::from(b"header"), &mut in_out)
///     .unwrap();
/// assert_eq!(plaintext, b"hello");
/// ```
pub mod aead;

/// Unauthenticated ciphers, for protocols that specify one alongside their own integrity protection.
///
/// Prefer [`aead`] unless a protocol requires one of these.
///
/// Unlike aws-lc-rs's `EncryptingKey` and `DecryptingKey` contexts, these are
/// bare keys: QUIC and DTLS header protection and SRTP need nothing more.
pub mod cipher;

/// CPU support.
///
/// Every operation panics on a CPU missing a feature rind requires. Check at
/// startup to refuse cleanly instead:
///
/// ```
/// if let Err(missing) = rind::cpu::check() {
///     eprintln!("{missing}");
///     std::process::exit(1);
/// }
/// ```
pub mod cpu {
    pub use crate::low::cpu::{MissingFeature, check, has_aes_hardware};
}

/// Random bytes from the system's secure random source.
///
/// Unlike aws-lc-rs, there is no `SecureRandom` trait or `SystemRandom`
/// type: no rind API takes a random source, so [`rand::fill`] is all a
/// caller needs.
///
/// ```
/// let mut nonce = [0u8; 16];
/// rind::rand::fill(&mut nonce).unwrap();
/// ```
pub mod rand {
    /// Fills the entirety of `out` with random bytes.
    pub fn fill(out: &mut [u8]) -> Result<(), super::Error> {
        use crate::mid::rng::{RandomSource, SystemRandom};
        SystemRandom.fill(out)
    }
}
