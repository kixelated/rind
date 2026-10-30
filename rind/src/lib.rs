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

/// Public key signatures.
pub mod signing {
    /// RSA signatures.
    pub mod rsa {
        pub use crate::high::rsa::{KeySize, SigningKey, VerifyingKey};
    }

    /// ECDSA signatures.
    pub mod ecdsa {
        pub use crate::high::curve::P384;
        pub use crate::high::curve::{Curve, P256};
        pub use crate::high::ecdsa::{SigningKey, VerifyingKey};
    }

    /// EdDSA signatures.
    pub mod eddsa {
        pub use crate::high::ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};
    }
}

/// Cryptographic hash functions.
pub mod hashing {
    pub use super::high::hash::{
        Hash, HashContext, HashOutput, LegacySha1, Sha256, Sha384, Sha512, SignatureHash,
    };
    pub use super::high::hkdf;
    pub use super::high::hmac;
    pub use super::mid::sha2;
    #[cfg(not(target_arch = "arm"))]
    pub use super::mid::sha3;
}

/// Authenticated encryption.
pub mod aead {
    pub use super::mid::aes_gcm::AesGcm;
    pub use super::mid::chacha20poly1305::ChaCha20Poly1305;
    pub use super::mid::xchacha20poly1305::XChaCha20Poly1305;
}

/// Unauthenticated ciphers, for protocols that specify one alongside their own integrity protection.
///
/// Prefer [`aead`] unless a protocol requires one of these.
pub mod cipher {
    pub use super::mid::aes::{Aes, AesCtr};
    pub use super::mid::chacha20::ChaCha20;
}

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
    pub use crate::low::cpu::{MissingFeature, check};
}

/// Cryptographic-quality random source
pub mod random {
    /// Fills the entirety of `out` with cryptographic-quality random bytes.
    pub fn fill(out: &mut [u8]) -> Result<(), super::Error> {
        use crate::mid::rng::{RandomSource, SystemRandom};
        SystemRandom.fill(out)
    }
}
