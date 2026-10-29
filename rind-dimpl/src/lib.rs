//! <h1 align="center">rind-dimpl</h1>
//! <img width="40%" align="right" src="https://raw.githubusercontent.com/kixelated/rind/main/admin/picture.png">
//!
//! This crate provides a [`CryptoProvider`] for [dimpl](https://github.com/algesten/dimpl), backed by [rind](https://github.com/kixelated/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).
//!
//! Build dimpl with `default-features = false`, since its default features compile aws-lc-rs.
//! Then hand the provider to each config:
//!
//! ```rust
//! let config = dimpl::Config::builder()
//!     .with_crypto_provider(rind_dimpl::default_provider())
//!     .build()
//!     .unwrap();
//! ```
//!
//! Or install it for the process with [`CryptoProvider::install_default`].

use dimpl::crypto::CryptoProvider;

mod digest;
mod kx;
mod sign;
mod suite;

/// Returns a dimpl [`CryptoProvider`] backed by rind.
///
/// It negotiates DTLS 1.2 ECDHE-ECDSA and DTLS 1.3 with AES-128-GCM,
/// AES-256-GCM, and ChaCha20-Poly1305, over X25519, P-256, and P-384, and
/// signs with ECDSA P-256 or P-384 keys in PKCS#8 or SEC1 DER.
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        kx_groups: kx::ALL,
        signature_verification: &sign::VERIFIER,
        key_provider: &sign::KEYS,
        secure_random: &digest::RANDOM,
        hash_provider: &digest::HASH,
        hmac_provider: &digest::HMAC,
        cipher_suites: suite::DTLS12,
        dtls13_cipher_suites: suite::DTLS13,
    }
}
