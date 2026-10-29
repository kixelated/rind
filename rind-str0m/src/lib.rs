//! <h1 align="center">rind-str0m</h1>
//! <img width="40%" align="right" src="https://raw.githubusercontent.com/kixelated/rind/main/admin/picture.png">
//!
//! This crate provides a [`CryptoProvider`] for [str0m](https://github.com/algesten/str0m), backed by [rind](https://github.com/kixelated/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).
//!
//! Build str0m with `default-features = false`, since its default features compile aws-lc-rs.
//! Then hand the provider to each connection:
//!
//! ```rust
//! use std::sync::Arc;
//! use std::time::Instant;
//!
//! let rtc = str0m::Rtc::builder()
//!     .set_crypto_provider(Arc::new(rind_str0m::default_provider()))
//!     .build(Instant::now());
//! ```
//!
//! Or install it for the process with [`CryptoProvider::install_default`].

use str0m_proto::crypto::CryptoProvider;

mod dtls;
mod hash;
mod srtp;

/// Returns a str0m [`CryptoProvider`] backed by rind.
///
/// It protects SRTP with AES-128-CM-HMAC-SHA1-80, AEAD-AES-128-GCM, and
/// AEAD-AES-256-GCM, signs STUN with HMAC-SHA1, hashes certificate
/// fingerprints with SHA-1 and SHA-256, and runs DTLS through dimpl on
/// [`rind_dimpl::default_provider`] with a self-signed ECDSA P-256 certificate.
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        srtp_provider: &srtp::SRTP,
        sha1_hmac_provider: &hash::SHA1_HMAC,
        sha1_provider: &hash::SHA1,
        sha256_provider: &hash::SHA256,
        dtls_provider: &dtls::DTLS,
    }
}
