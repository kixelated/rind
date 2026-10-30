//! <h1 align="center">rind-rustls</h1>
//! <img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/picture.png">
//!
//! This crate provides an integration between [rustls](https://github.com/rustls/rustls) and [rind](https://github.com/moq-dev/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).
//!
//! Use it like:
//!
//! ```rust
//! rind_rustls::default_provider().install_default().unwrap();
//! ```
//!
//! And then use rustls as normal.

use rustls::crypto::CryptoProvider;

mod aead;
mod hash;
mod hmac;
mod quic;
mod sign;
mod verify;

/// Supported key exchange algorithms.
pub mod kx;

/// Supported cipher suites.
pub mod suites;

mod ticketer;
pub use ticketer::Ticketer;

/// This is a rustls [`CryptoProvider`] using cryptography from rind.
///
/// This provides the same algorithms as the rustls *ring*-based
/// provider, which are interoperable and safe defaults for modern TLS.
/// It prefers ChaCha20-Poly1305 where rind runs AES without CPU instructions.
pub fn default_provider() -> CryptoProvider {
    let cipher_suites = if rind::cpu::has_aes_hardware() {
        suites::ALL_CIPHER_SUITES
    } else {
        suites::CHACHA20_FIRST
    };
    CryptoProvider {
        cipher_suites: cipher_suites.to_vec(),
        kx_groups: kx::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &RngProvider,
        key_provider: &sign::Provider,
    }
}

#[derive(Debug)]
struct RngProvider;

impl rustls::crypto::SecureRandom for RngProvider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        rind::random::fill(bytes).map_err(|_| rustls::crypto::GetRandomFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_chacha20_without_aes_hardware() {
        // CI runs armv7 on a CPU model with the crypto extension and one
        // without, and names which, so both orders are checked.
        match std::env::var_os("RIND_TEST_ARM_CRYPTO_EXT") {
            Some(expected) => assert_eq!(rind::cpu::has_aes_hardware(), expected == "1"),
            None if cfg!(not(target_arch = "arm")) => assert!(rind::cpu::has_aes_hardware()),
            None => {}
        }

        let expected = if rind::cpu::has_aes_hardware() {
            suites::ALL_CIPHER_SUITES
        } else {
            suites::CHACHA20_FIRST
        };
        assert_eq!(default_provider().cipher_suites, expected);
    }

    #[test]
    fn chacha20_first_reorders_every_suite() {
        let mut all = suites::ALL_CIPHER_SUITES.to_vec();
        let mut chacha20_first = suites::CHACHA20_FIRST.to_vec();
        for suites in [&mut all, &mut chacha20_first] {
            suites.sort_by_key(|suite| u16::from(suite.suite()));
        }
        assert_eq!(all, chacha20_first);
    }
}
