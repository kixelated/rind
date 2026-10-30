//! <h1 align="center">rind-rcgen</h1>
//! <img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/picture.png">
//!
//! This crate provides an ECDSA P-256 signing key for [rcgen](https://github.com/rustls/rcgen), backed by [rind](https://github.com/moq-dev/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).
//!
//! Build rcgen with `default-features = false` so it compiles no other crypto backend.
//! rcgen then needs each certificate's serial number set explicitly.
//!
//! ```rust
//! let key = rind_rcgen::KeyPair::generate().unwrap();
//!
//! let mut serial = [0u8; 16];
//! rind::random::fill(&mut serial).unwrap();
//!
//! let mut params = rcgen::CertificateParams::new(["localhost".to_string()]).unwrap();
//! params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
//!
//! let cert = params.self_signed(&key).unwrap();
//! let key = key.to_pkcs8_der().unwrap();
//! ```

use core::fmt;

use rind::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
use rustls_pki_types::PrivatePkcs8KeyDer;

/// An ECDSA P-256 key pair that signs rcgen certificates with SHA-256.
pub struct KeyPair(EcdsaKeyPair);

impl KeyPair {
    /// Generate a random key pair.
    pub fn generate() -> Result<Self, rind::Error> {
        EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).map(Self)
    }

    /// Encode the private key as PKCS#8 DER, the form rustls loads.
    pub fn to_pkcs8_der(&self) -> Result<PrivatePkcs8KeyDer<'static>, rind::Error> {
        let mut buffer = [0u8; 256];
        let der = self.0.to_pkcs8_der(&mut buffer)?;
        Ok(PrivatePkcs8KeyDer::from(der.to_vec()))
    }
}

impl rcgen::PublicKeyData for KeyPair {
    // rcgen takes the uncompressed point (0x04 || x || y) for EC keys.
    fn der_bytes(&self) -> &[u8] {
        self.0.public_key().as_ref()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for KeyPair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let signature = self.0.sign(msg).map_err(|_| rcgen::Error::RemoteKeyError)?;
        Ok(signature.as_ref().to_vec())
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair").finish_non_exhaustive()
    }
}
