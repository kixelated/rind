//! <h1 align="center">rind-rcgen</h1>
//! <img width="40%" align="right" src="https://raw.githubusercontent.com/kixelated/rind/main/admin/picture.png">
//!
//! This crate provides an ECDSA P-256 signing key for [rcgen](https://github.com/rustls/rcgen), backed by [rind](https://github.com/kixelated/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).
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

use rind::hashing::Sha256;
use rind::signing::ecdsa::{P256, SigningKey};
use rustls_pki_types::PrivatePkcs8KeyDer;

/// An ECDSA P-256 key pair that signs rcgen certificates with SHA-256.
pub struct KeyPair {
    key: SigningKey<P256>,
    // rcgen borrows the public key, so encode the uncompressed point
    // (0x04 || x || y) once.
    public_key: [u8; 65],
}

impl KeyPair {
    /// Generate a random key pair.
    pub fn generate() -> Result<Self, rind::Error> {
        let key = SigningKey::<P256>::generate()?;
        let public_key = key.private_key.public_key_uncompressed();
        Ok(Self { key, public_key })
    }

    /// Encode the private key as PKCS#8 DER, the form rustls loads.
    pub fn to_pkcs8_der(&self) -> Result<PrivatePkcs8KeyDer<'static>, rind::Error> {
        let mut buffer = [0u8; 256];
        let der = self.key.to_pkcs8_der(&mut buffer)?;
        Ok(PrivatePkcs8KeyDer::from(der.to_vec()))
    }
}

impl rcgen::PublicKeyData for KeyPair {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for KeyPair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let mut buffer = [0u8; 128];
        let signature = self
            .key
            .sign_asn1::<Sha256>(&[msg], &mut buffer)
            .map_err(|_| rcgen::Error::RemoteKeyError)?;
        Ok(signature.to_vec())
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair").finish_non_exhaustive()
    }
}
