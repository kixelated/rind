//! <h1 align="center">rind-instant-acme</h1>
//! <img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/picture.png">
//!
//! This crate provides a [`CryptoProvider`] for [instant-acme](https://github.com/djc/instant-acme), backed by [rind](https://github.com/moq-dev/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).
//!
//! Build instant-acme with `default-features = false`, since its default features compile aws-lc-rs.
//! Then hand the provider to each account, alongside an HTTPS client such as
//! instant-acme's `DefaultClient` on [rind-rustls](https://crates.io/crates/rind-rustls):
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use instant_acme::{Account, DefaultClient};
//!
//! let http = DefaultClient::new(Arc::new(rind_rustls::default_provider())).unwrap();
//! let builder = Account::builder(Box::new(http), &rind_instant_acme::DEFAULT_PROVIDER).unwrap();
//! ```

use instant_acme::{
    CryptoProvider, EcCurve, Error, HmacKey, HmacKeyProvider, Jwk, JwkThumbFields, Sha256,
    SigningAlgorithm, SigningKey, SigningKeyProvider,
};
use rind::digest;
use rind::hashing::hmac::Hmac;
use rind::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair as _,
};
use rustls_pki_types::PrivatePkcs8KeyDer;

/// An instant-acme [`CryptoProvider`] that signs with ECDSA P-256 account keys and HS256 EAB keys on rind.
///
/// It loads and generates the same PKCS#8 account keys as instant-acme's
/// aws-lc-rs and ring providers, so stored credentials move between them.
pub static DEFAULT_PROVIDER: CryptoProvider = CryptoProvider {
    key_provider: &P256KeyProvider,
    sha256: &RindSha256,
    hmac: &HmacSha256Provider,
};

struct P256KeyProvider;

/// JWS's ES256: P-256 and SHA-256, with the fixed-length `r || s` encoding.
const ES256: &EcdsaSigningAlgorithm = &ECDSA_P256_SHA256_FIXED_SIGNING;

impl SigningKeyProvider for P256KeyProvider {
    fn load_key(&self, pkcs8: PrivatePkcs8KeyDer<'static>) -> Result<Box<dyn SigningKey>, Error> {
        let key = EcdsaKeyPair::from_pkcs8(ES256, pkcs8.secret_pkcs8_der())
            .map_err(|_| Error::KeyRejected)?;
        Ok(Box::new(P256Key(key)))
    }

    fn generate_key(&self) -> Result<(Box<dyn SigningKey>, PrivatePkcs8KeyDer<'static>), Error> {
        let key = EcdsaKeyPair::generate(ES256).map_err(|_| Error::Crypto)?;
        // A P-256 PKCS#8 encoding is under 150 bytes.
        let mut buffer = [0u8; 256];
        let pkcs8 = key.to_pkcs8_der(&mut buffer).map_err(|_| Error::Crypto)?;
        let pkcs8 = PrivatePkcs8KeyDer::from(pkcs8.to_vec());
        Ok((Box::new(P256Key(key)), pkcs8))
    }
}

struct P256Key(EcdsaKeyPair);

impl SigningKey for P256Key {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let signature = self.0.sign(data).map_err(|_| Error::Crypto)?;
        Ok(signature.as_ref().to_vec())
    }

    fn as_jwk(&self) -> Jwk<'_> {
        // An uncompressed point is 0x04 || x || y.
        let point = &self.0.public_key().as_ref()[1..];
        let (x, y) = point.split_at(32);
        Jwk {
            alg: SigningAlgorithm::Es256,
            key: JwkThumbFields::Ec {
                crv: EcCurve::P256,
                x,
                y,
            },
            r#use: "sig",
        }
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Es256
    }
}

struct RindSha256;

impl Sha256 for RindSha256 {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        digest::digest(&digest::SHA256, data)
            .as_ref()
            .try_into()
            .unwrap()
    }
}

struct HmacSha256Provider;

impl HmacKeyProvider for HmacSha256Provider {
    fn load_key(&self, key_value: &[u8]) -> Box<dyn HmacKey> {
        // Keep the keyed state rather than a copy of the secret.
        Box::new(HmacSha256Key(Hmac::new(key_value)))
    }
}

struct HmacSha256Key(Hmac<rind::hashing::Sha256>);

impl HmacKey for HmacSha256Key {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let mut hmac = self.0.clone();
        hmac.update(data);
        hmac.finish().as_ref().to_vec()
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::Hs256
    }
}
