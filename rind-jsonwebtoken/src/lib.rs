//! <h1 align="center">rind-jsonwebtoken</h1>
//! <img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/picture.png">
//!
//! This crate provides an integration between [jsonwebtoken](https://github.com/Keats/jsonwebtoken) and [rind](https://github.com/moq-dev/rind/), a fork of [Graviola](https://github.com/ctz/graviola/).
//!
//! Use it like:
//!
//! ```rust
//! rind_jsonwebtoken::DEFAULT_PROVIDER
//!     .install_default()
//!     .unwrap();
//! ```
//!
//! And then use jsonwebtoken as normal.

use jsonwebtoken::crypto::{CryptoProvider, JwtSigner, JwtVerifier, KeyUtils};
use jsonwebtoken::errors::{Error, ErrorKind, Result};
use jsonwebtoken::jwk::{EllipticCurve, ThumbprintHash};
use jsonwebtoken::signature::{self, Signer, Verifier};
use jsonwebtoken::{Algorithm, DecodingKey, DecodingKeyKind, EncodingKey};
use pkcs1::der::asn1::UintRef;
use pkcs1::der::{Decode, Encode};
use rind::digest;
use rind::hashing::hmac::Hmac;
use rind::hashing::{Sha256, Sha384, Sha512};
use rind::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED,
    ECDSA_P384_SHA384_FIXED_SIGNING, ED25519, EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair,
    KeyPair as _, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
    RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512, RSA_PSS_SHA256,
    RSA_PSS_SHA384, RSA_PSS_SHA512, RsaKeyPair, RsaSignatureEncoding, UnparsedPublicKey,
    VerificationAlgorithm,
};

/// A jsonwebtoken [`CryptoProvider`] that signs and verifies every algorithm with rind.
pub static DEFAULT_PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: new_signer,
    verifier_factory: new_verifier,
    key_utils: KeyUtils {
        rsa_pub_components_from_private_key,
        rsa_pub_components_from_public_key,
        ec_pub_components_from_private_key,
        ed_pub_components_from_private_key,
        compute_digest,
    },
};

type RindResult<T> = std::result::Result<T, rind::Error>;

/// A key that signs for exactly one algorithm.
trait Sign {
    fn sign_message(&self, message: &[u8]) -> RindResult<Vec<u8>>;
}

/// A key that verifies for exactly one algorithm.
trait Verify {
    fn verify_message(&self, message: &[u8], signature: &[u8]) -> RindResult<()>;
}

/// A key tagged with the algorithm jsonwebtoken asked for.
struct Keyed<K> {
    algorithm: Algorithm,
    key: K,
}

fn signer<K: Sign + 'static>(algorithm: Algorithm, key: K) -> Box<dyn JwtSigner> {
    Box::new(Keyed { algorithm, key })
}

fn verifier<K: Verify + 'static>(algorithm: Algorithm, key: K) -> Box<dyn JwtVerifier> {
    Box::new(Keyed { algorithm, key })
}

fn new_signer(algorithm: &Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>> {
    if key.family() != algorithm.family() {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }

    let algorithm = *algorithm;
    let der = key.as_bytes();
    let ecdsa = |signing: &'static EcdsaSigningAlgorithm| -> Result<Box<dyn JwtSigner>> {
        let key = EcdsaKeyPair::from_pkcs8(signing, der).map_err(|_| ErrorKind::InvalidEcdsaKey)?;
        Ok(signer(algorithm, key))
    };
    let rsa = |padding: &'static RsaSignatureEncoding| -> Result<Box<dyn JwtSigner>> {
        let key = RsaKeyPair::from_der(der).map_err(invalid_rsa)?;
        Ok(signer(algorithm, (key, padding)))
    };

    Ok(match algorithm {
        // HMAC keeps the keyed state rather than a copy of the secret.
        Algorithm::HS256 => signer(algorithm, Hmac::<Sha256>::new(der)),
        Algorithm::HS384 => signer(algorithm, Hmac::<Sha384>::new(der)),
        Algorithm::HS512 => signer(algorithm, Hmac::<Sha512>::new(der)),
        Algorithm::ES256 => ecdsa(&ECDSA_P256_SHA256_FIXED_SIGNING)?,
        Algorithm::ES384 => ecdsa(&ECDSA_P384_SHA384_FIXED_SIGNING)?,
        Algorithm::EdDSA => signer(
            algorithm,
            Ed25519KeyPair::from_pkcs8(der).map_err(|_| ErrorKind::InvalidEddsaKey)?,
        ),
        Algorithm::RS256 => rsa(&RSA_PKCS1_SHA256)?,
        Algorithm::RS384 => rsa(&RSA_PKCS1_SHA384)?,
        Algorithm::RS512 => rsa(&RSA_PKCS1_SHA512)?,
        Algorithm::PS256 => rsa(&RSA_PSS_SHA256)?,
        Algorithm::PS384 => rsa(&RSA_PSS_SHA384)?,
        Algorithm::PS512 => rsa(&RSA_PSS_SHA512)?,
        _ => return Err(ErrorKind::InvalidAlgorithm.into()),
    })
}

fn new_verifier(algorithm: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>> {
    if key.family() != algorithm.family() {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }

    // As with jsonwebtoken's aws-lc-rs provider, a public key is parsed when
    // it verifies, so a malformed one fails verification.
    let algorithm = *algorithm;
    let public =
        |verification: &'static dyn VerificationAlgorithm, der: Vec<u8>| -> Box<dyn JwtVerifier> {
            verifier(algorithm, UnparsedPublicKey::new(verification, der))
        };
    let bytes = |verification: &'static dyn VerificationAlgorithm| -> Result<Box<dyn JwtVerifier>> {
        Ok(public(verification, key.try_get_as_bytes()?.to_vec()))
    };
    let rsa = |verification: &'static dyn VerificationAlgorithm| -> Result<Box<dyn JwtVerifier>> {
        let der = match key.kind() {
            DecodingKeyKind::SecretOrDer(der) => der.to_vec(),
            DecodingKeyKind::RsaModulusExponent { n, e } => pkcs1::RsaPublicKey {
                modulus: UintRef::new(n).map_err(invalid_rsa)?,
                public_exponent: UintRef::new(e).map_err(invalid_rsa)?,
            }
            .to_der()
            .map_err(invalid_rsa)?,
        };
        Ok(public(verification, der))
    };

    Ok(match algorithm {
        Algorithm::HS256 => verifier(algorithm, Hmac::<Sha256>::new(key.try_get_as_bytes()?)),
        Algorithm::HS384 => verifier(algorithm, Hmac::<Sha384>::new(key.try_get_as_bytes()?)),
        Algorithm::HS512 => verifier(algorithm, Hmac::<Sha512>::new(key.try_get_as_bytes()?)),
        Algorithm::ES256 => bytes(&ECDSA_P256_SHA256_FIXED)?,
        Algorithm::ES384 => bytes(&ECDSA_P384_SHA384_FIXED)?,
        Algorithm::EdDSA => bytes(&ED25519)?,
        Algorithm::RS256 => rsa(&RSA_PKCS1_2048_8192_SHA256)?,
        Algorithm::RS384 => rsa(&RSA_PKCS1_2048_8192_SHA384)?,
        Algorithm::RS512 => rsa(&RSA_PKCS1_2048_8192_SHA512)?,
        Algorithm::PS256 => rsa(&RSA_PSS_2048_8192_SHA256)?,
        Algorithm::PS384 => rsa(&RSA_PSS_2048_8192_SHA384)?,
        Algorithm::PS512 => rsa(&RSA_PSS_2048_8192_SHA512)?,
        _ => return Err(ErrorKind::InvalidAlgorithm.into()),
    })
}

// rind's hash markers name no trait to be generic over.
macro_rules! hmac {
    ($($hash:ty),*) => {$(
        impl Sign for Hmac<$hash> {
            fn sign_message(&self, message: &[u8]) -> RindResult<Vec<u8>> {
                let mut mac = self.clone();
                mac.update(message);
                Ok(mac.finish().as_ref().to_vec())
            }
        }

        impl Verify for Hmac<$hash> {
            fn verify_message(&self, message: &[u8], signature: &[u8]) -> RindResult<()> {
                let mut mac = self.clone();
                mac.update(message);
                mac.verify(signature)
            }
        }
    )*};
}

hmac!(Sha256, Sha384, Sha512);

impl Sign for EcdsaKeyPair {
    fn sign_message(&self, message: &[u8]) -> RindResult<Vec<u8>> {
        Ok(self.sign(message)?.as_ref().to_vec())
    }
}

impl Sign for Ed25519KeyPair {
    fn sign_message(&self, message: &[u8]) -> RindResult<Vec<u8>> {
        Ok(self.sign(message).as_ref().to_vec())
    }
}

// An RSA key serves six algorithms, so it carries the padding it was made for.
impl Sign for (RsaKeyPair, &'static RsaSignatureEncoding) {
    fn sign_message(&self, message: &[u8]) -> RindResult<Vec<u8>> {
        let (key, padding) = self;
        let mut signature = vec![0; key.public_modulus_len()];
        key.sign(padding, message, &mut signature)?;
        Ok(signature)
    }
}

impl Verify for UnparsedPublicKey<Vec<u8>> {
    fn verify_message(&self, message: &[u8], signature: &[u8]) -> RindResult<()> {
        self.verify(message, signature)
    }
}

impl<K: Sign> Signer<Vec<u8>> for Keyed<K> {
    fn try_sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, signature::Error> {
        self.key
            .sign_message(message)
            .map_err(signature::Error::from_source)
    }
}

impl<K: Verify> Verifier<Vec<u8>> for Keyed<K> {
    fn verify(
        &self,
        message: &[u8],
        signature: &Vec<u8>,
    ) -> std::result::Result<(), signature::Error> {
        self.key
            .verify_message(message, signature)
            .map_err(signature::Error::from_source)
    }
}

impl<K: Sign> JwtSigner for Keyed<K> {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

impl<K: Verify> JwtVerifier for Keyed<K> {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

fn invalid_rsa(error: impl std::fmt::Display) -> Error {
    ErrorKind::InvalidRsaKey(error.to_string()).into()
}

fn rsa_pub_components_from_private_key(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = RsaKeyPair::from_der(der).map_err(invalid_rsa)?;
    rsa_pub_components_from_public_key(key.public_key().as_ref())
}

// Only splits the key: like the other public keys here, rind validates it
// when it verifies.
fn rsa_pub_components_from_public_key(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = pkcs1::RsaPublicKey::from_der(der).map_err(invalid_rsa)?;
    Ok((
        key.modulus.as_bytes().to_vec(),
        key.public_exponent.as_bytes().to_vec(),
    ))
}

fn ec_pub_components_from_private_key(
    der: &[u8],
    algorithm: Algorithm,
) -> Result<(EllipticCurve, Vec<u8>, Vec<u8>)> {
    let (curve, signing) = match algorithm {
        Algorithm::ES256 => (EllipticCurve::P256, &ECDSA_P256_SHA256_FIXED_SIGNING),
        Algorithm::ES384 => (EllipticCurve::P384, &ECDSA_P384_SHA384_FIXED_SIGNING),
        _ => return Err(ErrorKind::InvalidEcdsaKey.into()),
    };
    let key = EcdsaKeyPair::from_pkcs8(signing, der).map_err(|_| ErrorKind::InvalidEcdsaKey)?;

    // An uncompressed point is 0x04 || x || y.
    let point = &key.public_key().as_ref()[1..];
    let (x, y) = point.split_at(point.len() / 2);
    Ok((curve, x.to_vec(), y.to_vec()))
}

fn ed_pub_components_from_private_key(der: &[u8], curve: &EllipticCurve) -> Result<Vec<u8>> {
    match curve {
        EllipticCurve::Ed25519 => Ok(Ed25519KeyPair::from_pkcs8(der)
            .map_err(|_| ErrorKind::InvalidEddsaKey)?
            .public_key()
            .as_ref()
            .to_vec()),
        _ => Err(ErrorKind::InvalidAlgorithm.into()),
    }
}

fn compute_digest(data: &[u8], hash: ThumbprintHash) -> Result<Vec<u8>> {
    let algorithm = match hash {
        ThumbprintHash::SHA256 => &digest::SHA256,
        ThumbprintHash::SHA384 => &digest::SHA384,
        ThumbprintHash::SHA512 => &digest::SHA512,
        _ => return Err(ErrorKind::InvalidAlgorithm.into()),
    };
    Ok(digest::digest(algorithm, data).as_ref().to_vec())
}
