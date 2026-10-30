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
use rind::hashing::hmac::Hmac;
use rind::hashing::{Hash, Sha256, Sha384, Sha512};
use rind::signing::{ecdsa, eddsa, rsa};

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
type RsaSign = for<'a> fn(&rsa::SigningKey, &'a mut [u8], &[u8]) -> RindResult<&'a [u8]>;
type RsaVerify = fn(&rsa::VerifyingKey, &[u8], &[u8]) -> RindResult<()>;

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
    let rsa = |sign: RsaSign| -> Result<Box<dyn JwtSigner>> {
        let key = rsa::SigningKey::from_pkcs1_der(der).map_err(invalid_rsa)?;
        Ok(signer(algorithm, (key, sign)))
    };

    Ok(match algorithm {
        // HMAC keeps the keyed state rather than a copy of the secret.
        Algorithm::HS256 => signer(algorithm, Hmac::<Sha256>::new(der)),
        Algorithm::HS384 => signer(algorithm, Hmac::<Sha384>::new(der)),
        Algorithm::HS512 => signer(algorithm, Hmac::<Sha512>::new(der)),
        Algorithm::ES256 => signer(
            algorithm,
            ecdsa::SigningKey::<ecdsa::P256>::from_pkcs8_der(der)
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
        ),
        Algorithm::ES384 => signer(
            algorithm,
            ecdsa::SigningKey::<ecdsa::P384>::from_pkcs8_der(der)
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
        ),
        Algorithm::EdDSA => signer(
            algorithm,
            eddsa::Ed25519SigningKey::from_pkcs8_der(der)
                .map_err(|_| ErrorKind::InvalidEddsaKey)?,
        ),
        Algorithm::RS256 => rsa(rsa::SigningKey::sign_pkcs1_sha256)?,
        Algorithm::RS384 => rsa(rsa::SigningKey::sign_pkcs1_sha384)?,
        Algorithm::RS512 => rsa(rsa::SigningKey::sign_pkcs1_sha512)?,
        Algorithm::PS256 => rsa(rsa::SigningKey::sign_pss_sha256)?,
        Algorithm::PS384 => rsa(rsa::SigningKey::sign_pss_sha384)?,
        Algorithm::PS512 => rsa(rsa::SigningKey::sign_pss_sha512)?,
        _ => return Err(ErrorKind::InvalidAlgorithm.into()),
    })
}

fn new_verifier(algorithm: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>> {
    if key.family() != algorithm.family() {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }

    let algorithm = *algorithm;
    let rsa = |verify: RsaVerify| -> Result<Box<dyn JwtVerifier>> {
        let parsed = match key.kind() {
            DecodingKeyKind::SecretOrDer(der) => rsa::VerifyingKey::from_pkcs1_der(der),
            DecodingKeyKind::RsaModulusExponent { n, e } => {
                let der = pkcs1::RsaPublicKey {
                    modulus: UintRef::new(n).map_err(invalid_rsa)?,
                    public_exponent: UintRef::new(e).map_err(invalid_rsa)?,
                }
                .to_der()
                .map_err(invalid_rsa)?;
                rsa::VerifyingKey::from_pkcs1_der(&der)
            }
        };
        Ok(verifier(algorithm, (parsed.map_err(invalid_rsa)?, verify)))
    };

    Ok(match algorithm {
        Algorithm::HS256 => verifier(algorithm, Hmac::<Sha256>::new(key.try_get_as_bytes()?)),
        Algorithm::HS384 => verifier(algorithm, Hmac::<Sha384>::new(key.try_get_as_bytes()?)),
        Algorithm::HS512 => verifier(algorithm, Hmac::<Sha512>::new(key.try_get_as_bytes()?)),
        Algorithm::ES256 => verifier(
            algorithm,
            ecdsa::VerifyingKey::<ecdsa::P256>::from_x962_uncompressed(key.try_get_as_bytes()?)
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
        ),
        Algorithm::ES384 => verifier(
            algorithm,
            ecdsa::VerifyingKey::<ecdsa::P384>::from_x962_uncompressed(key.try_get_as_bytes()?)
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
        ),
        Algorithm::EdDSA => verifier(
            algorithm,
            eddsa::Ed25519VerifyingKey::from_bytes(key.try_get_as_bytes()?)
                .map_err(|_| ErrorKind::InvalidEddsaKey)?,
        ),
        Algorithm::RS256 => rsa(rsa::VerifyingKey::verify_pkcs1_sha256)?,
        Algorithm::RS384 => rsa(rsa::VerifyingKey::verify_pkcs1_sha384)?,
        Algorithm::RS512 => rsa(rsa::VerifyingKey::verify_pkcs1_sha512)?,
        Algorithm::PS256 => rsa(rsa::VerifyingKey::verify_pss_sha256)?,
        Algorithm::PS384 => rsa(rsa::VerifyingKey::verify_pss_sha384)?,
        Algorithm::PS512 => rsa(rsa::VerifyingKey::verify_pss_sha512)?,
        _ => return Err(ErrorKind::InvalidAlgorithm.into()),
    })
}

fn mac<H: Hash + Clone>(key: &Hmac<H>, message: &[u8]) -> Hmac<H> {
    let mut mac = key.clone();
    mac.update(message);
    mac
}

impl<H: Hash + Clone> Sign for Hmac<H> {
    fn sign_message(&self, message: &[u8]) -> RindResult<Vec<u8>> {
        Ok(mac(self, message).finish().as_ref().to_vec())
    }
}

impl<H: Hash + Clone> Verify for Hmac<H> {
    fn verify_message(&self, message: &[u8], signature: &[u8]) -> RindResult<()> {
        mac(self, message).verify(signature)
    }
}

impl Sign for ecdsa::SigningKey<ecdsa::P256> {
    fn sign_message(&self, message: &[u8]) -> RindResult<Vec<u8>> {
        Ok(self.sign::<Sha256>(&[message], &mut [0; 64])?.to_vec())
    }
}

impl Verify for ecdsa::VerifyingKey<ecdsa::P256> {
    fn verify_message(&self, message: &[u8], signature: &[u8]) -> RindResult<()> {
        self.verify::<Sha256>(&[message], signature)
    }
}

impl Sign for ecdsa::SigningKey<ecdsa::P384> {
    fn sign_message(&self, message: &[u8]) -> RindResult<Vec<u8>> {
        Ok(self.sign::<Sha384>(&[message], &mut [0; 96])?.to_vec())
    }
}

impl Verify for ecdsa::VerifyingKey<ecdsa::P384> {
    fn verify_message(&self, message: &[u8], signature: &[u8]) -> RindResult<()> {
        self.verify::<Sha384>(&[message], signature)
    }
}

impl Sign for eddsa::Ed25519SigningKey {
    fn sign_message(&self, message: &[u8]) -> RindResult<Vec<u8>> {
        Ok(self.sign(message).to_vec())
    }
}

impl Verify for eddsa::Ed25519VerifyingKey {
    fn verify_message(&self, message: &[u8], signature: &[u8]) -> RindResult<()> {
        self.verify(signature, message)
    }
}

// An RSA key serves six algorithms, so it carries the one it was made for.
impl Sign for (rsa::SigningKey, RsaSign) {
    fn sign_message(&self, message: &[u8]) -> RindResult<Vec<u8>> {
        let (key, sign) = self;
        let mut signature = vec![0; key.modulus_len_bytes()];
        sign(key, &mut signature, message)?;
        Ok(signature)
    }
}

impl Verify for (rsa::VerifyingKey, RsaVerify) {
    fn verify_message(&self, message: &[u8], signature: &[u8]) -> RindResult<()> {
        let (key, verify) = self;
        verify(key, signature, message)
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
    let key = rsa::SigningKey::from_pkcs1_der(der).map_err(invalid_rsa)?;
    rsa_components(&key.public_key())
}

fn rsa_pub_components_from_public_key(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = rsa::VerifyingKey::from_pkcs1_der(der).map_err(invalid_rsa)?;
    rsa_components(&key)
}

// Reads back rind's canonical encoding of an already validated key.
fn rsa_components(key: &rsa::VerifyingKey) -> Result<(Vec<u8>, Vec<u8>)> {
    // Room for an 8192-bit modulus plus its DER framing.
    let mut buffer = [0u8; 1024 + 64];
    let der = key.to_pkcs1_der(&mut buffer).map_err(invalid_rsa)?;
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
    let (curve, point) = match algorithm {
        Algorithm::ES256 => (
            EllipticCurve::P256,
            ecdsa::SigningKey::<ecdsa::P256>::from_pkcs8_der(der)
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?
                .private_key
                .public_key_uncompressed()
                .to_vec(),
        ),
        Algorithm::ES384 => (
            EllipticCurve::P384,
            ecdsa::SigningKey::<ecdsa::P384>::from_pkcs8_der(der)
                .map_err(|_| ErrorKind::InvalidEcdsaKey)?
                .private_key
                .public_key_uncompressed()
                .to_vec(),
        ),
        _ => return Err(ErrorKind::InvalidEcdsaKey.into()),
    };

    // An uncompressed point is 0x04 || x || y.
    let (x, y) = point[1..].split_at(point.len() / 2);
    Ok((curve, x.to_vec(), y.to_vec()))
}

fn ed_pub_components_from_private_key(der: &[u8], curve: &EllipticCurve) -> Result<Vec<u8>> {
    match curve {
        EllipticCurve::Ed25519 => Ok(eddsa::Ed25519SigningKey::from_pkcs8_der(der)
            .map_err(|_| ErrorKind::InvalidEddsaKey)?
            .public_key()
            .as_bytes()
            .to_vec()),
        _ => Err(ErrorKind::InvalidAlgorithm.into()),
    }
}

fn compute_digest(data: &[u8], hash: ThumbprintHash) -> Result<Vec<u8>> {
    let digest = match hash {
        ThumbprintHash::SHA256 => Sha256::hash(data),
        ThumbprintHash::SHA384 => Sha384::hash(data),
        ThumbprintHash::SHA512 => Sha512::hash(data),
        _ => return Err(ErrorKind::InvalidAlgorithm.into()),
    };
    Ok(digest.as_ref().to_vec())
}
