use std::fmt;

use dimpl::crypto::{
    Buf, HashAlgorithm, KeyProvider, NamedGroup, SignatureAlgorithm, SignatureVerifier, SigningKey,
    check_verify_scheme,
};
use dimpl::{CryptoError, CryptoOperation};
use rind::hashing::{Sha256, Sha384};
use rind::signing::ecdsa::{self, Curve, P256, P384};
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::spki::ObjectIdentifier;

const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

#[derive(Debug)]
pub(crate) struct Keys;

pub(crate) static KEYS: Keys = Keys;

impl KeyProvider for Keys {
    fn load_private_key(&self, der: &[u8]) -> Result<Box<dyn SigningKey>, CryptoError> {
        let key = if let Ok(key) = ecdsa::SigningKey::from_pkcs8_der(der) {
            Key::P256(key)
        } else if let Ok(key) = ecdsa::SigningKey::from_pkcs8_der(der) {
            Key::P384(key)
        } else if let Ok(key) = ecdsa::SigningKey::from_sec1_der(der) {
            Key::P256(key)
        } else if let Ok(key) = ecdsa::SigningKey::from_sec1_der(der) {
            Key::P384(key)
        } else {
            return Err(CryptoError::InvalidPrivateKey);
        };
        Ok(Box::new(key))
    }
}

enum Key {
    P256(ecdsa::SigningKey<P256>),
    P384(ecdsa::SigningKey<P384>),
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::P256(_) => "P256",
            Self::P384(_) => "P384",
        })
    }
}

impl SigningKey for Key {
    fn sign(&mut self, data: &[u8], hash: HashAlgorithm, out: &mut Buf) -> Result<(), CryptoError> {
        match self {
            Self::P256(key) => sign(key, NamedGroup::Secp256r1, data, hash, out),
            Self::P384(key) => sign(key, NamedGroup::Secp384r1, data, hash, out),
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::P256(_) => HashAlgorithm::SHA256,
            Self::P384(_) => HashAlgorithm::SHA384,
        }
    }

    fn supported_hash_algorithms(&self) -> &[HashAlgorithm] {
        // DTLS 1.2 may pair either curve with either hash.
        &[HashAlgorithm::SHA256, HashAlgorithm::SHA384]
    }
}

fn sign<C: Curve>(
    key: &ecdsa::SigningKey<C>,
    group: NamedGroup,
    data: &[u8],
    hash: HashAlgorithm,
    out: &mut Buf,
) -> Result<(), CryptoError> {
    // Fits a DER signature on P-384, the largest curve.
    let mut signature = [0u8; 128];
    let signature = match hash {
        HashAlgorithm::SHA256 => key.sign_asn1::<Sha256>(&[data], &mut signature),
        HashAlgorithm::SHA384 => key.sign_asn1::<Sha384>(&[data], &mut signature),
        _ => return Err(CryptoError::SigningKeyUnsupportedHash { group, hash }),
    }
    .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Sign))?;
    out.clear();
    out.extend_from_slice(signature);
    Ok(())
}

#[derive(Debug)]
pub(crate) struct Verifier;

pub(crate) static VERIFIER: Verifier = Verifier;

impl SignatureVerifier for Verifier {
    fn verify_signature(
        &self,
        cert_der: &[u8],
        data: &[u8],
        signature: &[u8],
        hash: HashAlgorithm,
        algorithm: SignatureAlgorithm,
    ) -> Result<(), CryptoError> {
        if algorithm != SignatureAlgorithm::ECDSA {
            return Err(CryptoError::UnsupportedSignatureAlgorithm(algorithm));
        }

        let cert =
            Certificate::from_der(cert_der).map_err(|_| CryptoError::CertificateParseFailed)?;
        let spki = cert.tbs_certificate().subject_public_key_info();
        if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
            return Err(CryptoError::UnsupportedPublicKeyAlgorithm);
        }
        let curve: ObjectIdentifier = spki
            .algorithm
            .parameters
            .as_ref()
            .ok_or(CryptoError::MissingEcCurveParameter)?
            .decode_as()
            .map_err(|_| CryptoError::InvalidEcCurveParameter)?;
        type Verify = fn(NamedGroup, &[u8], &[u8], &[u8], HashAlgorithm) -> Result<(), CryptoError>;
        let (group, verify): (_, Verify) = match curve {
            SECP256R1 => (NamedGroup::Secp256r1, verify::<P256>),
            SECP384R1 => (NamedGroup::Secp384r1, verify::<P384>),
            _ => return Err(CryptoError::UnsupportedEcCurve),
        };
        check_verify_scheme(algorithm, hash, group)?;

        let point = spki
            .subject_public_key
            .as_bytes()
            .ok_or(CryptoError::InvalidSubjectPublicKey)?;
        verify(group, point, data, signature, hash)
    }
}

fn verify<C: Curve>(
    group: NamedGroup,
    point: &[u8],
    data: &[u8],
    signature: &[u8],
    hash: HashAlgorithm,
) -> Result<(), CryptoError> {
    let key = ecdsa::VerifyingKey::<C>::from_x962_uncompressed(point)
        .map_err(|_| CryptoError::InvalidPublicKey(group))?;
    let signature_alg = SignatureAlgorithm::ECDSA;
    match hash {
        HashAlgorithm::SHA256 => key.verify_asn1::<Sha256>(&[data], signature),
        HashAlgorithm::SHA384 => key.verify_asn1::<Sha384>(&[data], signature),
        _ => {
            return Err(CryptoError::UnsupportedSignatureVerification {
                signature: signature_alg,
                hash,
                group,
            });
        }
    }
    .map_err(|_| CryptoError::SignatureVerificationFailed {
        signature: signature_alg,
        hash,
        group,
    })
}
