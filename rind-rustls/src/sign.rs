use core::fmt;
use std::sync::Arc;

use rind::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair,
    EcdsaSigningAlgorithm, Ed25519KeyPair, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
    RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512, RsaKeyPair, RsaSignatureEncoding,
};
use rustls::pki_types::SubjectPublicKeyInfoDer;
use rustls::{SignatureScheme, pki_types, sign};

#[derive(Debug)]
pub(super) struct Provider;

impl rustls::crypto::KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: pki_types::PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn sign::SigningKey>, rustls::Error> {
        match key_der {
            pki_types::PrivateKeyDer::Pkcs8(p8) => load_pkcs8(p8),
            pki_types::PrivateKeyDer::Pkcs1(p1) => load_pkcs1(p1),
            pki_types::PrivateKeyDer::Sec1(sec1) => load_sec1(sec1),
            _ => Err(rustls::Error::General("unhandled private key".to_string())),
        }
    }
}

/// Each curve's one scheme, since TLS 1.3 binds the hash to the curve.
const ECDSA: [(&EcdsaSigningAlgorithm, SignatureScheme); 2] = [
    (
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        SignatureScheme::ECDSA_NISTP256_SHA256,
    ),
    (
        &ECDSA_P384_SHA384_ASN1_SIGNING,
        SignatureScheme::ECDSA_NISTP384_SHA384,
    ),
];

fn load_pkcs8(
    key_der: pki_types::PrivatePkcs8KeyDer<'static>,
) -> Result<Arc<dyn sign::SigningKey>, rustls::Error> {
    let der = key_der.secret_pkcs8_der();
    if let Ok(rsa) = RsaKeyPair::from_pkcs8(der) {
        return Ok(Arc::new(Rsa(Arc::new(rsa))));
    }

    for (algorithm, scheme) in ECDSA {
        if let Ok(key) = EcdsaKeyPair::from_pkcs8(algorithm, der) {
            return Ok(Arc::new(Ecdsa::new(key, scheme)));
        }
    }

    if let Ok(ed25519) = Ed25519KeyPair::from_pkcs8(der) {
        return Ok(Arc::new(Ed25519(Arc::new(ed25519))));
    }

    Err(rustls::Error::General("unhandled pkcs8 format".to_string()))
}

fn load_pkcs1(
    key_der: pki_types::PrivatePkcs1KeyDer<'static>,
) -> Result<Arc<dyn sign::SigningKey>, rustls::Error> {
    let rsa = RsaKeyPair::from_der(key_der.secret_pkcs1_der())
        .map_err(|err| rustls::Error::General(format!("cannot parse RSA key: {err:?}")))?;

    Ok(Arc::new(Rsa(Arc::new(rsa))))
}

fn load_sec1(
    key_der: pki_types::PrivateSec1KeyDer<'static>,
) -> Result<Arc<dyn sign::SigningKey>, rustls::Error> {
    for (algorithm, scheme) in ECDSA {
        if let Ok(key) = EcdsaKeyPair::from_private_key_der(algorithm, key_der.secret_sec1_der()) {
            return Ok(Arc::new(Ecdsa::new(key, scheme)));
        }
    }

    Err(rustls::Error::General(
        "unhandled sec1 format/curve".to_string(),
    ))
}

/// The RSA schemes in preference order: PSS over PKCS#1, then the longest hash.
/// SHA-1 is absent, so it is never chosen.
const RSA: [(SignatureScheme, &RsaSignatureEncoding); 6] = [
    (SignatureScheme::RSA_PSS_SHA512, &RSA_PSS_SHA512),
    (SignatureScheme::RSA_PSS_SHA384, &RSA_PSS_SHA384),
    (SignatureScheme::RSA_PSS_SHA256, &RSA_PSS_SHA256),
    (SignatureScheme::RSA_PKCS1_SHA512, &RSA_PKCS1_SHA512),
    (SignatureScheme::RSA_PKCS1_SHA384, &RSA_PKCS1_SHA384),
    (SignatureScheme::RSA_PKCS1_SHA256, &RSA_PKCS1_SHA256),
];

struct Rsa(Arc<RsaKeyPair>);

impl sign::SigningKey for Rsa {
    fn choose_scheme(
        &self,
        schemes: &[SignatureScheme],
    ) -> Option<Box<dyn sign::Signer + 'static>> {
        let (scheme, padding) = RSA
            .into_iter()
            .find(|(scheme, _)| schemes.contains(scheme))?;
        Some(Box::new(RsaSigner {
            key: Arc::clone(&self.0),
            scheme,
            padding,
        }))
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::RSA
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'static>> {
        let size = self.0.public_modulus_len() + 64;
        let mut buffer = vec![0u8; size];

        let used = self.0.to_spki_der(&mut buffer).ok()?.len();

        buffer.truncate(used);
        Some(SubjectPublicKeyInfoDer::from(buffer))
    }
}

impl fmt::Debug for Rsa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("Rsa").finish_non_exhaustive()
    }
}

struct RsaSigner {
    key: Arc<RsaKeyPair>,
    scheme: SignatureScheme,
    padding: &'static RsaSignatureEncoding,
}

impl sign::Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut sig = vec![0u8; self.key.public_modulus_len()];
        self.key
            .sign(self.padding, message, &mut sig)
            .map_err(|err| rustls::Error::General(format!("signing failed: {err:?}")))?;

        Ok(sig)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl fmt::Debug for RsaSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("RsaSigner").finish_non_exhaustive()
    }
}

/// An ECDSA key, which signs only with its curve's scheme.
#[derive(Clone)]
struct Ecdsa {
    key: Arc<EcdsaKeyPair>,
    scheme: SignatureScheme,
}

impl Ecdsa {
    fn new(key: EcdsaKeyPair, scheme: SignatureScheme) -> Self {
        Self {
            key: Arc::new(key),
            scheme,
        }
    }
}

impl sign::SigningKey for Ecdsa {
    fn choose_scheme(
        &self,
        schemes: &[SignatureScheme],
    ) -> Option<Box<dyn sign::Signer + 'static>> {
        if schemes.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'static>> {
        let mut buffer = [0u8; 128];
        self.key
            .to_spki_der(&mut buffer)
            .ok()
            .map(|bytes| SubjectPublicKeyInfoDer::from(bytes.to_vec()))
    }
}

impl sign::Signer for Ecdsa {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let sig = self
            .key
            .sign(message)
            .map_err(|err| rustls::Error::General(format!("signing failed: {err:?}")))?;

        Ok(sig.as_ref().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

impl fmt::Debug for Ecdsa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("Ecdsa")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

struct Ed25519(Arc<Ed25519KeyPair>);

impl sign::SigningKey for Ed25519 {
    fn choose_scheme(
        &self,
        schemes: &[SignatureScheme],
    ) -> Option<Box<dyn sign::Signer + 'static>> {
        if schemes.contains(&SignatureScheme::ED25519) {
            Some(Box::new(Self(self.0.clone())))
        } else {
            None
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'static>> {
        let mut buffer = [0; 64];
        self.0
            .to_spki_der(&mut buffer)
            .ok()
            .map(|bytes| SubjectPublicKeyInfoDer::from(bytes.to_vec()))
    }
}

impl sign::Signer for Ed25519 {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(self.0.sign(message).as_ref().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

impl fmt::Debug for Ed25519 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("Ed25519").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use rustls::crypto::KeyProvider;
    use rustls::sign::SigningKey;

    use super::*;

    #[test]
    fn test_load_signing_key() {
        let provider = Provider;

        // Valid inputs: RSA private keys in PKCS#1 and PKCS#8 DER format
        let rsa2048_pkcs1 = pki_types::PrivateKeyDer::Pkcs1(pki_types::PrivatePkcs1KeyDer::from(
            include_bytes!("../../rind/src/high/rsa/rsa2048.der").to_vec(),
        ));
        assert!(provider.load_private_key(rsa2048_pkcs1).is_ok());
        let rsa2048_pkcs8 = pki_types::PrivateKeyDer::Pkcs8(pki_types::PrivatePkcs8KeyDer::from(
            include_bytes!("../../rind/src/high/rsa/rsa2048.pkcs8.der").to_vec(),
        ));
        assert!(provider.load_private_key(rsa2048_pkcs8).is_ok());

        // Valid inputs: ECDSA P256 and P384 keys in SEC1 and PKCS#8 DER
        // format, each choosing only its curve's scheme.
        for (sec1, pkcs8, scheme) in [
            (
                &include_bytes!("../../rind/src/high/ecdsa/secp256r1.der")[..],
                &include_bytes!("../../rind/src/high/ecdsa/secp256r1.pkcs8.der")[..],
                SignatureScheme::ECDSA_NISTP256_SHA256,
            ),
            (
                &include_bytes!("../../rind/src/high/ecdsa/secp384r1.der")[..],
                &include_bytes!("../../rind/src/high/ecdsa/secp384r1.pkcs8.der")[..],
                SignatureScheme::ECDSA_NISTP384_SHA384,
            ),
        ] {
            let keys = [
                pki_types::PrivateKeyDer::Sec1(pki_types::PrivateSec1KeyDer::from(sec1.to_vec())),
                pki_types::PrivateKeyDer::Pkcs8(pki_types::PrivatePkcs8KeyDer::from(
                    pkcs8.to_vec(),
                )),
            ];
            for key in keys {
                let key = provider.load_private_key(key).unwrap();
                let schemes = [
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                ];
                assert_eq!(key.choose_scheme(&schemes).unwrap().scheme(), scheme);
            }
        }

        // Error case: invalid key file
        let invalid_pkcs1 = pki_types::PrivateKeyDer::Pkcs1(pki_types::PrivatePkcs1KeyDer::from(
            [0u8; 1024].to_vec(),
        ));
        assert!(provider.load_private_key(invalid_pkcs1).is_err());
        let invalid_pkcs8 = pki_types::PrivateKeyDer::Pkcs8(pki_types::PrivatePkcs8KeyDer::from(
            [0u8; 1024].to_vec(),
        ));
        assert!(provider.load_private_key(invalid_pkcs8).is_err());
        let invalid_sec1 = pki_types::PrivateKeyDer::Sec1(pki_types::PrivateSec1KeyDer::from(
            [0u8; 1024].to_vec(),
        ));
        assert!(provider.load_private_key(invalid_sec1).is_err());
        let ecdsap256_sec1 = pki_types::PrivateKeyDer::Sec1(pki_types::PrivateSec1KeyDer::from(
            include_bytes!("../../rind/src/high/ecdsa/secp256r1.wrong-version.der").to_vec(),
        ));
        assert!(provider.load_private_key(ecdsap256_sec1).is_err());
    }

    #[test]
    fn test_rsa_signing_key() {
        let signing_key = Arc::new(
            RsaKeyPair::from_der(include_bytes!("../../rind/src/high/rsa/rsa2048.der")).unwrap(),
        );
        let rsa = Rsa(signing_key.clone());
        println!("{:?}", rsa);
        assert_eq!(rsa.algorithm(), rustls::SignatureAlgorithm::RSA);

        // If multiple schemes are specified, choose PSS over PKCS#1 and then longest specified hash length.
        assert!(rsa.choose_scheme(&[]).is_none());
        assert_eq!(
            rsa.choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA256])
                .unwrap()
                .scheme(),
            SignatureScheme::RSA_PKCS1_SHA256
        );
        assert_eq!(
            rsa.choose_scheme(&[
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PSS_SHA256
            ])
            .unwrap()
            .scheme(),
            SignatureScheme::RSA_PSS_SHA256
        );
        assert_eq!(
            rsa.choose_scheme(&[
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384
            ])
            .unwrap()
            .scheme(),
            SignatureScheme::RSA_PSS_SHA256
        );
        assert_eq!(
            rsa.choose_scheme(&[
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384
            ])
            .unwrap()
            .scheme(),
            SignatureScheme::RSA_PSS_SHA512
        );
        // Don't choose non-RSA schemes.
        assert!(
            rsa.choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
                .is_none()
        );
        assert_eq!(
            rsa.choose_scheme(&[SignatureScheme::ED25519, SignatureScheme::RSA_PSS_SHA384])
                .unwrap()
                .scheme(),
            SignatureScheme::RSA_PSS_SHA384
        );
        assert_eq!(
            rsa.choose_scheme(&[
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PKCS1_SHA384
            ])
            .unwrap()
            .scheme(),
            SignatureScheme::RSA_PKCS1_SHA384
        );
        assert_eq!(
            rsa.choose_scheme(&[SignatureScheme::ED448, SignatureScheme::RSA_PKCS1_SHA512])
                .unwrap()
                .scheme(),
            SignatureScheme::RSA_PKCS1_SHA512
        );
        // Don't choose SHA1.
        assert!(
            rsa.choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA1])
                .is_none()
        );

        // Each chosen scheme signs.
        let message = vec![0u8; 64];
        for (scheme, _) in RSA {
            let signer = rsa.choose_scheme(&[scheme]).unwrap();
            assert_eq!(signer.sign(&message).unwrap().len(), 256);
            println!("{:?}", signer);
        }
    }

    #[test]
    fn test_ecdsa_signing_key() {
        for (pkcs8, (algorithm, scheme)) in [
            &include_bytes!("../../rind/src/high/ecdsa/secp256r1.pkcs8.der")[..],
            &include_bytes!("../../rind/src/high/ecdsa/secp384r1.pkcs8.der")[..],
        ]
        .into_iter()
        .zip(ECDSA)
        {
            let ecdsa = Ecdsa::new(EcdsaKeyPair::from_pkcs8(algorithm, pkcs8).unwrap(), scheme);
            println!("{:?}", ecdsa);
            assert_eq!(ecdsa.algorithm(), rustls::SignatureAlgorithm::ECDSA);

            // Choose only a matching scheme.
            assert!(ecdsa.choose_scheme(&[]).is_none());
            let others = [
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
                SignatureScheme::ML_DSA_44,
                SignatureScheme::ML_DSA_65,
                SignatureScheme::ML_DSA_87,
            ]
            .into_iter()
            .filter(|other| *other != scheme)
            .collect::<Vec<_>>();
            assert!(ecdsa.choose_scheme(&others).is_none());
            assert_eq!(
                ecdsa
                    .choose_scheme(&[
                        SignatureScheme::ECDSA_NISTP521_SHA512,
                        scheme,
                        SignatureScheme::ED25519,
                    ])
                    .unwrap()
                    .scheme(),
                scheme
            );
        }
    }

    #[test]
    fn test_ed25519_signing_key() {
        let signing_key = Arc::new(Ed25519KeyPair::generate().unwrap());
        let ed25519 = Ed25519(signing_key.clone());
        assert_eq!(ed25519.algorithm(), rustls::SignatureAlgorithm::ED25519);
        assert!(ed25519.choose_scheme(&[]).is_none());
        assert_eq!(format!("{ed25519:?}"), "Ed25519 { .. }");
    }
}
