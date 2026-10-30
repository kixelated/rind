use rind::signature::{self, VerificationAlgorithm};
use rustls::SignatureScheme;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};

pub(crate) static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA512,
        ECDSA_P256_SHA384,
        ECDSA_P256_SHA256,
        ECDSA_P384_SHA512,
        ECDSA_P384_SHA384,
        ECDSA_P384_SHA256,
        ED25519,
        RSA_PSS_SHA512,
        RSA_PSS_SHA384,
        RSA_PSS_SHA256,
        RSA_PKCS1_SHA512,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA256,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[ECDSA_P256_SHA256, ECDSA_P384_SHA256],
        ),
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[ECDSA_P384_SHA384, ECDSA_P256_SHA384],
        ),
        (SignatureScheme::ED25519, &[ED25519]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
    ],
};

static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA256,
    algorithm: &signature::ECDSA_P256_SHA256_ASN1,
};

static ECDSA_P256_SHA384: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA384,
    algorithm: &signature::ECDSA_P256_SHA384_ASN1,
};

static ECDSA_P256_SHA512: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key_alg_id: alg_id::ECDSA_P256,
    signature_alg_id: alg_id::ECDSA_SHA512,
    algorithm: &signature::ECDSA_P256_SHA512_ASN1,
};

static ECDSA_P384_SHA256: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA256,
    algorithm: &signature::ECDSA_P384_SHA256_ASN1,
};

static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA384,
    algorithm: &signature::ECDSA_P384_SHA384_ASN1,
};

static ECDSA_P384_SHA512: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key_alg_id: alg_id::ECDSA_P384,
    signature_alg_id: alg_id::ECDSA_SHA512,
    algorithm: &signature::ECDSA_P384_SHA512_ASN1,
};

static ED25519: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key_alg_id: alg_id::ED25519,
    signature_alg_id: alg_id::ED25519,
    algorithm: &signature::ED25519,
};

static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA256,
    algorithm: &signature::RSA_PSS_2048_8192_SHA256,
};

static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA384,
    algorithm: &signature::RSA_PSS_2048_8192_SHA384,
};

static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PSS_SHA512,
    algorithm: &signature::RSA_PSS_2048_8192_SHA512,
};

static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
    algorithm: &signature::RSA_PKCS1_2048_8192_SHA256,
};

static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
    algorithm: &signature::RSA_PKCS1_2048_8192_SHA384,
};

static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &Verify {
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
    algorithm: &signature::RSA_PKCS1_2048_8192_SHA512,
};

/// A webpki algorithm: its identifiers, and the rind constant that verifies it.
///
/// webpki hands over the `subjectPublicKey` bit string, which is the encoding
/// each constant takes: an X9.62 point, a PKCS#1 `RSAPublicKey`, or Ed25519's
/// 32 bytes.
#[derive(Debug)]
struct Verify {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    algorithm: &'static dyn VerificationAlgorithm,
}

impl SignatureVerificationAlgorithm for Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        signature::UnparsedPublicKey::new(self.algorithm, public_key)
            .verify(message, signature)
            .map_err(|_| InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use rind::random;
    use rind::signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair,
        Ed25519KeyPair, KeyPair, RsaKeyPair,
    };

    use super::*;

    fn message() -> [u8; 64] {
        let mut message = [0u8; 64];
        random::fill(&mut message).unwrap();
        message
    }

    // TLS 1.3 binds each ECDSA scheme to a curve and verifies with the first
    // entry only, so that entry must be for the scheme's curve.
    #[test]
    fn test_ecdsa_scheme_curves() {
        for (scheme, algorithms) in ALGORITHMS.mapping {
            let curve = match scheme {
                SignatureScheme::ECDSA_NISTP256_SHA256 => alg_id::ECDSA_P256,
                SignatureScheme::ECDSA_NISTP384_SHA384 => alg_id::ECDSA_P384,
                _ => continue,
            };
            assert_eq!(algorithms[0].public_key_alg_id(), curve, "{scheme:?}");
        }
    }

    // A signature verifies under its own algorithm, and under no other
    // algorithm for the same key type. rind signs ECDSA only with each
    // curve's own hash; Wycheproof covers the other pairs.
    #[test]
    fn test_ecdsa_verify() {
        for (pkcs8, signing, algorithm, others) in [
            (
                &include_bytes!("../../rind/src/high/ecdsa/secp256r1.pkcs8.der")[..],
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                ECDSA_P256_SHA256,
                [ECDSA_P256_SHA384, ECDSA_P256_SHA512, ECDSA_P384_SHA256],
            ),
            (
                &include_bytes!("../../rind/src/high/ecdsa/secp384r1.pkcs8.der")[..],
                &ECDSA_P384_SHA384_ASN1_SIGNING,
                ECDSA_P384_SHA384,
                [ECDSA_P384_SHA256, ECDSA_P384_SHA512, ECDSA_P256_SHA384],
            ),
        ] {
            let key = EcdsaKeyPair::from_pkcs8(signing, pkcs8).unwrap();
            let message = message();
            let signature = key.sign(&message).unwrap();
            let public_key = key.public_key().as_ref();
            algorithm
                .verify_signature(public_key, &message, signature.as_ref())
                .unwrap();
            for other in others {
                assert!(
                    other
                        .verify_signature(public_key, &message, signature.as_ref())
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn test_ed25519_verify() {
        let key = Ed25519KeyPair::generate().unwrap();
        let message = message();
        let signature = key.sign(&message);
        ED25519
            .verify_signature(key.public_key().as_ref(), &message, signature.as_ref())
            .unwrap();
    }

    #[test]
    fn test_rsa_verify() {
        let key =
            RsaKeyPair::from_pkcs8(include_bytes!("../../rind/src/high/rsa/rsa2048.pkcs8.der"))
                .unwrap();
        let message = message();
        let schemes = [
            (
                RSA_PSS_SHA256,
                alg_id::RSA_PSS_SHA256,
                &signature::RSA_PSS_SHA256,
            ),
            (
                RSA_PSS_SHA384,
                alg_id::RSA_PSS_SHA384,
                &signature::RSA_PSS_SHA384,
            ),
            (
                RSA_PSS_SHA512,
                alg_id::RSA_PSS_SHA512,
                &signature::RSA_PSS_SHA512,
            ),
            (
                RSA_PKCS1_SHA256,
                alg_id::RSA_PKCS1_SHA256,
                &signature::RSA_PKCS1_SHA256,
            ),
            (
                RSA_PKCS1_SHA384,
                alg_id::RSA_PKCS1_SHA384,
                &signature::RSA_PKCS1_SHA384,
            ),
            (
                RSA_PKCS1_SHA512,
                alg_id::RSA_PKCS1_SHA512,
                &signature::RSA_PKCS1_SHA512,
            ),
        ];
        for (i, (algorithm, alg_id, padding)) in schemes.iter().enumerate() {
            assert_eq!(algorithm.signature_alg_id(), *alg_id);
            let mut signature = [0u8; 256];
            key.sign(padding, &message, &mut signature).unwrap();
            for (j, (other, ..)) in schemes.iter().enumerate() {
                let result =
                    other.verify_signature(key.public_key().as_ref(), &message, &signature);
                assert_eq!(result.is_ok(), i == j);
            }
        }
    }
}
