use std::fmt;

use dimpl::crypto::{
    Aad, Buf, Cipher, Dtls12CipherSuite, Dtls13CipherSuite, HashAlgorithm, Nonce,
    SupportedDtls12CipherSuite, SupportedDtls13CipherSuite, TmpBuf,
};
use dimpl::{CryptoError, CryptoOperation};
use rind::aead::{AesGcm, ChaCha20Poly1305};
use rind::cipher::{Aes, ChaCha20};

const TAG_LEN: usize = 16;

/// The AEAD behind a suite, shared by its DTLS 1.2 and 1.3 forms.
#[derive(Debug, Clone, Copy)]
enum Algorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Algorithm {
    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    fn cipher(self, key: &[u8]) -> Result<Box<dyn Cipher>, CryptoError> {
        let actual = key.len().min(u16::MAX as usize) as u16;
        let aead = match self {
            // rind takes either AES key length, but the suite fixes one.
            Self::Aes128Gcm | Self::Aes256Gcm if key.len() == self.key_len() => {
                Aead::AesGcm(Box::new(
                    AesGcm::new(key).map_err(|_| CryptoError::InvalidAesGcmKeySize { actual })?,
                ))
            }
            Self::Aes128Gcm | Self::Aes256Gcm => {
                return Err(CryptoError::InvalidAesGcmKeySize { actual });
            }
            Self::ChaCha20Poly1305 => Aead::ChaCha20Poly1305(ChaCha20Poly1305::new(
                key.try_into()
                    .map_err(|_| CryptoError::InvalidChacha20Poly1305KeySize { actual })?,
            )),
        };
        Ok(Box::new(aead))
    }

    /// DTLS 1.3 record number protection (RFC 9147 section 4.2.3).
    fn mask(self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        // dimpl derives `sn_key` at the suite's key length.
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => {
                let mut mask = *sample;
                Aes::new(sn_key)
                    .expect("sn_key is an AES key length")
                    .encrypt_block(&mut mask);
                mask
            }
            Self::ChaCha20Poly1305 => {
                let key = sn_key.try_into().expect("sn_key is a ChaCha20 key length");
                let [c0, c1, c2, c3, nonce @ ..] = sample;
                let counter = u32::from_le_bytes([*c0, *c1, *c2, *c3]);
                let mut mask = [0u8; 16];
                ChaCha20::new(key)
                    .apply_keystream(nonce, counter, &mut mask)
                    .expect("one block never wraps the counter");
                mask
            }
        }
    }
}

enum Aead {
    AesGcm(Box<AesGcm>),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl fmt::Debug for Aead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AesGcm(_) => "AesGcm",
            Self::ChaCha20Poly1305(_) => "ChaCha20Poly1305",
        })
    }
}

impl Cipher for Aead {
    fn encrypt(&mut self, plaintext: &mut Buf, aad: Aad, nonce: Nonce) -> Result<(), CryptoError> {
        let mut tag = [0u8; TAG_LEN];
        match self {
            Self::AesGcm(aead) => aead.encrypt(&nonce.0, &aad, plaintext, &mut tag),
            Self::ChaCha20Poly1305(aead) => aead.encrypt(&nonce.0, &aad, plaintext, &mut tag),
        }
        .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Encrypt))?;
        plaintext.extend_from_slice(&tag);
        Ok(())
    }

    fn decrypt(
        &mut self,
        ciphertext: &mut TmpBuf,
        aad: Aad,
        nonce: Nonce,
    ) -> Result<(), CryptoError> {
        let len = ciphertext.len();
        let Some(plaintext_len) = len.checked_sub(TAG_LEN) else {
            return Err(CryptoError::CiphertextTooShort {
                minimum: TAG_LEN as u8,
                actual: len as u8,
            });
        };

        let (body, tag) = ciphertext.as_mut().split_at_mut(plaintext_len);
        match self {
            Self::AesGcm(aead) => aead.decrypt(&nonce.0, &aad, body, tag),
            Self::ChaCha20Poly1305(aead) => aead.decrypt(&nonce.0, &aad, body, tag),
        }
        .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Decrypt))?;

        ciphertext.truncate(plaintext_len);
        Ok(())
    }
}

#[derive(Debug)]
struct Dtls12 {
    suite: Dtls12CipherSuite,
    hash: HashAlgorithm,
    algorithm: Algorithm,
}

impl SupportedDtls12CipherSuite for Dtls12 {
    fn suite(&self) -> Dtls12CipherSuite {
        self.suite
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash
    }

    fn key_lengths(&self) -> (usize, usize, usize) {
        // (MAC key, encryption key, fixed IV): RFC 5288 and RFC 7905.
        let fixed_iv_len = match self.algorithm {
            Algorithm::Aes128Gcm | Algorithm::Aes256Gcm => 4,
            Algorithm::ChaCha20Poly1305 => 12,
        };
        (0, self.algorithm.key_len(), fixed_iv_len)
    }

    fn explicit_nonce_len(&self) -> usize {
        match self.algorithm {
            Algorithm::Aes128Gcm | Algorithm::Aes256Gcm => 8,
            Algorithm::ChaCha20Poly1305 => 0,
        }
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, CryptoError> {
        self.algorithm.cipher(key)
    }
}

#[derive(Debug)]
struct Dtls13 {
    suite: Dtls13CipherSuite,
    hash: HashAlgorithm,
    algorithm: Algorithm,
}

impl SupportedDtls13CipherSuite for Dtls13 {
    fn suite(&self) -> Dtls13CipherSuite {
        self.suite
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash
    }

    fn key_len(&self) -> usize {
        self.algorithm.key_len()
    }

    fn iv_len(&self) -> usize {
        12
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn Cipher>, CryptoError> {
        self.algorithm.cipher(key)
    }

    fn encrypt_sn(&self, sn_key: &[u8], sample: &[u8; 16]) -> [u8; 16] {
        self.algorithm.mask(sn_key, sample)
    }
}

/// DTLS 1.2 suites, in order of preference.
pub(crate) static DTLS12: &[&dyn SupportedDtls12CipherSuite] = &[
    &Dtls12 {
        suite: Dtls12CipherSuite::ECDHE_ECDSA_AES128_GCM_SHA256,
        hash: HashAlgorithm::SHA256,
        algorithm: Algorithm::Aes128Gcm,
    },
    &Dtls12 {
        suite: Dtls12CipherSuite::ECDHE_ECDSA_AES256_GCM_SHA384,
        hash: HashAlgorithm::SHA384,
        algorithm: Algorithm::Aes256Gcm,
    },
    &Dtls12 {
        suite: Dtls12CipherSuite::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256,
        hash: HashAlgorithm::SHA256,
        algorithm: Algorithm::ChaCha20Poly1305,
    },
];

/// DTLS 1.3 suites, in order of preference.
pub(crate) static DTLS13: &[&dyn SupportedDtls13CipherSuite] = &[
    &Dtls13 {
        suite: Dtls13CipherSuite::AES_128_GCM_SHA256,
        hash: HashAlgorithm::SHA256,
        algorithm: Algorithm::Aes128Gcm,
    },
    &Dtls13 {
        suite: Dtls13CipherSuite::AES_256_GCM_SHA384,
        hash: HashAlgorithm::SHA384,
        algorithm: Algorithm::Aes256Gcm,
    },
    &Dtls13 {
        suite: Dtls13CipherSuite::CHACHA20_POLY1305_SHA256,
        hash: HashAlgorithm::SHA256,
        algorithm: Algorithm::ChaCha20Poly1305,
    },
];
