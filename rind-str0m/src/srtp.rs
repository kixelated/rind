use std::fmt;

use rind::aead::AesGcm;
use rind::cipher::{Aes, AesCtr};
use str0m_proto::crypto::{
    AeadAes128GcmCipher, AeadAes256GcmCipher, Aes128CmSha1_80Cipher, CryptoError, SrtpProvider,
    SupportedAeadAes128Gcm, SupportedAeadAes256Gcm, SupportedAes128CmSha1_80,
};

const TAG_LEN: usize = 16;

pub(crate) static SRTP: RindSrtp = RindSrtp;

#[derive(Debug)]
pub(crate) struct RindSrtp;

impl SrtpProvider for RindSrtp {
    fn aes_128_cm_sha1_80(&self) -> &'static dyn SupportedAes128CmSha1_80 {
        &RindSrtp
    }

    fn aead_aes_128_gcm(&self) -> &'static dyn SupportedAeadAes128Gcm {
        &RindSrtp
    }

    fn aead_aes_256_gcm(&self) -> &'static dyn SupportedAeadAes256Gcm {
        &RindSrtp
    }

    fn srtp_aes_128_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        ecb_round::<16>(key, input, output);
    }

    fn srtp_aes_256_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        ecb_round::<32>(key, input, output);
    }
}

// str0m sizes these from its own types, never from a packet, and the trait has
// no error path, so a mismatch is a str0m bug worth a panic.
fn ecb_round<const KEY_LEN: usize>(key: &[u8], input: &[u8], output: &mut [u8]) {
    assert_eq!(key.len(), KEY_LEN, "SRTP master key length");
    let mut block: [u8; 16] = input.try_into().expect("SRTP key derivation block");
    Aes::new(key).unwrap().encrypt_block(&mut block);
    output[..16].copy_from_slice(&block);
}

impl SupportedAes128CmSha1_80 for RindSrtp {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn Aes128CmSha1_80Cipher> {
        Box::new(Cm(AesCtr::new(&key).unwrap()))
    }
}

impl SupportedAeadAes128Gcm for RindSrtp {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn AeadAes128GcmCipher> {
        Box::new(Gcm(AesGcm::new(&key)))
    }
}

impl SupportedAeadAes256Gcm for RindSrtp {
    fn create_cipher(&self, key: [u8; 32], _encrypt: bool) -> Box<dyn AeadAes256GcmCipher> {
        Box::new(Gcm(AesGcm::new(&key)))
    }
}

/// AES counter mode, keyed for one SRTP or SRTCP direction.
struct Cm(AesCtr);

impl fmt::Debug for Cm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cm").finish_non_exhaustive()
    }
}

impl Cm {
    fn apply(&self, iv: &[u8; 16], input: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        let output = output
            .get_mut(..input.len())
            .ok_or_else(|| CryptoError::Other("AES-CM output too short".into()))?;
        output.copy_from_slice(input);

        // SRTP's 128-bit counter block splits into rind's 96-bit nonce and
        // 32-bit counter. str0m's IVs leave the low 16 bits zero, so a packet
        // never carries past the counter; one that would is refused.
        let (nonce, counter) = iv.split_first_chunk::<12>().unwrap();
        let counter = u32::from_be_bytes(counter.try_into().unwrap());
        self.0
            .apply_keystream(nonce, counter, output)
            .map_err(|e| CryptoError::Other(format!("AES-CM failed: {e:?}")))
    }
}

impl Aes128CmSha1_80Cipher for Cm {
    fn encrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.apply(iv, input, output)
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.apply(iv, input, output)
    }
}

/// AES-GCM, keyed for one SRTP or SRTCP direction.
struct Gcm(AesGcm);

impl fmt::Debug for Gcm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gcm").finish_non_exhaustive()
    }
}

impl Gcm {
    /// Writes the ciphertext then the tag into `output`.
    fn seal(
        &self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let output = output
            .get_mut(..input.len() + TAG_LEN)
            .ok_or_else(|| CryptoError::Other("AES-GCM output too short".into()))?;
        let (ciphertext, tag) = output.split_at_mut(input.len());
        ciphertext.copy_from_slice(input);
        self.0
            .encrypt(iv, aad, ciphertext, tag.try_into().unwrap())
            .map_err(|e| CryptoError::Other(format!("AES-GCM failed: {e:?}")))
    }

    /// Opens `input`, the ciphertext then the tag, and returns the plaintext length.
    fn open(
        &self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let (ciphertext, tag) = input
            .split_last_chunk::<TAG_LEN>()
            .ok_or_else(|| CryptoError::Other("AES-GCM input shorter than its tag".into()))?;
        let plaintext = output
            .get_mut(..ciphertext.len())
            .ok_or_else(|| CryptoError::Other("AES-GCM output too short".into()))?;
        plaintext.copy_from_slice(ciphertext);

        // str0m splits the AAD only for unencrypted SRTCP.
        let joined;
        let aad = match aads {
            [aad] => aad,
            _ => {
                joined = aads.concat();
                joined.as_slice()
            }
        };

        self.0
            .decrypt(iv, aad, plaintext, tag)
            .map_err(|e| CryptoError::Other(format!("AES-GCM failed: {e:?}")))?;
        Ok(ciphertext.len())
    }
}

impl AeadAes128GcmCipher for Gcm {
    fn encrypt(
        &mut self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.seal(iv, aad, input, output)
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.open(iv, aads, input, output)
    }
}

impl AeadAes256GcmCipher for Gcm {
    fn encrypt(
        &mut self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.seal(iv, aad, input, output)
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.open(iv, aads, input, output)
    }
}
