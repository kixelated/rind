// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use libcrux_aes::aes_gcm_128::portable::PortableAesGcm128;
use libcrux_aes::aes_gcm_256::portable::PortableAesGcm256;
use libcrux_traits::aead::arrayref::Aead;

use super::aes::check_gcm_lengths;
use crate::Error;
use crate::low::{self, Entry, zeroise, zeroise_value};

/// An AES-GCM key.
///
/// This implementation is limited to that which is commonly
/// used:
///
/// - AES-192 is not supported, as it is rarely used.
/// - Only nonces that are 12-bytes/96-bits are supported.
pub struct AesGcm {
    key: [u8; 32],
    key_len: usize,
}

impl AesGcm {
    /// Expands a 16- or 32-byte key into an AES-128-GCM or AES-256-GCM key.
    ///
    /// Any other length, including AES-192's 24 bytes, is an error.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        let _entry = Entry::new_secret();
        if !matches!(key.len(), 16 | 32) {
            return Err(Error::WrongLength);
        }

        let mut r = Self {
            key: [0u8; 32],
            key_len: key.len(),
        };
        r.key[..key.len()].copy_from_slice(key);
        low::ct::secret_slice(&r.key[..key.len()]);
        Ok(r)
    }

    /// Encrypts the given message.
    ///
    /// On entry, `cipher_inout` contains the plaintext of the message.
    /// `nonce` contains the nonce, which must be unique for a given key.
    /// `aad` is the additionally-authenticated data.  It may be empty.
    ///
    /// On exit, `cipher_inout` contains the ciphertext of the message,
    /// and `tag_out` contains the authentication tag.
    ///
    /// Fails with [`Error::WrongLength`], leaving `cipher_inout` unchanged,
    /// if the message is longer than GCM's 2^36 - 32 bytes, or `aad` is
    /// 2^61 bytes or longer.
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        cipher_inout: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), Error> {
        let _entry = Entry::new_secret();
        check_gcm_lengths(aad.len(), cipher_inout.len())?;
        // libcrux reads and writes separate buffers.
        let mut plain = cipher_inout.to_vec();
        let result = match self.key_len {
            16 => PortableAesGcm128::encrypt(
                cipher_inout,
                tag_out,
                self.key[..16].try_into().unwrap(),
                nonce,
                aad,
                &plain,
            ),
            _ => PortableAesGcm256::encrypt(cipher_inout, tag_out, &self.key, nonce, aad, &plain),
        };
        zeroise(&mut plain);
        result.map_err(|_| Error::WrongLength)
    }

    /// Decrypts and verifies the given message.
    ///
    /// On entry, `cipher_inout` contains the ciphertext of the message.
    /// `nonce` contains the nonce, which must match what was supplied
    /// when encrypting this message.
    /// `aad` is the additionally-authenticated data.  It may be empty.
    /// `tag` is the purported authentication tag.
    ///
    /// On success, `cipher_inout` contains the plaintext of the message,
    /// and `Ok(())` is returned.
    /// A message past [`Self::encrypt`]'s limits fails with
    /// `Err(Error::WrongLength)`, leaving `cipher_inout` unchanged.
    /// Otherwise, `Err(Error::DecryptFailed)` is returned and `cipher_inout`
    /// is cleared.
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        cipher_inout: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        let _entry = Entry::new_secret();
        check_gcm_lengths(aad.len(), cipher_inout.len())?;
        let result = match <&[u8; 16]>::try_from(tag) {
            Ok(tag) => {
                let cipher = cipher_inout.to_vec();
                match self.key_len {
                    16 => PortableAesGcm128::decrypt(
                        cipher_inout,
                        self.key[..16].try_into().unwrap(),
                        nonce,
                        aad,
                        &cipher,
                        tag,
                    ),
                    _ => PortableAesGcm256::decrypt(
                        cipher_inout,
                        &self.key,
                        nonce,
                        aad,
                        &cipher,
                        tag,
                    ),
                }
                .is_ok()
            }
            Err(_) => false,
        };

        if result {
            Ok(())
        } else {
            // avoid unauthenticated plaintext leak
            cipher_inout.fill(0x00);
            Err(Error::DecryptFailed)
        }
    }
}

impl Drop for AesGcm {
    fn drop(&mut self) {
        zeroise(&mut self.key);
        zeroise_value(&mut self.key_len);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn smoketest() {
        let t = AesGcm::new(&[0; 16]).unwrap();
        let mut tag = [0u8; 16];
        t.encrypt(&[0u8; 12], &[], &mut [], &mut tag).unwrap();
        assert_eq!(
            &tag,
            b"\x58\xe2\xfc\xce\xfa\x7e\x30\x61\x36\x7f\x1d\x57\xa4\xe7\x45\x5a"
        );
    }

    #[test]
    fn long_round_trip() {
        let t = AesGcm::new(&[b'k'; 16]).unwrap();
        let expected = include_bytes!("../../testdata/aes-gcm-ciphertext.bin");
        let (expected_cipher, expected_tag) = expected.split_at(expected.len() - 16);

        let mut tag = [0u8; 16];
        let mut cipher = [b'p'; 4164];
        t.encrypt(b"noncenonceno", b"aad", &mut cipher, &mut tag)
            .unwrap();
        assert_eq!(expected_cipher, cipher);
        assert_eq!(expected_tag, tag);

        t.decrypt(b"noncenonceno", b"aad", &mut cipher, &tag)
            .unwrap();
        assert_eq!(cipher, [b'p'; 4164]);
    }

    #[test]
    fn rejects_short_tag() {
        let t = AesGcm::new(&[b'k'; 32]).unwrap();
        let mut tag = [0u8; 16];
        let mut cipher = *b"hello";
        t.encrypt(b"noncenonceno", b"", &mut cipher, &mut tag)
            .unwrap();
        assert_eq!(
            t.decrypt(b"noncenonceno", b"", &mut cipher, &tag[..15]),
            Err(Error::DecryptFailed)
        );
        assert_eq!(cipher, [0u8; 5]);
    }
}
