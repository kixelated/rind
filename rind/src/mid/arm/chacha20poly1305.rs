// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::chacha20::check_counter;
use crate::Error;
use crate::low::{Entry, zeroise};

/// A ChaCha20Poly1305 key.
///
/// See [RFC7539](https://datatracker.ietf.org/doc/html/rfc7539).
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl ChaCha20Poly1305 {
    /// Create a new [`ChaCha20Poly1305`] from 32 bytes of key material.
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Encrypt the given message.
    ///
    /// On entry, `cipher_inout` contains the plaintext of the message.
    /// `nonce` contains the nonce, which must be unique for a given key.
    /// `aad` is the additionally-authenticated data.  It may be empty.
    ///
    /// On exit, `cipher_inout` contains the ciphertext of the message,
    /// and `tag_out` contains the authentication tag.
    ///
    /// Fails with [`Error::WrongLength`], leaving `cipher_inout` unchanged,
    /// if the message is longer than the 2^38 - 64 bytes its 32-bit block
    /// counter covers.
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        cipher_inout: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), Error> {
        let _entry = Entry::new_secret();
        // block 0 keys Poly1305
        check_counter(1, cipher_inout.len())?;
        // libcrux reads and writes separate buffers.
        let plain = cipher_inout.to_vec();
        libcrux_chacha20poly1305::encrypt_detached(
            &self.key,
            &plain,
            cipher_inout,
            tag_out,
            aad,
            nonce,
        )
        .map(|_| ())
        .map_err(|_| Error::WrongLength)
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
    /// A message past [`Self::encrypt`]'s limit fails with
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
        check_counter(1, cipher_inout.len())?;
        let ok = match <&[u8; 16]>::try_from(tag) {
            Ok(tag) => {
                let cipher = cipher_inout.to_vec();
                libcrux_chacha20poly1305::decrypt_detached(
                    &self.key,
                    cipher_inout,
                    &cipher,
                    tag,
                    aad,
                    nonce,
                )
                .is_ok()
            }
            Err(_) => false,
        };

        if ok {
            Ok(())
        } else {
            // avoid unauthenticated plaintext leak
            cipher_inout.fill(0x00);
            Err(Error::DecryptFailed)
        }
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        zeroise(&mut self.key);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn round_trip_in_place() {
        let k = ChaCha20Poly1305::new([1; 32]);
        let mut buffer = *b"hello world";
        let mut tag = [0u8; 16];
        k.encrypt(&[2; 12], b"aad", &mut buffer, &mut tag).unwrap();
        assert_ne!(&buffer, b"hello world");
        k.decrypt(&[2; 12], b"aad", &mut buffer, &tag).unwrap();
        assert_eq!(&buffer, b"hello world");
    }

    #[test]
    fn rejects_short_tag() {
        let k = ChaCha20Poly1305::new([1; 32]);
        let mut buffer = *b"hello";
        let mut tag = [0u8; 16];
        k.encrypt(&[2; 12], b"", &mut buffer, &mut tag).unwrap();
        assert_eq!(
            k.decrypt(&[2; 12], b"", &mut buffer, &tag[..15]),
            Err(Error::DecryptFailed)
        );
        assert_eq!(buffer, [0u8; 5]);
    }
}
