// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use libcrux_chacha20poly1305::xchacha20_poly1305;

use crate::Error;
use crate::low::{self, Entry, zeroise};

/// A XChaCha20Poly1305 key.
///
/// See [RFC7539](https://datatracker.ietf.org/doc/html/rfc7539).
pub struct XChaCha20Poly1305 {
    key: [u8; 32],
}

impl XChaCha20Poly1305 {
    /// Create a new [`XChaCha20Poly1305`] from 32 bytes of key material.
    pub fn new(key: [u8; 32]) -> Self {
        low::ct::secret_slice(&key);
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
    pub fn encrypt(
        &self,
        nonce: &[u8; 24],
        aad: &[u8],
        cipher_inout: &mut [u8],
        tag_out: &mut [u8; 16],
    ) {
        let _entry = Entry::new_secret();
        // libcrux writes the ciphertext and tag to one separate buffer.
        let mut plain = cipher_inout.to_vec();
        let mut sealed = vec![0u8; plain.len() + 16];
        let result = xchacha20_poly1305::encrypt(&self.key, &plain, &mut sealed, aad, nonce).map(
            |(cipher, tag)| {
                cipher_inout.copy_from_slice(cipher);
                tag_out.copy_from_slice(tag);
            },
        );
        zeroise(&mut plain);
        // `usize` is 32 bits here, so every length fits HACL's `u32`.
        result.expect("XChaCha20Poly1305 lengths are within limits");
        low::ct::public_slice(cipher_inout);
        low::ct::public_slice(tag_out);
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
    /// Otherwise, `Err(Error::DecryptFailed)` is returned and `cipher_inout`
    /// is cleared.
    pub fn decrypt(
        &self,
        nonce: &[u8; 24],
        aad: &[u8],
        cipher_inout: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        let _entry = Entry::new_secret();
        let ok = tag.len() == 16 && {
            let mut sealed = Vec::with_capacity(cipher_inout.len() + 16);
            sealed.extend_from_slice(cipher_inout);
            sealed.extend_from_slice(tag);
            xchacha20_poly1305::decrypt(&self.key, cipher_inout, &sealed, aad, nonce).is_ok()
        };

        if low::ct::into_public(ok) {
            low::ct::public_slice(cipher_inout);
            Ok(())
        } else {
            // avoid unauthenticated plaintext leak
            cipher_inout.fill(0x00);
            Err(Error::DecryptFailed)
        }
    }
}

impl Drop for XChaCha20Poly1305 {
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
        let k = XChaCha20Poly1305::new([1; 32]);
        let mut buffer = *b"hello world";
        let mut tag = [0u8; 16];
        k.encrypt(&[2; 24], b"aad", &mut buffer, &mut tag);
        assert_ne!(&buffer, b"hello world");
        k.decrypt(&[2; 24], b"aad", &mut buffer, &tag).unwrap();
        assert_eq!(&buffer, b"hello world");
    }

    #[test]
    fn rejects_short_tag() {
        let k = XChaCha20Poly1305::new([1; 32]);
        let mut buffer = *b"hello";
        let mut tag = [0u8; 16];
        k.encrypt(&[2; 24], b"", &mut buffer, &mut tag);
        assert_eq!(
            k.decrypt(&[2; 24], b"", &mut buffer, &tag[..15]),
            Err(Error::DecryptFailed)
        );
        assert_eq!(buffer, [0u8; 5]);
    }
}
