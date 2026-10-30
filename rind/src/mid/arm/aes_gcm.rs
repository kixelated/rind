// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use libcrux_aes::aes_gcm_128::portable::PortableAesGcm128;
use libcrux_aes::aes_gcm_256::portable::PortableAesGcm256;
use libcrux_traits::aead::arrayref::Aead;

use super::aes::check_gcm_lengths;
use crate::Error;
use crate::low::{
    self, AesHwKey, Entry, GhashTable, HaveCryptoExt, ct_equal, zeroise, zeroise_value,
};

/// An AES-GCM key.
///
/// This implementation is limited to that which is commonly
/// used:
///
/// - AES-192 is not supported, as it is rarely used.
/// - Only nonces that are 12-bytes/96-bits are supported.
// A process only ever builds one variant, so boxing would buy nothing.
#[expect(clippy::large_enum_variant)]
pub(crate) enum AesGcm {
    Portable(Portable),
    /// The crypto extension's, which the key picks when the CPU has it.
    Hw(Hw),
}

impl AesGcm {
    /// Expands a 16- or 32-byte key into an AES-128-GCM or AES-256-GCM key.
    ///
    /// Any other length, including AES-192's 24 bytes, is an error.
    pub(crate) fn new(key: &[u8]) -> Result<Self, Error> {
        let _entry = Entry::new_secret();
        if !matches!(key.len(), 16 | 32) {
            return Err(Error::WrongLength);
        }

        // Mark a copy: the caller's buffer may be shared, or a promoted constant.
        let mut copy = [0u8; 32];
        let copy_key = &mut copy[..key.len()];
        copy_key.copy_from_slice(key);
        low::ct::secret_slice(copy_key);
        Ok(match HaveCryptoExt::check() {
            Some(token) => Self::Hw(Hw::new(copy_key, token)),
            None => Self::Portable(Portable::new(copy_key)),
        })
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
    pub(crate) fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        cipher_inout: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), Error> {
        let _entry = Entry::new_secret();
        check_gcm_lengths(aad.len(), cipher_inout.len())?;
        match self {
            Self::Portable(key) => key.encrypt(nonce, aad, cipher_inout, tag_out)?,
            Self::Hw(key) => key.encrypt(nonce, aad, cipher_inout, tag_out),
        }
        low::ct::public_slice(cipher_inout);
        low::ct::public_slice(tag_out);
        Ok(())
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
    pub(crate) fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        cipher_inout: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        let _entry = Entry::new_secret();
        check_gcm_lengths(aad.len(), cipher_inout.len())?;
        let result = match self {
            Self::Portable(key) => key.decrypt(nonce, aad, cipher_inout, tag),
            Self::Hw(key) => key.decrypt(nonce, aad, cipher_inout, tag),
        };

        if low::ct::into_public(result) {
            low::ct::public_slice(cipher_inout);
            Ok(())
        } else {
            // avoid unauthenticated plaintext leak
            cipher_inout.fill(0x00);
            Err(Error::DecryptFailed)
        }
    }
}

/// libcrux's portable AES-GCM, for CPUs without the crypto extension.
pub(crate) struct Portable {
    key: [u8; 32],
    key_len: usize,
}

impl Portable {
    fn new(key: &[u8]) -> Self {
        let mut r = Self {
            key: [0u8; 32],
            key_len: key.len(),
        };
        r.key[..key.len()].copy_from_slice(key);
        r
    }

    fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        cipher_inout: &mut [u8],
        tag_out: &mut [u8; 16],
    ) -> Result<(), Error> {
        // libcrux reads and writes separate buffers.
        let plain = cipher_inout.to_vec();
        match self.key_len {
            16 => PortableAesGcm128::encrypt(
                cipher_inout,
                tag_out,
                self.key[..16].try_into().unwrap(),
                nonce,
                aad,
                &plain,
            ),
            _ => PortableAesGcm256::encrypt(cipher_inout, tag_out, &self.key, nonce, aad, &plain),
        }
        .map_err(|_| Error::WrongLength)
    }

    /// Decrypts in place, returning whether `tag` is right.
    fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], cipher_inout: &mut [u8], tag: &[u8]) -> bool {
        match <&[u8; 16]>::try_from(tag) {
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
        }
    }
}

impl Drop for Portable {
    fn drop(&mut self) {
        zeroise(&mut self.key);
        zeroise_value(&mut self.key_len);
    }
}

/// aws-lc's AES and GHASH for the crypto extension, composed as aws-lc's
/// `CRYPTO_gcm128_encrypt_ctr32` does on 32-bit ARM.
pub(crate) struct Hw {
    key: AesHwKey,
    table: GhashTable,
}

impl Hw {
    /// Bytes of counter mode between GHASH passes, so GHASH reads them back
    /// from cache: aws-lc's `GHASH_CHUNK`.
    const CHUNK: usize = 3 * 1024;

    fn new(key: &[u8], token: HaveCryptoExt) -> Self {
        let key = AesHwKey::new(key, token);
        let mut h = [0u8; 16];
        key.encrypt_block(&mut h);
        let table = GhashTable::new(&h, token);
        Self { key, table }
    }

    fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        cipher_inout: &mut [u8],
        tag_out: &mut [u8; 16],
    ) {
        let mut xi = [0u8; 16];
        self.ghash(&mut xi, aad);
        let mut counter = 2;
        for chunk in cipher_inout.chunks_mut(Self::CHUNK) {
            counter = self.ctr(nonce, counter, chunk);
            self.ghash(&mut xi, chunk);
        }
        *tag_out = self.tag(nonce, xi, aad.len(), cipher_inout.len());
    }

    /// Decrypts in place, returning whether `tag` is right.
    fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], cipher_inout: &mut [u8], tag: &[u8]) -> bool {
        let mut xi = [0u8; 16];
        self.ghash(&mut xi, aad);
        let mut counter = 2;
        for chunk in cipher_inout.chunks_mut(Self::CHUNK) {
            self.ghash(&mut xi, chunk);
            counter = self.ctr(nonce, counter, chunk);
        }
        ct_equal(&self.tag(nonce, xi, aad.len(), cipher_inout.len()), tag)
    }

    /// XORs the keystream from block `counter` into `inout`, returning the
    /// next block's counter.
    fn ctr(&self, nonce: &[u8; 12], counter: u32, inout: &mut [u8]) -> u32 {
        let mut ivec = [0u8; 16];
        ivec[..12].copy_from_slice(nonce);
        ivec[12..].copy_from_slice(&counter.to_be_bytes());

        let (blocks, tail) = inout.as_chunks_mut::<16>();
        self.key.ctr32(&ivec, blocks);
        // `check_gcm_lengths` keeps the counter from wrapping.
        let counter = counter + blocks.len() as u32;
        if tail.is_empty() {
            return counter;
        }

        ivec[12..].copy_from_slice(&counter.to_be_bytes());
        self.key.encrypt_block(&mut ivec);
        for (b, k) in tail.iter_mut().zip(ivec) {
            *b ^= k;
        }
        counter + 1
    }

    /// Folds `data` into `xi`, padding its last block with zeroes.
    fn ghash(&self, xi: &mut [u8; 16], data: &[u8]) {
        let (blocks, tail) = data.as_chunks::<16>();
        self.table.ghash(xi, blocks);
        if !tail.is_empty() {
            let mut last = [0u8; 16];
            last[..tail.len()].copy_from_slice(tail);
            self.table.ghash(xi, &[last]);
        }
    }

    /// Finishes GHASH with the bit lengths, then masks it with the first
    /// counter block's keystream.
    fn tag(&self, nonce: &[u8; 12], mut xi: [u8; 16], aad: usize, msg: usize) -> [u8; 16] {
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&((aad as u64) * 8).to_be_bytes());
        lengths[8..].copy_from_slice(&((msg as u64) * 8).to_be_bytes());
        self.table.ghash(&mut xi, &[lengths]);

        let mut y0 = [0u8; 16];
        y0[..12].copy_from_slice(nonce);
        y0[15] = 1;
        self.key.encrypt_block(&mut y0);
        for (x, e) in xi.iter_mut().zip(y0) {
            *x ^= e;
        }
        xi
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

    // Every other test sees only the path the CPU picks, so the crypto
    // extension's is checked against libcrux's here: each key size, AAD and
    // message lengths around the block and chunk boundaries, and a tampered
    // tag.
    #[test]
    fn hw_matches_portable() {
        let Some(token) = HaveCryptoExt::check() else {
            return;
        };
        let bytes = |n: usize, seed: u32| -> Vec<u8> {
            (0..n as u32)
                .map(|i| (i.wrapping_add(seed).wrapping_mul(0x9e3779b9) >> 24) as u8)
                .collect()
        };
        for key_len in [16, 32] {
            let key = bytes(key_len, 1);
            let portable = Portable::new(&key);
            let hw = Hw::new(&key, token);
            for aad_len in [0, 1, 15, 16, 17, 33] {
                for msg_len in [0, 1, 15, 16, 17, 48, 127, 128, 129, 3071, 3072, 3073, 6200] {
                    let nonce = bytes(12, msg_len as u32).try_into().unwrap();
                    let aad = bytes(aad_len, 2);
                    let plain = bytes(msg_len, 3);

                    let (mut want, mut want_tag) = (plain.clone(), [0u8; 16]);
                    portable
                        .encrypt(&nonce, &aad, &mut want, &mut want_tag)
                        .unwrap();
                    let (mut got, mut got_tag) = (plain.clone(), [0u8; 16]);
                    hw.encrypt(&nonce, &aad, &mut got, &mut got_tag);
                    assert_eq!(
                        (&got, got_tag),
                        (&want, want_tag),
                        "{key_len} {aad_len} {msg_len}"
                    );

                    assert!(hw.decrypt(&nonce, &aad, &mut got, &want_tag));
                    assert_eq!(got, plain);
                    want_tag[0] ^= 1;
                    assert!(!hw.decrypt(&nonce, &aad, &mut want, &want_tag));
                }
            }
        }
    }
}
