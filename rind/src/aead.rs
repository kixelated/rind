// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::Error;
use crate::low::{Zeroable, zeroise_value};
use crate::mid::aes_gcm::AesGcm;
use crate::mid::chacha20poly1305::ChaCha20Poly1305;
use crate::mid::rng::{RandomSource, SystemRandom};
use crate::mid::xchacha20poly1305::XChaCha20Poly1305;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// An AEAD algorithm, which fixes the key length a key must have.
#[derive(Debug)]
pub struct Algorithm {
    id: AlgorithmId,
}

#[derive(Debug)]
enum AlgorithmId {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Algorithm {
    /// The length of a key, in bytes.
    pub fn key_len(&self) -> usize {
        match self.id {
            AlgorithmId::Aes128Gcm => 16,
            AlgorithmId::Aes256Gcm | AlgorithmId::ChaCha20Poly1305 => 32,
        }
    }

    /// The length of a tag, in bytes.
    pub fn tag_len(&self) -> usize {
        TAG_LEN
    }

    /// The length of a nonce, in bytes.
    pub fn nonce_len(&self) -> usize {
        NONCE_LEN
    }
}

/// AES-128 in GCM mode, with a 16-byte key.
pub static AES_128_GCM: Algorithm = Algorithm {
    id: AlgorithmId::Aes128Gcm,
};

/// AES-256 in GCM mode, with a 32-byte key.
pub static AES_256_GCM: Algorithm = Algorithm {
    id: AlgorithmId::Aes256Gcm,
};

/// ChaCha20-Poly1305 from RFC 8439, with a 32-byte key.
pub static CHACHA20_POLY1305: Algorithm = Algorithm {
    id: AlgorithmId::ChaCha20Poly1305,
};

/// An AEAD key, expanded once for its algorithm and wiped on drop.
///
/// Bind it to a nonce policy, such as [`LessSafeKey`], to use it.
pub struct UnboundKey(Key);

impl UnboundKey {
    /// Expands `key` for `algorithm`, failing with [`Error::WrongLength`] if
    /// it is not [`Algorithm::key_len`] bytes.
    pub fn new(algorithm: &'static Algorithm, key: &[u8]) -> Result<Self, Error> {
        if key.len() != algorithm.key_len() {
            return Err(Error::WrongLength);
        }

        Ok(Self(match algorithm.id {
            AlgorithmId::Aes128Gcm | AlgorithmId::Aes256Gcm => Key::AesGcm(AesGcm::new(key)?),
            AlgorithmId::ChaCha20Poly1305 => Key::ChaCha20Poly1305(ChaCha20Poly1305::new(
                key.try_into().map_err(|_| Error::WrongLength)?,
            )),
        }))
    }
}

// All-zero is the `AesGcm` variant with an all-zero key and table, which
// `Zeroable` requires to be valid: every field is a plain integer or vector.
//
// Boxing the AES-GCM table would allocate for every key to save space only on
// ChaCha20-Poly1305 keys; the 32-bit arm table is small, so the lint is allowed
// rather than expected.
#[allow(clippy::large_enum_variant)]
#[repr(u8)]
enum Key {
    AesGcm(AesGcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl Key {
    fn seal(&self, nonce: Nonce, aad: &[u8], in_out: &mut [u8]) -> Result<Tag, Error> {
        let mut tag = [0u8; TAG_LEN];
        match self {
            Self::AesGcm(key) => key.encrypt(&nonce.0, aad, in_out, &mut tag),
            Self::ChaCha20Poly1305(key) => key.encrypt(&nonce.0, aad, in_out, &mut tag),
        }?;
        Ok(Tag(tag))
    }

    fn open(&self, nonce: Nonce, aad: &[u8], tag: &[u8], in_out: &mut [u8]) -> Result<(), Error> {
        match self {
            Self::AesGcm(key) => key.decrypt(&nonce.0, aad, in_out, tag),
            Self::ChaCha20Poly1305(key) => key.decrypt(&nonce.0, aad, in_out, tag),
        }
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // Wipes the discriminant and the space a smaller variant leaves unused,
        // not only the variant's own key.
        zeroise_value(self);
    }
}

impl Zeroable for Key {}

/// An AEAD key that seals with any nonce the caller gives it.
///
/// The caller owns nonce uniqueness: sealing two messages with one nonce and
/// key loses confidentiality and lets anyone forge messages. Derive nonces
/// from protocol state that never repeats, such as a record sequence number,
/// or use [`RandomizedNonceKey`].
pub struct LessSafeKey(UnboundKey);

impl LessSafeKey {
    /// Binds `key` to caller-provided nonces.
    pub fn new(key: UnboundKey) -> Self {
        Self(key)
    }

    /// Encrypts `in_out` in place and returns the tag.
    ///
    /// Fails with [`Error::WrongLength`], leaving `in_out` unchanged, if
    /// `in_out` or `aad` is past the algorithm's limit: 2^36 - 32 and 2^61 - 1
    /// bytes for AES-GCM, and 2^38 - 64 bytes of `in_out` for
    /// ChaCha20-Poly1305.
    pub fn seal_in_place_separate_tag<A: AsRef<[u8]>>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut [u8],
    ) -> Result<Tag, Error> {
        self.0.0.seal(nonce, aad.0.as_ref(), in_out)
    }

    /// Encrypts `in_out` in place and appends the tag to it.
    ///
    /// Fails as [`Self::seal_in_place_separate_tag`] does.
    pub fn seal_in_place_append_tag<A, InOut>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), Error>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'a> Extend<&'a u8>,
    {
        let tag = self.seal_in_place_separate_tag(nonce, aad, in_out.as_mut())?;
        in_out.extend(tag.as_ref());
        Ok(())
    }

    /// Decrypts and verifies `in_out`, the ciphertext followed by its tag, and
    /// returns the plaintext at its front.
    ///
    /// Fails with [`Error::DecryptFailed`] if `in_out` is shorter than a tag or
    /// does not verify, clearing the ciphertext in the latter case, and with
    /// [`Error::WrongLength`] past the sealing limits.
    pub fn open_in_place<'a, A: AsRef<[u8]>>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error> {
        let len = in_out
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::DecryptFailed)?;
        let (in_out, tag) = in_out.split_at_mut(len);
        self.0.0.open(nonce, aad.0.as_ref(), tag, in_out)?;
        Ok(in_out)
    }

    /// Decrypts and verifies `in_out` against the separate `tag`, and returns
    /// the plaintext.
    ///
    /// Fails with [`Error::DecryptFailed`], clearing `in_out`, if it does not
    /// verify, and with [`Error::WrongLength`] past the sealing limits.
    pub fn open_in_place_separate_tag<'a, A: AsRef<[u8]>>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        tag: &[u8],
        in_out: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error> {
        self.0.0.open(nonce, aad.0.as_ref(), tag, in_out)?;
        Ok(in_out)
    }
}

/// A 96-bit nonce, which the caller promises seals only once under a key.
///
/// It is not `Clone`, so one value seals at most one message.
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Wraps `nonce`, which the caller promises is never reused with the same key.
    pub fn assume_unique_for_key(nonce: [u8; NONCE_LEN]) -> Self {
        Self(nonce)
    }
}

/// Additional authenticated data: authenticated but not encrypted.
pub struct Aad<A: AsRef<[u8]>>(A);

impl<A: AsRef<[u8]>> Aad<A> {
    /// Wraps `aad`.
    pub fn from(aad: A) -> Self {
        Self(aad)
    }
}

impl Aad<[u8; 0]> {
    /// No additional authenticated data.
    pub fn empty() -> Self {
        Self([])
    }
}

/// An authentication tag, as sealing returns it.
pub struct Tag([u8; TAG_LEN]);

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// An XChaCha20-Poly1305 key that picks a random 192-bit nonce for every seal.
///
/// A 192-bit nonce is long enough that random ones never collide in
/// practice, so the caller tracks no nonce state. aws-lc-rs builds this key
/// on AES-GCM, whose random 96-bit nonces risk a collision after about 2^32
/// seals; rind builds it on XChaCha20-Poly1305 alone, so it takes no
/// algorithm.
pub struct RandomizedNonceKey(XChaCha20Poly1305);

impl RandomizedNonceKey {
    /// Makes a key from 32 bytes of key material.
    pub fn new(key: &[u8; 32]) -> Self {
        Self(XChaCha20Poly1305::new(*key))
    }

    /// Encrypts `in_out` in place under a fresh random nonce, appends the tag,
    /// and returns the nonce, which the opener needs.
    ///
    /// Fails with [`Error::RngFailed`] if the system random source does, or
    /// with [`Error::WrongLength`], leaving `in_out` unchanged, if it is longer
    /// than 2^38 - 64 bytes.
    pub fn seal_in_place_append_tag<A, InOut>(
        &self,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<RandomNonce, Error>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'a> Extend<&'a u8>,
    {
        let mut nonce = [0u8; 24];
        SystemRandom.fill(&mut nonce)?;
        let mut tag = [0u8; TAG_LEN];
        self.0
            .encrypt(&nonce, aad.0.as_ref(), in_out.as_mut(), &mut tag)?;
        in_out.extend(&tag);
        Ok(RandomNonce(nonce))
    }

    /// Decrypts and verifies `in_out`, the ciphertext followed by its tag,
    /// sealed under `nonce`, and returns the plaintext at its front.
    ///
    /// Fails as [`LessSafeKey::open_in_place`] does.
    pub fn open_in_place<'a, A: AsRef<[u8]>>(
        &self,
        nonce: RandomNonce,
        aad: Aad<A>,
        in_out: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error> {
        let len = in_out
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::DecryptFailed)?;
        let (in_out, tag) = in_out.split_at_mut(len);
        self.0.decrypt(&nonce.0, aad.0.as_ref(), in_out, tag)?;
        Ok(in_out)
    }
}

/// The 192-bit nonce a [`RandomizedNonceKey`] picked, to send with its ciphertext.
#[derive(Clone, Copy, Debug)]
pub struct RandomNonce([u8; 24]);

impl AsRef<[u8]> for RandomNonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 24]> for RandomNonce {
    fn from(nonce: [u8; 24]) -> Self {
        Self(nonce)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const ALGORITHMS: [&Algorithm; 3] = [&AES_128_GCM, &AES_256_GCM, &CHACHA20_POLY1305];

    #[test]
    fn key_length_must_match_algorithm() {
        let key = [0u8; 33];
        for algorithm in ALGORITHMS {
            for len in 0..=key.len() {
                assert_eq!(
                    UnboundKey::new(algorithm, &key[..len]).is_ok(),
                    len == algorithm.key_len(),
                    "{algorithm:?} len {len}"
                );
            }
        }
    }

    #[test]
    fn seal_and_open() {
        for algorithm in ALGORITHMS {
            let key = LessSafeKey::new(
                UnboundKey::new(algorithm, &[7u8; 32][..algorithm.key_len()]).unwrap(),
            );
            let nonce = || Nonce::assume_unique_for_key([9; 12]);

            let mut sealed = b"hello".to_vec();
            key.seal_in_place_append_tag(nonce(), Aad::from(b"aad"), &mut sealed)
                .unwrap();
            assert_eq!(sealed.len(), 5 + algorithm.tag_len());

            let mut separate = b"hello".to_vec();
            let tag = key
                .seal_in_place_separate_tag(nonce(), Aad::from(b"aad"), &mut separate)
                .unwrap();
            assert_eq!([&separate[..], tag.as_ref()].concat(), sealed);

            let mut opened = sealed.clone();
            assert_eq!(
                key.open_in_place(nonce(), Aad::from(b"aad"), &mut opened)
                    .unwrap(),
                b"hello"
            );
            assert_eq!(
                key.open_in_place_separate_tag(
                    nonce(),
                    Aad::from(b"aad"),
                    tag.as_ref(),
                    &mut separate
                )
                .unwrap(),
                b"hello"
            );

            // A wrong AAD fails and clears the ciphertext, leaving the tag.
            let mut wrong = sealed.clone();
            assert_eq!(
                key.open_in_place(nonce(), Aad::empty(), &mut wrong),
                Err(Error::DecryptFailed)
            );
            assert_eq!(wrong[..5], [0; 5]);
            assert_eq!(wrong[5..], sealed[5..]);
        }
    }

    #[test]
    fn open_refuses_input_shorter_than_tag() {
        for algorithm in ALGORITHMS {
            let key = LessSafeKey::new(
                UnboundKey::new(algorithm, &[7u8; 32][..algorithm.key_len()]).unwrap(),
            );
            let mut short = [0xaau8; TAG_LEN - 1];
            assert_eq!(
                key.open_in_place(
                    Nonce::assume_unique_for_key([0; 12]),
                    Aad::empty(),
                    &mut short
                ),
                Err(Error::DecryptFailed)
            );
            assert_eq!(short, [0xaa; TAG_LEN - 1]);
        }
    }

    #[test]
    fn randomized_nonce_key() {
        let key = RandomizedNonceKey::new(&[3u8; 32]);

        let mut first = b"ticket".to_vec();
        let nonce = key
            .seal_in_place_append_tag(Aad::from(b"name"), &mut first)
            .unwrap();
        let mut second = b"ticket".to_vec();
        let other = key
            .seal_in_place_append_tag(Aad::from(b"name"), &mut second)
            .unwrap();
        assert_ne!(nonce.as_ref(), other.as_ref());
        assert_ne!(first, second);

        let received = RandomNonce::from(<[u8; 24]>::try_from(nonce.as_ref()).unwrap());
        assert_eq!(
            key.open_in_place(received, Aad::from(b"name"), &mut first)
                .unwrap(),
            b"ticket"
        );
        assert_eq!(
            key.open_in_place(nonce, Aad::from(b"name"), &mut second),
            Err(Error::DecryptFailed)
        );
        assert_eq!(
            key.open_in_place(nonce, Aad::empty(), &mut [0u8; TAG_LEN - 1]),
            Err(Error::DecryptFailed)
        );
    }
}
