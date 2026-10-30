// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! HKDF (HMAC-based Key Derivation Function), following aws-lc-rs's `hkdf`.
//!
//! HKDF is standardized in [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869).

use super::digest::MAX_OUTPUT_LEN;
use super::hash::Hash;
use super::hmac::{self, Hmac, Keyed};
use crate::low::zeroise;
use crate::{Error, aead};

/// An HKDF algorithm, chosen by one of this module's constants.
#[derive(Clone, Copy, Debug)]
pub struct Algorithm(hmac::Algorithm);

impl Algorithm {
    /// The HMAC algorithm that extracts and expands.
    pub fn hmac_algorithm(&self) -> hmac::Algorithm {
        self.0
    }
}

/// HKDF-SHA256.
pub static HKDF_SHA256: Algorithm = Algorithm(hmac::HMAC_SHA256);

/// HKDF-SHA384.
pub static HKDF_SHA384: Algorithm = Algorithm(hmac::HMAC_SHA384);

/// HKDF-SHA512.
pub static HKDF_SHA512: Algorithm = Algorithm(hmac::HMAC_SHA512);

/// A salt, keyed once and reused for every secret it extracts from.
pub struct Salt(hmac::Key);

impl Salt {
    /// Keys `algorithm` with `value`; an empty `value` is RFC 5869's absent salt.
    pub fn new(algorithm: Algorithm, value: &[u8]) -> Self {
        Self(hmac::Key::new(algorithm.0, value))
    }

    /// Extracts a pseudorandom key from `secret` (HKDF-Extract).
    pub fn extract(&self, secret: &[u8]) -> Prk {
        let prk = hmac::sign(&self.0, secret);
        Prk(hmac::Key::new(self.0.algorithm(), prk.as_ref()))
    }
}

/// A pseudorandom key, from which [`Prk::expand`] derives any number of keys; wiped on drop.
//
// Held as an HMAC key so each expand block skips the two key compressions.
pub struct Prk(hmac::Key);

impl Prk {
    /// Derives `len` bytes of key material for the concatenation of `info` (HKDF-Expand).
    ///
    /// Fails with [`Error::WrongLength`] if `len` is longer than 255 hash outputs.
    pub fn expand<'a, L: KeyType>(
        &'a self,
        info: &'a [&'a [u8]],
        len: L,
    ) -> Result<Okm<'a, L>, Error> {
        if len.len() > self.max_len() {
            return Err(Error::WrongLength);
        }
        Ok(Okm {
            prk: self,
            info,
            len,
        })
    }

    // HKDF-Expand's one-byte block counter limits it to 255 blocks.
    fn max_len(&self) -> usize {
        255 * self.0.algorithm().tag_len()
    }

    // Fills `out`, which the caller has checked is at most `max_len` bytes.
    fn expand_into(&self, info: &[&[u8]], out: &mut [u8]) {
        fn expand<H: Hash>(hmac: &Hmac<H>, info: &[&[u8]], out: &mut [u8]) {
            let mut block = H::zeroed_output();
            let hash_len = block.as_ref().len();
            for (counter, chunk) in (1..=255u8).zip(out.chunks_mut(hash_len)) {
                let mut ctx = hmac.clone();
                if counter > 1 {
                    ctx.update(&block);
                }
                for part in info {
                    ctx.update(part);
                }
                ctx.update([counter]);
                block = ctx.finish();
                chunk.copy_from_slice(&block.as_ref()[..chunk.len()]);
            }

            // The last block's tail is key material the caller did not take.
            zeroise(block.as_mut());
        }

        match &self.0.0 {
            Keyed::Sha1(hmac) => expand(hmac, info, out),
            Keyed::Sha256(hmac) => expand(hmac, info, out),
            Keyed::Sha384(hmac) => expand(hmac, info, out),
            Keyed::Sha512(hmac) => expand(hmac, info, out),
        }
    }
}

/// A length of HKDF output: a plain `usize`, or the algorithm of the key it becomes.
#[allow(clippy::len_without_is_empty)]
pub trait KeyType {
    /// The length, in bytes.
    fn len(&self) -> usize;
}

/// Raw key material of this many bytes, for [`Okm::fill`].
///
/// This is rind's addition: aws-lc-rs callers write a newtype for it.
impl KeyType for usize {
    fn len(&self) -> usize {
        *self
    }
}

/// A key of the algorithm's [`aead::Algorithm::key_len`].
impl KeyType for &'static aead::Algorithm {
    fn len(&self) -> usize {
        self.key_len()
    }
}

/// A key of the algorithm's [`hmac::Algorithm::tag_len`].
impl KeyType for hmac::Algorithm {
    fn len(&self) -> usize {
        self.tag_len()
    }
}

/// Key material from [`Prk::expand`], sized by `L`: fill a buffer with it, or convert it into a key.
pub struct Okm<'a, L: KeyType> {
    prk: &'a Prk,
    info: &'a [&'a [u8]],
    len: L,
}

impl<L: KeyType> Okm<'_, L> {
    /// Writes the key material into `out`.
    ///
    /// Fails with [`Error::WrongLength`], leaving `out` unchanged, unless
    /// `out` is the length [`Prk::expand`] was given.
    pub fn fill(self, out: &mut [u8]) -> Result<(), Error> {
        // Bounded again: a `KeyType` may answer differently than it did in `expand`.
        if out.len() != self.len.len() || out.len() > self.prk.max_len() {
            return Err(Error::WrongLength);
        }
        self.prk.expand_into(self.info, out);
        Ok(())
    }

    // Expands into a stack buffer for `key` to copy, then wipes it, since the
    // key it becomes owns the secret. Only rind's own `KeyType`s reach here,
    // whose lengths fit the buffer and the 255-block limit.
    fn into_key<K>(self, key: impl FnOnce(&L, &[u8]) -> K) -> K {
        let mut buf = [0u8; MAX_OUTPUT_LEN];
        let bytes = &mut buf[..self.len.len()];
        self.prk.expand_into(self.info, bytes);
        let key = key(&self.len, bytes);
        zeroise(&mut buf);
        key
    }
}

impl From<Okm<'_, &'static aead::Algorithm>> for aead::UnboundKey {
    fn from(okm: Okm<'_, &'static aead::Algorithm>) -> Self {
        okm.into_key(|algorithm, bytes| Self::new(algorithm, bytes))
            .expect("HKDF output is the algorithm's key length")
    }
}

impl From<Okm<'_, hmac::Algorithm>> for hmac::Key {
    fn from(okm: Okm<'_, hmac::Algorithm>) -> Self {
        okm.into_key(|algorithm, bytes| Self::new(*algorithm, bytes))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::aead::{AES_128_GCM, AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce};

    #[test]
    fn rfc5869() {
        // Appendix A.1 to A.3, the SHA-256 cases; A.3 has no salt or info.
        let cases = [
            (
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "000102030405060708090a0b0c",
                "f0f1f2f3f4f5f6f7f8f9",
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                 34007208d5b887185865",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
                 404142434445464748494a4b4c4d4e4f",
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
                 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
                 a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
                 d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
                 f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
                 59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
                 cc30c58179ec3e87c14c01d5c1f3434f1d87",
            ),
            (
                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                "",
                "",
                "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                 9d201395faa4b61a96c8",
            ),
        ];

        for (ikm, salt, info, prk, okm) in cases {
            let got = Salt::new(HKDF_SHA256, &hex::decode(salt).unwrap())
                .extract(&hex::decode(ikm).unwrap());
            // HMAC of the empty message under the stored key identifies the PRK.
            let wanted = hmac::Key::new(hmac::HMAC_SHA256, &hex::decode(prk).unwrap());
            assert_eq!(
                hmac::sign(&got.0, b"").as_ref(),
                hmac::sign(&wanted, b"").as_ref()
            );

            let info = hex::decode(info).unwrap();
            let mut out = vec![0u8; okm.len() / 2];
            got.expand(&[&info], out.len())
                .unwrap()
                .fill(&mut out)
                .unwrap();
            assert_eq!(hex::encode(out), okm);
        }
    }

    #[test]
    fn lengths() {
        for algorithm in [HKDF_SHA256, HKDF_SHA384, HKDF_SHA512] {
            let prk = Salt::new(algorithm, b"salt").extract(b"secret");
            let max = 255 * algorithm.hmac_algorithm().tag_len();
            assert_eq!(prk.expand(&[], max + 1).err(), Some(Error::WrongLength));

            let mut out = vec![0u8; max];
            prk.expand(&[], max).unwrap().fill(&mut out).unwrap();
            for len in [0, max - 1, max + 1] {
                let mut wrong = vec![0u8; len];
                let okm = prk.expand(&[], max).unwrap();
                assert_eq!(okm.fill(&mut wrong), Err(Error::WrongLength));
                assert!(wrong.iter().all(|b| *b == 0));
            }
        }

        // A `KeyType` that grows after `expand` checked it is refused by
        // `fill`, rather than reaching past the 255-block limit.
        struct Growing(core::cell::Cell<usize>);

        impl KeyType for Growing {
            fn len(&self) -> usize {
                self.0.replace(10_000)
            }
        }

        let prk = Salt::new(HKDF_SHA256, b"salt").extract(b"secret");
        let okm = prk.expand(&[], Growing(core::cell::Cell::new(32))).unwrap();
        let mut out = vec![0u8; 10_000];
        assert_eq!(okm.fill(&mut out), Err(Error::WrongLength));
    }

    #[test]
    fn keys_match_filled_bytes() {
        let prk = Salt::new(HKDF_SHA256, b"salt").extract(b"secret");
        let info: [&[u8]; 2] = [b"label", b"context"];

        for algorithm in [&AES_128_GCM, &AES_256_GCM, &CHACHA20_POLY1305] {
            let mut bytes = vec![0u8; algorithm.key_len()];
            prk.expand(&info, bytes.len())
                .unwrap()
                .fill(&mut bytes)
                .unwrap();
            let seal = |key: aead::UnboundKey| {
                LessSafeKey::new(key)
                    .seal_in_place_separate_tag(
                        Nonce::assume_unique_for_key([0; 12]),
                        Aad::empty(),
                        &mut [0u8; 16],
                    )
                    .unwrap()
                    .as_ref()
                    .to_vec()
            };
            assert_eq!(
                seal(aead::UnboundKey::from(
                    prk.expand(&info, algorithm).unwrap()
                )),
                seal(aead::UnboundKey::new(algorithm, &bytes).unwrap()),
            );
        }

        for algorithm in [
            hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            hmac::HMAC_SHA256,
            hmac::HMAC_SHA384,
            hmac::HMAC_SHA512,
        ] {
            let mut bytes = vec![0u8; algorithm.tag_len()];
            prk.expand(&info, bytes.len())
                .unwrap()
                .fill(&mut bytes)
                .unwrap();
            let key = hmac::Key::from(prk.expand(&info, algorithm).unwrap());
            assert_eq!(key.algorithm().tag_len(), algorithm.tag_len());
            assert_eq!(
                hmac::sign(&key, b"message").as_ref(),
                hmac::sign(&hmac::Key::new(algorithm, &bytes), b"message").as_ref()
            );
        }
    }

    #[test]
    fn secret_ikm() {
        // Under `admin/ctgrind`, nothing may branch on or index by the input
        // key material or anything derived from it, including the keys an
        // `Okm` becomes.
        let info: [&[u8]; 1] = [b"info"];
        let derive = |algorithm, ikm: &[u8]| {
            let prk = Salt::new(algorithm, b"salt").extract(ikm);
            let mut bytes = [0u8; 100];
            prk.expand(&info, bytes.len())
                .unwrap()
                .fill(&mut bytes)
                .unwrap();
            let aead_key = LessSafeKey::new(aead::UnboundKey::from(
                prk.expand(&info, &AES_256_GCM).unwrap(),
            ));
            let aead_tag = aead_key
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key([0; 12]),
                    Aad::empty(),
                    &mut [],
                )
                .unwrap();
            let hmac_key = hmac::Key::from(prk.expand(&info, hmac::HMAC_SHA256).unwrap());
            let hmac_tag = hmac::sign(&hmac_key, b"message");
            (
                bytes,
                aead_tag.as_ref().to_vec(),
                hmac_tag.as_ref().to_vec(),
            )
        };

        for algorithm in [HKDF_SHA256, HKDF_SHA384, HKDF_SHA512] {
            let ikm = [0x5a; 48];
            let wanted = derive(algorithm, &ikm);

            crate::low::ct::secret_slice(&ikm);
            let (bytes, aead_tag, hmac_tag) = derive(algorithm, &ikm);
            crate::low::ct::public_slice(&bytes);
            crate::low::ct::public_slice(&aead_tag);
            crate::low::ct::public_slice(&hmac_tag);
            assert_eq!((bytes, aead_tag, hmac_tag), wanted);
        }
    }
}
