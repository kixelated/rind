// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! HKDF (HMAC-based Key Derivation Function).
//!
//! HKDF is standardized in [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869).
//!
//! ```
//! use rind::hashing::Sha256;
//! use rind::hashing::hkdf::Prk;
//!
//! let prk = Prk::<Sha256>::extract(b"salt", b"input key material");
//!
//! let mut key = [0u8; 16];
//! prk.expand(&[b"label", b"context"], &mut key).unwrap();
//! ```

use core::marker::PhantomData;

use super::hash::Hash;
use super::hmac::Hmac;
use crate::Error;
use crate::low::zeroise;

/// A pseudorandom key, from which [`Prk::expand`] derives any number of keys.
pub struct Prk<H: Hash> {
    // Sized for the largest hash output; only the first hash length is used.
    key: [u8; 64],
    _hash: PhantomData<H>,
}

impl<H: Hash> Prk<H> {
    /// Extracts a pseudorandom key from `ikm`, keyed by `salt` (HKDF-Extract).
    ///
    /// An empty `salt` is the same as RFC 5869's absent salt.
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Self {
        let mut hmac = Hmac::<H>::new(salt);
        hmac.update(ikm);
        let prk = hmac.finish();

        let mut key = [0u8; 64];
        key[..prk.as_ref().len()].copy_from_slice(prk.as_ref());

        Self {
            key,
            _hash: PhantomData,
        }
    }

    /// Fills `out` with key material derived for the concatenation of `info` (HKDF-Expand).
    ///
    /// Fails with [`Error::WrongLength`], leaving `out` unchanged, if `out` is
    /// longer than 255 hash outputs.
    pub fn expand(&self, info: &[&[u8]], out: &mut [u8]) -> Result<(), Error> {
        let mut block = H::zeroed_output();
        let hash_len = block.as_ref().len();
        if out.len() > 255 * hash_len {
            return Err(Error::WrongLength);
        }

        for (i, chunk) in out.chunks_mut(hash_len).enumerate() {
            let mut ctx = Hmac::<H>::new(&self.key[..hash_len]);
            if i > 0 {
                ctx.update(&block);
            }
            for part in info {
                ctx.update(part);
            }
            ctx.update([i as u8 + 1]);
            block = ctx.finish();
            chunk.copy_from_slice(&block.as_ref()[..chunk.len()]);
        }

        // The last block's tail is key material the caller did not take.
        zeroise(block.as_mut());
        Ok(())
    }
}

impl<H: Hash> Drop for Prk<H> {
    fn drop(&mut self) {
        zeroise(&mut self.key);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::high::hash::{Sha256, Sha384, Sha512};

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
            let got =
                Prk::<Sha256>::extract(&hex::decode(salt).unwrap(), &hex::decode(ikm).unwrap());
            assert_eq!(hex::encode(&got.key[..32]), prk);

            let mut out = vec![0u8; okm.len() / 2];
            got.expand(&[&hex::decode(info).unwrap()], &mut out)
                .unwrap();
            assert_eq!(hex::encode(out), okm);
        }
    }

    #[test]
    fn secret_ikm() {
        // Under `admin/ctgrind`, nothing may branch on or index by the input
        // key material or anything derived from it.
        fn check<H: Hash>() {
            let ikm = [0x5a; 48];
            let mut wanted = [0u8; 100];
            Prk::<H>::extract(b"salt", &ikm)
                .expand(&[b"info"], &mut wanted)
                .unwrap();

            crate::low::ct::secret_slice(&ikm);
            let mut got = [0u8; 100];
            Prk::<H>::extract(b"salt", &ikm)
                .expand(&[b"info"], &mut got)
                .unwrap();
            crate::low::ct::public_slice(&got);
            assert_eq!(got, wanted);
        }

        check::<Sha256>();
        check::<Sha384>();
        check::<Sha512>();
    }
}
