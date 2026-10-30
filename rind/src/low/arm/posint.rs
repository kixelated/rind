// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! A fixed-capacity unsigned integer, with the same encoding as the
//! other backends' `PosInt`.
//!
//! The arithmetic lives in `mid`'s RSA, over HACL*'s `Bignum64`.

use core::ops::{Deref, DerefMut};

use crate::Error;
use crate::low::generic::zeroise::Zeroable;
use crate::low::{ct, zeroise_value};

/// Little-endian words, of which `used` are significant.
#[derive(Clone, Debug)]
pub(crate) struct PosInt<const N: usize> {
    words: [u64; N],
    used: usize,
}

impl<const N: usize> PosInt<N> {
    /// Makes a value from little-endian `words`, `words.len()` wide.
    pub(crate) fn from_words(words: &[u64]) -> Result<Self, Error> {
        let mut r = Self {
            words: [0; N],
            used: words.len(),
        };
        r.words
            .get_mut(..words.len())
            .ok_or(Error::OutOfRange)?
            .copy_from_slice(words);
        Ok(r)
    }

    /// Decodes big-endian `bytes`, at the minimum width.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        let bytes = &bytes[start..];
        if bytes.len() > N * 8 {
            return Err(Error::OutOfRange);
        }

        let mut r = Self {
            words: [0; N],
            used: bytes.len().div_ceil(8),
        };
        for (word, chunk) in r.words.iter_mut().zip(bytes.rchunks(8)) {
            let mut be = [0u8; 8];
            be[8 - chunk.len()..].copy_from_slice(chunk);
            *word = u64::from_be_bytes(be);
        }
        Ok(r)
    }

    /// Encodes as big-endian, `8 * used` bytes long.
    pub(crate) fn to_bytes<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let out = out.get_mut(..self.used * 8).ok_or(Error::OutOfRange)?;
        for (chunk, word) in out.rchunks_exact_mut(8).zip(self.as_words()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        Ok(out)
    }

    /// Like `to_bytes`, but with a zero byte prefix, so it encodes as a
    /// positive ASN.1 integer.
    pub(crate) fn to_bytes_asn1<'a>(&self, out: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let out = out.get_mut(..self.used * 8 + 1).ok_or(Error::OutOfRange)?;
        out[0] = 0x00;
        self.to_bytes(&mut out[1..])?;
        Ok(out)
    }

    /// The length in bytes, without leading zeroes.
    pub(crate) fn len_bytes(&self) -> usize {
        self.len_bits().div_ceil(8)
    }

    /// The length in bits, without leading zeroes.
    pub(crate) fn len_bits(&self) -> usize {
        let top = self.as_words().iter().rposition(|w| *w != 0);
        top.map_or(0, |i| i * 64 + 64 - self.words[i].leading_zeros() as usize)
    }

    pub(crate) fn is_even(&self) -> bool {
        self.words[0] & 1 == 0
    }

    /// The significant words.
    pub(crate) fn as_words(&self) -> &[u64] {
        &self.words[..self.used]
    }

    /// The first `len` words, zero-extended beyond `used`.
    ///
    /// Fails if a significant word lies beyond `len`.
    pub(crate) fn words_at_width(&self, len: usize) -> Result<&[u64], Error> {
        match self.words.get(len..self.used.max(len)) {
            Some(above) if above.iter().all(|w| *w == 0) => Ok(&self.words[..len]),
            _ => Err(Error::OutOfRange),
        }
    }
}

// All-zero bytes are a valid zero.
impl<const N: usize> Zeroable for PosInt<N> {}

/// A `SecretPosInt` is a `PosInt` containing long-term key material.
///
/// It is zeroed on drop, including any padding after `used`.
pub(crate) struct SecretPosInt<const N: usize>(PosInt<N>);

impl<const N: usize> From<PosInt<N>> for SecretPosInt<N> {
    fn from(pi: PosInt<N>) -> Self {
        Self(PosInt {
            used: pi.used,
            words: ct::into_secret(pi.words),
        })
    }
}

impl<const N: usize> Deref for SecretPosInt<N> {
    type Target = PosInt<N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for SecretPosInt<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> Drop for SecretPosInt<N> {
    fn drop(&mut self) {
        zeroise_value(&mut self.0);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip() {
        let x = PosInt::<2>::from_bytes(b"\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09").unwrap();
        assert_eq!(x.as_words(), &[0x0203040506070809, 0x01]);
        assert_eq!(x.len_bytes(), 9);
        assert_eq!(x.len_bits(), 65);
        let mut out = [0u8; 17];
        assert_eq!(
            x.to_bytes(&mut out).unwrap(),
            b"\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"
        );
        assert_eq!(x.to_bytes_asn1(&mut out).unwrap()[..2], [0, 0]);
        assert_eq!(x.to_bytes(&mut [0u8; 15]), Err(Error::OutOfRange));
    }

    #[test]
    fn zero() {
        let x = PosInt::<2>::from_bytes(b"\x00\x00").unwrap();
        assert!(x.as_words().is_empty());
        assert_eq!(x.len_bytes(), 0);
        assert_eq!(x.len_bits(), 0);
    }

    #[test]
    fn too_long() {
        assert_eq!(
            PosInt::<1>::from_bytes(&[1; 9]).unwrap_err(),
            Error::OutOfRange
        );
        assert!(PosInt::<1>::from_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08").is_ok());
    }

    #[test]
    fn widths() {
        let x = PosInt::<4>::from_words(&[1, 2, 0]).unwrap();
        assert_eq!(x.words_at_width(4).unwrap(), &[1, 2, 0, 0]);
        assert_eq!(x.words_at_width(2).unwrap(), &[1, 2]);
        assert_eq!(x.words_at_width(1), Err(Error::OutOfRange));
    }
}
