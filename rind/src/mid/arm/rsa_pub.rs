// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! RSA public operations over HACL*'s `Bignum64`, the arithmetic
//! libcrux's RSA-PSS uses.

use libcrux_hacl_rs::bignum::bignum64;

use crate::error::Error;
use crate::low;

#[derive(Clone, Debug)]
pub(crate) struct RsaPublicKey {
    pub(crate) n: RsaPosInt,
    pub(crate) e: u32,
}

impl RsaPublicKey {
    pub(crate) fn new(n: RsaPosInt, e: u32) -> Result<Self, Error> {
        let n_len = n.len_bytes();
        if n.is_even()
            || !(MIN_PUBLIC_MODULUS_BYTES..=MAX_PUBLIC_MODULUS_BYTES).contains(&n_len)
            || e == 0
        {
            return Err(Error::OutOfRange);
        }

        Ok(Self { n, e })
    }

    pub(crate) fn modulus_len_bytes(&self) -> usize {
        self.n.len_bytes()
    }

    /// m = c ** e mod n
    pub(crate) fn public_op(&self, c: RsaPosInt) -> Result<RsaPosInt, Error> {
        let n = self.n.as_words();
        let len = n.len() as u32;
        let c = c.words_at_width(n.len())?;
        if bignum64::lt_mask(len, c, n) != u64::MAX {
            return Err(Error::OutOfRange);
        }

        let mut m = [0u64; MAX_PUBLIC_MODULUS_WORDS];
        let m = &mut m[..n.len()];
        // The exponent is public, so a variable-time ladder is fine.
        match bignum64::mod_exp_vartime(len, n, c, u32::BITS, &[u64::from(self.e)], m) {
            true => RsaPosInt::from_words(m),
            false => Err(Error::OutOfRange),
        }
    }
}

const MAX_PUBLIC_MODULUS_BITS: usize = 8192;
pub(crate) const MAX_PUBLIC_MODULUS_WORDS: usize = MAX_PUBLIC_MODULUS_BITS / 64;
pub(crate) const MAX_PUBLIC_MODULUS_BYTES: usize = MAX_PUBLIC_MODULUS_BITS / 8;

const MIN_PUBLIC_MODULUS_BITS: usize = 2048;
const MIN_PUBLIC_MODULUS_BYTES: usize = MIN_PUBLIC_MODULUS_BITS / 8;

type RsaPosInt = low::PosInt<MAX_PUBLIC_MODULUS_WORDS>;
