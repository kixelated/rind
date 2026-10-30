// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! RSA public operations over HACL*'s `Bignum64`, the arithmetic
//! libcrux's RSA-PSS uses.

use libcrux_hacl_rs::bignum::base::{self, bn_mont_ctx_u64};
use libcrux_hacl_rs::bignum::bignum64;

use crate::error::Error;
use crate::low;

#[derive(Clone, Debug)]
pub(crate) struct RsaPublicKey {
    pub(crate) n: RsaPosInt,
    pub(crate) e: u32,

    /// The Montgomery setup, which HACL*'s `mod_exp_vartime` would
    /// otherwise recompute on every operation: R² mod n, as wide as `n`,
    /// and -n⁻¹ mod 2^64.
    r2: [u64; MAX_PUBLIC_MODULUS_WORDS],
    mu: u64,
}

// Every field is words, a length, or an integer, all valid at zero.
impl low::Zeroable for RsaPublicKey {}

impl RsaPublicKey {
    pub(crate) fn new(n: RsaPosInt, e: u32) -> Result<Self, Error> {
        if n.is_even()
            || !(MIN_PUBLIC_MODULUS_BITS..=MAX_PUBLIC_MODULUS_BITS).contains(&n.len_bits())
            || e == 0
        {
            return Err(Error::OutOfRange);
        }

        let mu = base::mod_inv_uint64(n.as_words()[0]);
        let r2 = montgomery_r2(&n, mu);
        Ok(Self { n, e, r2, mu })
    }

    pub(crate) fn modulus_len_bytes(&self) -> usize {
        self.n.len_bytes()
    }

    pub(crate) fn modulus_len_bits(&self) -> usize {
        self.n.len_bits()
    }

    /// m = c ** e mod n
    pub(crate) fn public_op(&self, c: RsaPosInt) -> Result<RsaPosInt, Error> {
        let n = self.n.as_words();
        let len = n.len() as u32;
        let c = c.words_at_width(n.len())?;
        if bignum64::lt_mask(len, c, n) != u64::MAX {
            return Err(Error::OutOfRange);
        }

        let k = [bn_mont_ctx_u64 {
            len,
            n: n.into(),
            mu: self.mu,
            r2: self.r2[..n.len()].into(),
        }];
        let mut m = [0u64; MAX_PUBLIC_MODULUS_WORDS];
        let m = &mut m[..n.len()];
        // The exponent is public, so a variable-time ladder is fine, and
        // its exact length saves the squarings past its top bit.
        let e_bits = u32::BITS - self.e.leading_zeros();
        bignum64::mod_exp_vartime_precomp(&k, c, e_bits, &[u64::from(self.e)], m);
        RsaPosInt::from_words(m)
    }
}

/// R² mod n, for R = 2^(64 * len) where `n`, of `len` words, is odd and
/// `mu` = -n⁻¹ mod 2^64.
///
/// HACL*'s `bn_precomp_r2_mod_n_u64` doubles up to R² itself, about
/// 64 * len modular doublings. This doubles 2^(bits - 1) only up to
/// R * 2^len, then squares six times in Montgomery form, which takes
/// R * 2^x to R * 2^(2x), so ends at R * 2^(64 * len) = R². Every step is
/// HACL*'s verified `bn_add_mod_n` or `bn_mont_sqr`, given an input below
/// n: 2^(bits - 1) < n since n is odd, and each step's result is below n.
fn montgomery_r2(n: &RsaPosInt, mu: u64) -> [u64; MAX_PUBLIC_MODULUS_WORDS] {
    let (bits, n) = (n.len_bits(), n.as_words());
    let len = n.len();
    let mut r2 = [0u64; MAX_PUBLIC_MODULUS_WORDS];
    let mut x = [0u64; MAX_PUBLIC_MODULUS_WORDS];
    let (r, x) = (&mut r2[..len], &mut x[..len]);
    r[(bits - 1) / 64] = 1 << ((bits - 1) % 64);
    for _ in bits - 1..64 * len + len {
        x.copy_from_slice(r);
        base::bn_add_mod_n_u64(len as u32, n, x, x, r);
    }
    for _ in 0..6 {
        x.copy_from_slice(r);
        base::bn_mont_sqr_u64(len as u32, n, mu, x, r);
    }
    r2
}

const MAX_PUBLIC_MODULUS_BITS: usize = 8192;
pub(crate) const MAX_PUBLIC_MODULUS_WORDS: usize = MAX_PUBLIC_MODULUS_BITS / 64;
pub(crate) const MAX_PUBLIC_MODULUS_BYTES: usize = MAX_PUBLIC_MODULUS_BITS / 8;

const MIN_PUBLIC_MODULUS_BITS: usize = 2048;

type RsaPosInt = low::PosInt<MAX_PUBLIC_MODULUS_WORDS>;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Against HACL*'s own R², at the extremes of each width, including a
    /// top word of one.
    #[test]
    fn montgomery_r2_matches_hacl() {
        for bits in [2048usize, 2049, 3072, 4095, 8192] {
            let len = bits.div_ceil(64);
            let mut low = [0u64; MAX_PUBLIC_MODULUS_WORDS];
            low[0] = 1;
            low[(bits - 1) / 64] |= 1 << ((bits - 1) % 64);
            let mut high = [0u64; MAX_PUBLIC_MODULUS_WORDS];
            high[..len].fill(u64::MAX);
            high[len - 1] >>= 64 * len - bits;

            for n in [&low[..len], &high[..len]] {
                let key = RsaPublicKey::new(RsaPosInt::from_words(n).unwrap(), 3).unwrap();
                let want = bignum64::mont_ctx_init(len as u32, n);
                assert_eq!(key.mu, want[0].mu, "{bits} bits");
                assert_eq!(&key.r2[..len], &want[0].r2[..], "{bits} bits");
            }
        }
    }
}
