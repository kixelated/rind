// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! RSA private operations over HACL*'s `Bignum64`, the arithmetic
//! libcrux's RSA-PSS uses, composed by the Chinese remainder theorem.

use core::ops::Deref;

use libcrux_hacl_rs::bignum::base::{self, bn_mont_ctx_u64};
use libcrux_hacl_rs::bignum::bignum64;

use super::rsa_pub::{MAX_PUBLIC_MODULUS_BYTES, RsaPublicKey};
use crate::error::Error;
use crate::low;
use crate::mid::rng::RandomSource;

#[path = "rsa_priv/generate.rs"]
mod generate;
pub use generate::KeySize;

/// `public` comes first so its (non-secret) bytes form a prefix.
#[repr(C)]
pub(crate) struct RsaPrivateKey {
    public: RsaPublicKey,

    p: SecretRsaPosIntModP,
    q: SecretRsaPosIntModP,
    d: SecretRsaPosIntD,
    dp: SecretRsaPosIntModP,
    dq: SecretRsaPosIntModP,
    iqmp: SecretRsaPosIntModP,
}

impl RsaPrivateKey {
    pub(crate) fn new(
        p: RsaPosIntModP,
        q: RsaPosIntModP,
        d: RsaPosIntD,
        dp: RsaPosIntModP,
        dq: RsaPosIntModP,
        iqmp: RsaPosIntModP,
        n: RsaPosIntModN,
        e: u32,
    ) -> Result<Self, Error> {
        let p_len = p.len_bytes();
        if p.is_even()
            || q.is_even()
            || !(MIN_PRIVATE_MODULUS_BYTES..=MAX_PRIVATE_MODULUS_BYTES).contains(&p_len)
        {
            return Err(Error::OutOfRange);
        }

        let public = RsaPublicKey::new(n, e)?;

        // The CRT works at the width of the wider prime, so every
        // component must fit it, and `n` twice it.
        let width = p.as_words().len().max(q.as_words().len());
        for x in [&dp, &dq, &iqmp] {
            x.words_at_width(width)?;
        }
        public.n.words_at_width(width * 2)?;

        Ok(Self {
            public,
            p: p.into(),
            q: q.into(),
            d: d.into(),
            dp: dp.into(),
            dq: dq.into(),
            iqmp: iqmp.into(),
        })
    }

    pub(crate) fn generate(
        size: KeySize,
        candidate_source: &mut dyn RandomSource,
        witness_source: &mut dyn RandomSource,
    ) -> Result<Self, Error> {
        generate::generate_key(size, candidate_source, witness_source)
    }

    pub(crate) fn public_key(&self) -> RsaPublicKey {
        self.public.clone()
    }

    pub(crate) fn modulus_len_bytes(&self) -> usize {
        self.public.modulus_len_bytes()
    }

    pub(crate) fn modulus_len_bits(&self) -> usize {
        self.public.modulus_len_bits()
    }

    pub(crate) fn encode_components<'a>(
        &self,
        buffer: &'a mut RsaComponentsBuffer,
    ) -> Result<RsaComponents<'a>, Error> {
        let (public_modulus, buffer) = buffer.0.split_at_mut(MAX_PUBLIC_MODULUS_BYTES + 1);
        let (public_exponent, buffer) = buffer.split_at_mut(4);
        let (p, buffer) = buffer.split_at_mut(MAX_PRIVATE_MODULUS_BYTES + 1);
        let (q, buffer) = buffer.split_at_mut(MAX_PRIVATE_MODULUS_BYTES + 1);
        let (d, buffer) = buffer.split_at_mut(MAX_PUBLIC_MODULUS_BYTES + 1);
        let (dp, buffer) = buffer.split_at_mut(MAX_PRIVATE_MODULUS_BYTES + 1);
        let (dq, buffer) = buffer.split_at_mut(MAX_PRIVATE_MODULUS_BYTES + 1);
        let (iqmp, _) = buffer.split_at_mut(MAX_PRIVATE_MODULUS_BYTES + 1);

        let public_modulus = self.public.n.to_bytes_asn1(public_modulus)?;
        public_exponent.copy_from_slice(&self.public.e.to_be_bytes());

        let p = self.p.to_bytes_asn1(p)?;
        let q = self.q.to_bytes_asn1(q)?;
        let d = self.d.to_bytes_asn1(d)?;
        let dp = self.dp.to_bytes_asn1(dp)?;
        let dq = self.dq.to_bytes_asn1(dq)?;
        let iqmp = self.iqmp.to_bytes_asn1(iqmp)?;

        // We are exporting this key; it is leaving the confines of this
        // library and becoming public data.
        low::ct::public_slice(p);
        low::ct::public_slice(q);
        low::ct::public_slice(d);
        low::ct::public_slice(dp);
        low::ct::public_slice(dq);
        low::ct::public_slice(iqmp);

        Ok(RsaComponents {
            public_modulus,
            public_exponent,
            p,
            q,
            d,
            dp,
            dq,
            iqmp,
        })
    }

    /// returns c ^ d mod n
    ///
    /// (albeit via CRT)
    pub(crate) fn private_op(&self, c: &RsaPosIntModN) -> Result<RsaPosIntModN, Error> {
        let n = self.public.n.as_words();
        let c_n = c.words_at_width(n.len())?;
        if bignum64::lt_mask(n.len() as u32, c_n, n) != u64::MAX {
            return Err(Error::OutOfRange);
        }

        // Widths were checked in `new`.
        let w = self.p.as_words().len().max(self.q.as_words().len());
        let dp = self.dp.words_at_width(w)?;
        let dq = self.dq.words_at_width(w)?;
        let iqmp = self.iqmp.words_at_width(w)?;
        let c = c.words_at_width(w * 2)?;

        // Each prime's length in words is public.
        let p = Mont::new_secret(self.p.words_at_width(w)?, self.p.as_words().len());
        let q = Mont::new_secret(self.q.words_at_width(w)?, self.q.as_words().len());

        let mut scratch = CrtScratch::default();
        scratch.compute(
            w,
            Primes {
                p: &p,
                q: &q,
                dp,
                dq,
                iqmp,
            },
            c,
        );
        let m = RsaPosIntModN::from_words(&scratch.m[..n.len()]);
        drop(scratch);
        let m = low::ct::into_public(m?);

        // validate the result as a fault attack countermeasure,
        // at the same time it validates our working above, and
        // the key halves against each other
        let c2 = self.public.public_op(m.clone())?;
        match c2.words_at_width(n.len()) {
            Ok(c2) if bignum64::eq_mask(n.len() as u32, c2, c_n) == u64::MAX => Ok(m),
            _ => Err(Error::DecryptFailed),
        }
    }
}

/// The CRT inputs, each `w` words wide.
struct Primes<'a> {
    p: &'a Mont,
    q: &'a Mont,
    dp: &'a [u64],
    dq: &'a [u64],
    iqmp: &'a [u64],
}

/// The CRT's intermediate values, zeroed on drop.
struct CrtScratch {
    m_1: [u64; MAX_PRIVATE_MODULUS_WORDS],
    m_2: [u64; MAX_PRIVATE_MODULUS_WORDS],
    h: [u64; MAX_PRIVATE_MODULUS_WORDS],
    t: [u64; MAX_PRIVATE_MODULUS_WORDS],
    wide: [u64; MAX_PRIVATE_MODULUS_WORDS * 2],
    qh: [u64; MAX_PRIVATE_MODULUS_WORDS * 2],
    m: [u64; MAX_PRIVATE_MODULUS_WORDS * 2],
}

impl CrtScratch {
    /// Leaves `c ^ d mod n` in `m`.
    fn compute(&mut self, w: usize, k: Primes<'_>, c: &[u64]) {
        let len = w as u32;
        let bits = len * 64;
        let (m_1, m_2) = (&mut self.m_1[..w], &mut self.m_2[..w]);
        let (h, t) = (&mut self.h[..w], &mut self.t[..w]);
        let (wide, qh) = (&mut self.wide[..w * 2], &mut self.qh[..w * 2]);
        let m = &mut self.m[..w * 2];

        // i.   Let m_1 = c^dP mod p and m_2 = c^dQ mod q.
        // (do reductions of c first, so the mod exp can be done at
        // width of p or q rather than pq.)
        bignum64::mod_precomp(k.p, c, t);
        bignum64::mod_exp_consttime_precomp(k.p, t, bits, k.dp, m_1);
        bignum64::mod_precomp(k.q, c, t);
        bignum64::mod_exp_consttime_precomp(k.q, t, bits, k.dq, m_2);

        // ii. If u > 2, let m_i = c^(d_i) mod r_i, i = 3, ..., u.
        // (we don't support multiprime rsa)

        // iii. Let h = (m_1 - m_2) * qInv mod p.
        // (m_2 < q may exceed p, so reduce it first.)
        wide.fill(0);
        wide[..w].copy_from_slice(m_2);
        bignum64::mod_precomp(k.p, wide, t);
        bignum64::sub_mod(len, &k.p[0].n, m_1, t, h);
        bignum64::mul(len, h, k.iqmp, wide);
        bignum64::mod_precomp(k.p, wide, h);

        // iv.  Let m = m_2 + q * h.
        // (no carry: m < pq < 2^(128w))
        bignum64::mul(len, &k.q[0].n, h, qh);
        wide.fill(0);
        wide[..w].copy_from_slice(m_2);
        let _carry = bignum64::add(len * 2, wide, qh, m);
    }
}

impl Default for CrtScratch {
    fn default() -> Self {
        Self {
            m_1: [0; MAX_PRIVATE_MODULUS_WORDS],
            m_2: [0; MAX_PRIVATE_MODULUS_WORDS],
            h: [0; MAX_PRIVATE_MODULUS_WORDS],
            t: [0; MAX_PRIVATE_MODULUS_WORDS],
            wide: [0; MAX_PRIVATE_MODULUS_WORDS * 2],
            qh: [0; MAX_PRIVATE_MODULUS_WORDS * 2],
            m: [0; MAX_PRIVATE_MODULUS_WORDS * 2],
        }
    }
}

impl Drop for CrtScratch {
    fn drop(&mut self) {
        low::zeroise(&mut self.m_1);
        low::zeroise(&mut self.m_2);
        low::zeroise(&mut self.h);
        low::zeroise(&mut self.t);
        low::zeroise(&mut self.wide);
        low::zeroise(&mut self.qh);
        low::zeroise(&mut self.m);
    }
}

/// A HACL* Montgomery context, zeroed on drop.
struct Mont(Box<[bn_mont_ctx_u64]>);

impl Mont {
    /// A context for a public `n`, which must be odd and above one.
    fn new(n: &[u64]) -> Self {
        Self(bignum64::mont_ctx_init(n.len() as u32, n))
    }

    /// A context for a secret `n`, which must be odd with `used`
    /// significant words.
    ///
    /// `mont_ctx_init` reads `n`'s highest nonzero word to set how many
    /// times it loops, so this takes it from `used`, which is public.
    fn new_secret(n: &[u64], used: usize) -> Self {
        let len = n.len() as u32;
        let mut r2 = vec![0; n.len()].into_boxed_slice();
        base::bn_precomp_r2_mod_n_u64(len, 64 * (used as u32 - 1), n, &mut r2);
        Self(Box::new([bn_mont_ctx_u64 {
            len,
            n: n.into(),
            mu: base::mod_inv_uint64(n[0]),
            r2,
        }]))
    }
}

impl Deref for Mont {
    type Target = [bn_mont_ctx_u64];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for Mont {
    fn drop(&mut self) {
        for k in self.0.iter_mut() {
            low::zeroise(&mut k.n);
            low::zeroise(&mut k.r2);
            low::zeroise_value(&mut k.mu);
        }
    }
}

pub(crate) struct RsaComponents<'a> {
    pub(crate) public_modulus: &'a [u8],
    pub(crate) public_exponent: &'a [u8],
    pub(crate) p: &'a [u8],
    pub(crate) q: &'a [u8],
    pub(crate) d: &'a [u8],
    pub(crate) dp: &'a [u8],
    pub(crate) dq: &'a [u8],
    pub(crate) iqmp: &'a [u8],
}

pub(crate) struct RsaComponentsBuffer([u8; Self::LEN]);

impl RsaComponentsBuffer {
    pub(crate) const LEN: usize =
        // public modulus and private exponent
        (MAX_PUBLIC_MODULUS_BYTES + 1) * 2 +
            // public exponent
            4 +
            // private moduli and crt components
            (MAX_PRIVATE_MODULUS_BYTES + 1) * 5;
}

impl Drop for RsaComponentsBuffer {
    fn drop(&mut self) {
        low::zeroise(&mut self.0);
    }
}

impl Default for RsaComponentsBuffer {
    fn default() -> Self {
        Self([0u8; Self::LEN])
    }
}

const MAX_PRIVATE_MODULUS_BITS: usize = 4096;
const MAX_PRIVATE_MODULUS_WORDS: usize = MAX_PRIVATE_MODULUS_BITS / 64;
pub(crate) const MAX_PRIVATE_MODULUS_BYTES: usize = MAX_PRIVATE_MODULUS_BITS / 8;

const MIN_PRIVATE_MODULUS_BITS: usize = 1024;
const MIN_PRIVATE_MODULUS_BYTES: usize = MIN_PRIVATE_MODULUS_BITS / 8;

type SecretRsaPosIntModP = low::SecretPosInt<MAX_PRIVATE_MODULUS_WORDS>;
type SecretRsaPosIntD = low::SecretPosInt<{ MAX_PRIVATE_MODULUS_WORDS * 2 }>;
type RsaPosIntModP = low::PosInt<MAX_PRIVATE_MODULUS_WORDS>;
type RsaPosIntD = low::PosInt<{ MAX_PRIVATE_MODULUS_WORDS * 2 }>;
type RsaPosIntModN = low::PosInt<{ MAX_PRIVATE_MODULUS_WORDS * 2 }>;
