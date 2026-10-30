// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! RSA key generation over HACL*'s `Bignum64`.
//!
//! It makes the same decisions as the other backends' `generate.rs`
//! (FIPS186-5 A.1.3 and B.3.1, with the same small-prime sieve and witness
//! draws), so the same random input yields the same key. It runs in constant
//! time in the secret primes, except for the decisions `public` declassifies:
//! whether a candidate is rejected, and Miller-Rabin's control flow on the
//! accepted prime, which the other backends also leak.
//!
//! References to FIPS186-5 are to:
//! <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf>

use core::ops::Range;

use libcrux_hacl_rs::bignum::bignum64;

use super::{MAX_PRIVATE_MODULUS_BYTES, MAX_PRIVATE_MODULUS_WORDS, Mont, RsaPrivateKey};
use crate::Error;
use crate::low::{self, PosInt, ct};
use crate::mid::rng::RandomSource;

/// Supported RSA key sizes for key generation.
///
/// This refers to the public modulus size.
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum KeySize {
    /// Generate a key with a 2048-bit public modulus.
    Rsa2048,
    /// Generate a key with a 3072-bit public modulus.
    Rsa3072,
    /// Generate a key with a 4096-bit public modulus.
    Rsa4096,
    /// Generate a key with a 6144-bit public modulus.
    Rsa6144,
    /// Generate a key with a 8192-bit public modulus.
    Rsa8192,
}

impl KeySize {
    fn public_modulus_size_bits(&self) -> usize {
        match self {
            Self::Rsa2048 => 2048,
            Self::Rsa3072 => 3072,
            Self::Rsa4096 => 4096,
            Self::Rsa6144 => 6144,
            Self::Rsa8192 => 8192,
        }
    }

    /// Every size is a whole number of words.
    fn private_prime_size_words(&self) -> usize {
        self.public_modulus_size_bits() / 128
    }

    fn miller_rabin_rounds(&self) -> usize {
        // refer to Table B.1.
        match self {
            Self::Rsa2048 => 5,
            Self::Rsa3072 => 4,
            Self::Rsa4096 => 4,
            // nb. not included in FIPS186-5.
            Self::Rsa6144 | Self::Rsa8192 => 4,
        }
    }
}

impl TryFrom<usize> for KeySize {
    type Error = Error;

    /// Convert an integer number of bits to a `KeySize`.
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            2048 => Ok(Self::Rsa2048),
            3072 => Ok(Self::Rsa3072),
            4096 => Ok(Self::Rsa4096),
            6144 => Ok(Self::Rsa6144),
            8192 => Ok(Self::Rsa8192),
            _ => Err(Error::OutOfRange),
        }
    }
}

pub(super) fn generate_key(
    size: KeySize,
    candidate_random: &mut dyn RandomSource,
    checks_random: &mut dyn RandomSource,
) -> Result<RsaPrivateKey, Error> {
    let len = size.private_prime_size_words();
    let sieve = Sieve::new();
    let e = Mont::new(&[PUBLIC_EXPONENT.into()]);

    loop {
        let mut p = random_prime(size, &sieve, candidate_random, checks_random)?;
        let mut q = random_prime(size, &sieve, candidate_random, checks_random)?;
        let (p, q) = (&mut p.0[..len], &mut q.0[..len]);

        if public(bignum64::eq_mask(len as u32, p, q)) != 0 {
            // for the set of `RsaSizes` supported here, choosing p == q
            // means `random` is hosed.
            return Err(Error::RngFailed);
        }

        // arrange that q < p, without revealing which was drawn first.
        let swap = bignum64::lt_mask(len as u32, p, q);
        for (p, q) in p.iter_mut().zip(q.iter_mut()) {
            let t = (*p ^ *q) & swap;
            *p ^= t;
            *q ^= t;
        }

        let mut k = Derivation::default();
        if !k.derive(&e, p, q) {
            // e divides phi; because e is prime, that means p or q are
            // 1 mod e.
            //
            // We throw away both primes and start again.
            continue;
        }

        // `new` checks only what the construction fixes (odd, full-length
        // primes of matching widths), so its branches reveal nothing.
        return RsaPrivateKey::new(
            public(PosInt::from_words(p)?),
            public(PosInt::from_words(q)?),
            public(PosInt::from_words(&k.d[..len * 2])?),
            public(PosInt::from_words(&k.dp[..len])?),
            public(PosInt::from_words(&k.dq[..len])?),
            public(PosInt::from_words(&k.iqmp[..len])?),
            public(PosInt::from_words(&k.n[..len * 2])?),
            PUBLIC_EXPONENT,
        );
    }
}

/// We only support F4 for the public exponent.
const PUBLIC_EXPONENT: u32 = 0x10001;

/// The private values derived from the primes, zeroed on drop.
struct Derivation {
    p_1: [u64; MAX_PRIVATE_MODULUS_WORDS],
    q_1: [u64; MAX_PRIVATE_MODULUS_WORDS],
    phi: [u64; MAX_PRIVATE_MODULUS_WORDS * 2],
    p_2: [u64; MAX_PRIVATE_MODULUS_WORDS],
    d: [u64; MAX_PRIVATE_MODULUS_WORDS * 2],
    dp: [u64; MAX_PRIVATE_MODULUS_WORDS],
    dq: [u64; MAX_PRIVATE_MODULUS_WORDS],
    iqmp: [u64; MAX_PRIVATE_MODULUS_WORDS],
    n: [u64; MAX_PRIVATE_MODULUS_WORDS * 2],
}

impl Derivation {
    /// Derives the key from primes `q < p`, returning false if `e`
    /// divides `phi`.
    fn derive(&mut self, e: &Mont, p: &[u64], q: &[u64]) -> bool {
        let len = p.len();
        let w = len as u32;

        // p and q are odd, so subtracting one clears bit 0.
        let (p_1, q_1) = (&mut self.p_1[..len], &mut self.q_1[..len]);
        p_1.copy_from_slice(p);
        p_1[0] ^= 1;
        q_1.copy_from_slice(q);
        q_1[0] ^= 1;
        let phi = &mut self.phi[..len * 2];
        bignum64::mul(w, p_1, q_1, phi);

        // As e is prime, it divides phi exactly when it divides p - 1 or
        // q - 1, so the three inversions succeed or fail together.
        let ok = invert_e(e, phi, &mut self.d[..len * 2])
            & invert_e(e, p_1, &mut self.dp[..len])
            & invert_e(e, q_1, &mut self.dq[..len]);
        if !ok {
            return false;
        }

        // iqmp = q ^ (p - 2) mod p, by Fermat's little theorem since p
        // is prime. HACL* requires the base below the modulus: q < p.
        let p_2 = &mut self.p_2[..len];
        bignum64::sub(w, p, &ONE_TWO[1][..len], p_2);
        let ctx = Mont::new_secret(p, len);
        bignum64::mod_exp_consttime_precomp(&ctx, q, w * 64, p_2, &mut self.iqmp[..len]);

        bignum64::mul(w, p, q, &mut self.n[..len * 2]);
        true
    }
}

impl Default for Derivation {
    fn default() -> Self {
        Self {
            p_1: [0; MAX_PRIVATE_MODULUS_WORDS],
            q_1: [0; MAX_PRIVATE_MODULUS_WORDS],
            phi: [0; MAX_PRIVATE_MODULUS_WORDS * 2],
            p_2: [0; MAX_PRIVATE_MODULUS_WORDS],
            d: [0; MAX_PRIVATE_MODULUS_WORDS * 2],
            dp: [0; MAX_PRIVATE_MODULUS_WORDS],
            dq: [0; MAX_PRIVATE_MODULUS_WORDS],
            iqmp: [0; MAX_PRIVATE_MODULUS_WORDS],
            n: [0; MAX_PRIVATE_MODULUS_WORDS * 2],
        }
    }
}

impl Drop for Derivation {
    fn drop(&mut self) {
        low::zeroise(&mut self.p_1);
        low::zeroise(&mut self.q_1);
        low::zeroise(&mut self.phi);
        low::zeroise(&mut self.p_2);
        low::zeroise(&mut self.d);
        low::zeroise(&mut self.dp);
        low::zeroise(&mut self.dq);
        low::zeroise(&mut self.iqmp);
        low::zeroise(&mut self.n);
    }
}

/// Writes `e ^ -1 mod m` to `out`, or returns false if `e` divides `m`.
///
/// `Bignum64` has no inverse modulo the even `m`, so this inverts `m`
/// modulo the prime `e` instead: with `t = -m ^ -1 mod e`, `e` divides
/// `t * m + 1`, and the quotient `d` has `d * e = t * m + 1 = 1 (mod m)`,
/// with `d < m` because `t < e`.
fn invert_e(e: &Mont, m: &[u64], out: &mut [u64]) -> bool {
    let len = m.len();

    // m mod e, by Horner's rule over its words.
    let mut x = [0u64];
    for word in m.iter().rev() {
        bignum64::mod_precomp(e, &[*word, x[0]], &mut x);
    }
    // Not `eq_mask(1, ..)`: inlined, its one-word comparison became a
    // branch on `x`.
    if public(low::bignum_eq(&x, &[0])) {
        return false;
    }

    // m ^ -1 = m ^ (e - 2) mod e, by Fermat's little theorem.
    let e_2 = u64::from(PUBLIC_EXPONENT) - 2;
    let mut inv = [0u64];
    bignum64::mod_exp_consttime_precomp(e, &x, 17, &[e_2], &mut inv);

    let mut scratch = InvertScratch::default();
    scratch.t[0] = u64::from(PUBLIC_EXPONENT) - inv[0];
    let wide = &mut scratch.wide[..len * 2];
    bignum64::mul(len as u32, m, &scratch.t[..len], wide);

    // The quotient fits `len` words, so only the low `len` words of
    // `t * m + 1` determine it.
    let mut carry = 1;
    for word in wide[..len].iter_mut() {
        let (sum, c) = word.overflowing_add(carry);
        *word = sum;
        carry = u64::from(c);
    }
    divide_exact_e(&wide[..len], out);
    true
}

/// `t` and `t * m`, zeroed on drop.
struct InvertScratch {
    t: [u64; MAX_PRIVATE_MODULUS_WORDS * 2],
    wide: [u64; MAX_PRIVATE_MODULUS_WORDS * 4],
}

impl Default for InvertScratch {
    fn default() -> Self {
        Self {
            t: [0; MAX_PRIVATE_MODULUS_WORDS * 2],
            wide: [0; MAX_PRIVATE_MODULUS_WORDS * 4],
        }
    }
}

impl Drop for InvertScratch {
    fn drop(&mut self) {
        low::zeroise(&mut self.t);
        low::zeroise(&mut self.wide);
    }
}

/// Writes `x / e` to `out`, for an `x` that `e` divides with a quotient
/// that fits `out`.
///
/// This is exact (Hensel) division: the quotient is `x * e ^ -1` modulo
/// `2 ^ (64 * len)`, computed a word at a time, lowest first, carrying the
/// part of each `q * e` above its word into the next (Jebelean, "An
/// algorithm for exact division", 1993; GMP's `mpn_divexact_1`).
fn divide_exact_e(x: &[u64], out: &mut [u64]) {
    const E: u64 = PUBLIC_EXPONENT as u64;
    // Newton's iteration doubles the correct low bits from the three of
    // `e * e = 1 (mod 8)`, so five steps reach 64.
    const E_INV: u64 = {
        let mut inv = E;
        let mut i = 0;
        while i < 5 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(E.wrapping_mul(inv)));
            i += 1;
        }
        assert!(inv.wrapping_mul(E) == 1);
        inv
    };

    let mut borrow = 0u64;
    for (q, x) in out.iter_mut().zip(x) {
        let (s, b) = x.overflowing_sub(borrow);
        *q = s.wrapping_mul(E_INV);
        borrow = ((u128::from(*q) * u128::from(E)) >> 64) as u64 + u64::from(b);
    }
}

/// A secret prime's words, zeroed on drop.
struct Prime([u64; MAX_PRIVATE_MODULUS_WORDS]);

impl Drop for Prime {
    fn drop(&mut self) {
        low::zeroise(&mut self.0);
    }
}

fn random_prime(
    size: KeySize,
    sieve: &Sieve,
    candidate_random: &mut dyn RandomSource,
    checks_random: &mut dyn RandomSource,
) -> Result<Prime, Error> {
    let len = size.private_prime_size_words();
    let mut buffer = [0u8; MAX_PRIVATE_MODULUS_BYTES];
    let mut candidate = Prime([0; MAX_PRIVATE_MODULUS_WORDS]);
    loop {
        candidate_random.fill(&mut buffer[..len * 8])?;

        // set top two bits to ensure the product of two primes, n, is the right size.
        buffer[0] |= 0b1100_0000;

        // set bottom bit: an even number (of given `size`) is never prime
        buffer[len * 8 - 1] |= 0b0000_0001;

        for (word, bytes) in candidate
            .0
            .iter_mut()
            .zip(buffer[..len * 8].rchunks_exact(8))
        {
            *word = u64::from_be_bytes(bytes.try_into().unwrap());
        }
        ct::secret_slice(&candidate.0[..len]);

        if is_prime(&candidate.0[..len], size, sieve, checks_random)? {
            return Ok(candidate);
        }
    }
}

fn is_prime(
    candidate: &[u64],
    size: KeySize,
    sieve: &Sieve,
    rng: &mut dyn RandomSource,
) -> Result<bool, Error> {
    if !sieve.is_coprime(candidate) {
        return Ok(false);
    }

    miller_rabin(candidate, size, rng)
}

fn miller_rabin(w: &[u64], size: KeySize, rng: &mut dyn RandomSource) -> Result<bool, Error> {
    let len = w.len();
    let ctx = Mont::new_secret(w, len);

    // See FIPS186-5 B.3.1:
    // 1. Let a be the largest integer such that 2 ^ a divides w - 1.
    //
    // w is odd, so w - 1 clears bit 0. Reading the bits up to the lowest
    // set one reveals a, which the loop in `check_z` reveals anyway.
    let mut s = MillerRabinScratch::default();
    let w1 = &mut s.w1[..len];
    w1.copy_from_slice(w);
    w1[0] ^= 1;
    let mut a = 1;
    while public((w1[a / 64] >> (a % 64)) & 1) == 0 {
        a += 1;
    }

    // 2. m = (w - 1) / 2 ^ a.
    let (shift_words, shift_bits) = (a / 64, a % 64);
    for (i, m) in s.m[..len].iter_mut().enumerate() {
        let lo = w1.get(i + shift_words).copied().unwrap_or(0);
        let hi = w1.get(i + shift_words + 1).copied().unwrap_or(0);
        *m = match shift_bits {
            0 => lo,
            _ => (lo >> shift_bits) | (hi << (64 - shift_bits)),
        };
    }

    // 3. wlen = len(w).
    //
    // A candidate's top bit is set, so this reveals nothing of it.
    let w_len = len * 64 - public(w[len - 1].leading_zeros()) as usize;

    // 4. For i = 1 to iterations do
    let mut iter = 1..=size.miller_rabin_rounds();
    loop {
        // 4.1. Obtain a string b of wlen bits from a DRBG.
        //      Convert b to an integer using the algorithm in B.2.1.
        //
        // We obtain bytes, and then discard the excess high bits.
        let mut buffer = [0u8; MAX_PRIVATE_MODULUS_BYTES];
        let w_bytes = w_len.div_ceil(8);
        rng.fill(&mut buffer[..w_bytes])?;
        if w_len & 7 != 0 {
            buffer[0] &= (1u8 << (w_len & 7)).saturating_sub(1);
        }
        let b = PosInt::<MAX_PRIVATE_MODULUS_WORDS>::from_bytes(&buffer[..w_bytes])?;
        let b = b.words_at_width(len)?;

        // 4.2. If ((b <= 1) or (b >= w - 1)), then go to step 4.1.
        let suitable = !bignum64::lt_mask(len as u32, b, &ONE_TWO[1][..len])
            & bignum64::lt_mask(len as u32, b, &s.w1[..len]);
        if public(suitable) == 0 {
            continue;
        }

        // Steps 4.3-4.6 inclusive.
        if !s.check_base(&ctx, b, a) {
            return Ok(false);
        }

        // 4.7. Continue
        if iter.next().is_none() {
            // 5. Return PROBABLY PRIME.
            return Ok(true);
        }
    }
}

/// Miller-Rabin's working, zeroed on drop.
struct MillerRabinScratch {
    w1: [u64; MAX_PRIVATE_MODULUS_WORDS],
    m: [u64; MAX_PRIVATE_MODULUS_WORDS],
    z: [u64; MAX_PRIVATE_MODULUS_WORDS],
    wide: [u64; MAX_PRIVATE_MODULUS_WORDS * 2],
}

impl MillerRabinScratch {
    /// Steps 4.3-4.6 for base `b`, returning false for COMPOSITE.
    fn check_base(&mut self, ctx: &Mont, b: &[u64], a: usize) -> bool {
        let len = b.len();
        let (w1, z) = (&self.w1[..len], &mut self.z[..len]);
        let one = &ONE_TWO[0][..len];
        let eq = |z: &[u64], x: &[u64]| public(bignum64::eq_mask(len as u32, z, x)) != 0;

        // 4.3. z = b ^ m mod w.
        bignum64::mod_exp_consttime_precomp(ctx, b, len as u32 * 64, &self.m[..len], z);

        // 4.4. If ((z = 1) or (z = w − 1)), then go to step 4.7.
        if eq(z, one) || eq(z, w1) {
            return true;
        }

        // 4.5. For j = 1 to a − 1 do.
        for _j in 1..a {
            // 4.5.1. z = z ^ 2 mod w.
            let wide = &mut self.wide[..len * 2];
            bignum64::sqr(len as u32, z, wide);
            bignum64::mod_precomp(ctx, wide, z);

            // 4.5.2. If (z = w − 1), then go to step 4.7.
            if eq(z, w1) {
                return true;
            }

            // 4.5.3 If (z = 1), then go to step 4.6.
            if eq(z, one) {
                return false;
            }
        }

        // 4.6. Return COMPOSITE.
        false
    }
}

impl Default for MillerRabinScratch {
    fn default() -> Self {
        Self {
            w1: [0; MAX_PRIVATE_MODULUS_WORDS],
            m: [0; MAX_PRIVATE_MODULUS_WORDS],
            z: [0; MAX_PRIVATE_MODULUS_WORDS],
            wide: [0; MAX_PRIVATE_MODULUS_WORDS * 2],
        }
    }
}

impl Drop for MillerRabinScratch {
    fn drop(&mut self) {
        low::zeroise(&mut self.w1);
        low::zeroise(&mut self.m);
        low::zeroise(&mut self.z);
        low::zeroise(&mut self.wide);
    }
}

/// Trial division by the odd primes below 743, whose product fits in 1024
/// bits, our smallest prime.
///
/// The other backends check that a candidate is coprime to that product
/// with `bignum_coprime`; `Bignum64` has no GCD, so this reduces the
/// candidate modulo word-sized products of those primes instead, then
/// tests each prime's divisibility of the remainder.
struct Sieve {
    /// A context for each product, with the range of `SMALL_PRIMES` in it.
    products: Vec<(Mont, Range<usize>)>,
}

impl Sieve {
    fn new() -> Self {
        let mut products = Vec::new();
        let mut start = 0;
        while start < SMALL_PRIMES.len() {
            let mut product = 1u64;
            let mut end = start;
            while let Some(next) = SMALL_PRIMES
                .get(end)
                .and_then(|prime| product.checked_mul(*prime))
            {
                product = next;
                end += 1;
            }
            products.push((Mont::new(&[product]), start..end));
            start = end;
        }
        Self { products }
    }

    /// Whether `candidate` has no factor in `SMALL_PRIMES`.
    fn is_coprime(&self, candidate: &[u64]) -> bool {
        for (ctx, primes) in &self.products {
            // candidate mod product, by Horner's rule over its words.
            let mut r = [0u64];
            for word in candidate.iter().rev() {
                bignum64::mod_precomp(ctx, &[*word, r[0]], &mut r);
            }

            // For odd s, s divides r exactly when r * s ^ -1 mod 2 ^ 64 is
            // at most (2 ^ 64 - 1) / s (Granlund and Montgomery, "Division
            // by invariant integers using multiplication", 1994, section 9).
            //
            // Each mask passes through `black_box`: inlined, `lt_mask`'s
            // one-word comparison became a branch on the remainder.
            let mut divisible = 0;
            for (inv, limit) in SMALL_PRIME_DIVISORS[primes.clone()].iter() {
                let (_, above) = limit.overflowing_sub(r[0].wrapping_mul(*inv));
                divisible |= core::hint::black_box(u64::from(above).wrapping_sub(1));
            }
            if public(divisible) != 0 {
                return false;
            }
        }
        true
    }
}

/// The odd primes below 743: the other backends' `PRODUCT_OF_SMALL_PRIMES`.
const SMALL_PRIMES: [u64; 130] = {
    let mut primes = [0; 130];
    let (mut found, mut n) = (0, 3);
    while n < 743 {
        let mut d = 3;
        while d * d <= n && n % d != 0 {
            d += 2;
        }
        if d * d > n {
            primes[found] = n;
            found += 1;
        }
        n += 2;
    }
    assert!(found == primes.len());
    primes
};

/// For each of `SMALL_PRIMES`, its inverse modulo `2 ^ 64` and the largest
/// quotient `(2 ^ 64 - 1) / s`.
const SMALL_PRIME_DIVISORS: [(u64, u64); 130] = {
    let mut divisors = [(0, 0); 130];
    let mut i = 0;
    while i < divisors.len() {
        let s = SMALL_PRIMES[i];
        // As in `divide_exact_e`: Newton's iteration from `s * s = 1 (mod 8)`.
        let mut inv = s;
        let mut j = 0;
        while j < 5 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(s.wrapping_mul(inv)));
            j += 1;
        }
        assert!(inv.wrapping_mul(s) == 1);
        divisors[i] = (inv, u64::MAX / s);
        i += 1;
    }
    divisors
};

/// One and two, at every width.
const ONE_TWO: [[u64; MAX_PRIVATE_MODULUS_WORDS]; 2] = {
    let mut r = [[0; MAX_PRIVATE_MODULUS_WORDS]; 2];
    r[0][0] = 1;
    r[1][0] = 2;
    r
};

/// Declassifies a decision this module reveals by branching on it.
fn public<T>(v: T) -> T {
    ct::into_public(v)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::high::hash::Sha256;
    use crate::high::hmac_drbg::HmacDrbg;
    use crate::mid::rng::{ChainRandomSource, SliceRandomSource, SystemRandom};

    fn read_hex(data: &str) -> Vec<u8> {
        data.split_whitespace()
            .flat_map(|line| {
                (0..line.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
            })
            .collect()
    }

    fn check_primes(data: &str, expected: bool) {
        let sieve = Sieve::new();
        for line in data.lines().filter(|line| !line.starts_with("#")) {
            let candidate =
                PosInt::<MAX_PRIVATE_MODULUS_WORDS>::from_bytes(&read_hex(line)).unwrap();
            assert_eq!(
                is_prime(
                    candidate.as_words(),
                    KeySize::Rsa2048,
                    &sieve,
                    &mut HmacDrbg::<Sha256>::new(b"", b"", b"")
                ),
                Ok(expected),
                "{line}"
            );
        }
    }

    #[test]
    fn valid_primes() {
        check_primes(include_str!("../../../testdata/valid-primes.txt"), true);
    }

    #[test]
    fn invalid_primes() {
        check_primes(include_str!("../../../testdata/invalid-primes.txt"), false);
    }

    #[test]
    fn sieve_matches_remainder() {
        let sieve = Sieve::new();
        assert_eq!(sieve.products.last().unwrap().1.end, SMALL_PRIMES.len());

        // Each small prime, and its multiples either side of the top of two
        // words, where `r * s ^ -1` is closest to the limit.
        for s in SMALL_PRIMES.map(u128::from) {
            let top = u128::MAX / s * s;
            for x in [s, s * 743, top, top - 1, top - s + 1, s << 64] {
                let coprime = SMALL_PRIMES.iter().all(|s| x % u128::from(*s) != 0);
                let words = [x as u64, (x >> 64) as u64];
                assert_eq!(sieve.is_coprime(&words), coprime, "{x:#x}");
            }
        }
    }

    #[test]
    fn inverts_e() {
        let e = Mont::new(&[PUBLIC_EXPONENT.into()]);
        // Odd and even moduli, across the word boundary.
        for m in [
            [3u64, 0],
            [6, 0],
            [u64::MAX - 3, 1],
            [0x1234_5678_9abc_def0, 0xf_ffff_ffff],
        ] {
            let mut d = [0u64; 2];
            assert!(invert_e(&e, &m, &mut d));
            let (m, d) = (
                (u128::from(m[1]) << 64) | u128::from(m[0]),
                (u128::from(d[1]) << 64) | u128::from(d[0]),
            );
            assert!(d < m);
            assert_eq!(d * u128::from(PUBLIC_EXPONENT) % m, 1);
        }
        assert!(!invert_e(&e, &[0x10001 * 7, 0], &mut [0; 2]));
    }

    #[test]
    fn hosed_rng() {
        // candidate rng
        assert_eq!(
            generate_key(
                KeySize::Rsa2048,
                &mut SliceRandomSource(&[]),
                &mut SystemRandom
            )
            .err(),
            Some(Error::RngFailed)
        );
        // MR base rng
        assert_eq!(
            generate_key(
                KeySize::Rsa2048,
                &mut SystemRandom,
                &mut SliceRandomSource(&[]),
            )
            .err(),
            Some(Error::RngFailed)
        );
    }

    #[test]
    fn p_q_equal() {
        // get one prime from this test vector and duplicate it.
        let mut bytes = read_hex(include_str!(
            "../../../testdata/rsa.phi-not-coprime-e.2048.txt"
        ));
        assert_eq!(bytes.len(), 256);
        bytes.drain(128..);
        bytes.extend_from_within(..);

        assert_eq!(
            generate_key(
                KeySize::Rsa2048,
                &mut SliceRandomSource(&bytes),
                &mut SystemRandom
            )
            .err(),
            Some(Error::RngFailed),
        );
    }

    #[test]
    fn phi_not_coprime_e() {
        let bytes = read_hex(include_str!(
            "../../../testdata/rsa.phi-not-coprime-e.2048.txt"
        ));

        let mut fixed_source = SliceRandomSource(&bytes);
        let mut retry_source = SystemRandom;
        let mut candidate_source = ChainRandomSource::First(&mut fixed_source, &mut retry_source);
        generate_key(KeySize::Rsa2048, &mut candidate_source, &mut SystemRandom).unwrap();
    }
}
