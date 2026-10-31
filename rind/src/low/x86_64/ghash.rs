// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
//
//! GHASH with aws-lc's `gcm_init_avx` and `gcm_ghash_avx`, plus the powers
//! of H that Graviola's AVX-512 by-16 AES-GCM kernel multiplies by.
//!
//! Refs. for the AVX-512 arithmetic:
//! - <https://patchwork.kernel.org/project/linux-crypto/patch/20240527075626.142576-3-ebiggers@kernel.org/>
//! - <https://github.com/google/boringssl/blob/d5440dd2c2c500ac2d3bba4afec47a054b4d99ae/crypto/fipsmodule/aes/asm/aes-gcm-avx512-x86_64.pl>

use core::arch::x86_64::*;
use core::mem;

use super::aws_lc::{self, Htable};
use super::cpu::{HaveAvx512ForAesGcm, HaveMovbe};
use crate::low;

pub(crate) struct GhashTable {
    pub(super) htable: Htable,
    pub(super) bulk: Bulk,
}

/// What runs the bulk of each AES-GCM message, picked from the CPU's
/// features when the key is made.
#[expect(clippy::large_enum_variant)] // boxing it would cost a heap allocation per key
pub(super) enum Bulk {
    /// Graviola's AVX-512 by-16 kernel, with the powers of H it needs.
    Avx512(GhashTableAvx512),
    /// aws-lc's stitched AES-NI and AVX kernel.
    Stitched(HaveMovbe),
    /// Nothing: aws-lc's counter mode and GHASH take every block, as aws-lc
    /// does without `movbe`.
    Separate,
}

impl GhashTable {
    pub(crate) fn new(h: u128) -> Self {
        let mut htable = Htable([[0; 2]; 16]);
        // SAFETY: `htable` is an `Htable`, and the halves of `h` two words.
        // This crate requires the `avx` and `pclmulqdq` cpu features.
        unsafe { aws_lc::gcm_init_avx(&mut htable, &[(h >> 64) as u64, h as u64]) };
        let bulk = match (HaveAvx512ForAesGcm::check(), HaveMovbe::check()) {
            (Some(token), _) => Bulk::Avx512(GhashTableAvx512::new(h, token)),
            (None, Some(token)) => Bulk::Stitched(token),
            (None, None) => Bulk::Separate,
        };
        Self { htable, bulk }
    }

    /// Folds whole blocks of `input` into the GHASH state `xi`.
    pub(super) fn ghash(&self, xi: &mut [u8; 16], input: &[[u8; 16]]) {
        // aws-lc loads the first block before checking the length.
        if input.is_empty() {
            return;
        }
        // SAFETY: `input` is `size_of_val(input)` readable bytes, a multiple
        // of 16. This crate requires the `avx` and `pclmulqdq` cpu features.
        unsafe {
            aws_lc::gcm_ghash_avx(xi, &self.htable, input.as_ptr().cast(), size_of_val(input))
        }
    }
}

impl Drop for GhashTable {
    fn drop(&mut self) {
        low::zeroise_value(self);
    }
}

// SAFETY: GhashTable is POD type
impl low::generic::zeroise::Zeroable for GhashTable {}

pub(crate) struct GhashTableAvx512 {
    /// H, H^2, H^3, H^4, ... H^16
    pub(super) powers: [__m512i; 4],
    pub(super) token: HaveAvx512ForAesGcm,
}

impl GhashTableAvx512 {
    fn new(h: u128, token: HaveAvx512ForAesGcm) -> Self {
        let mut powers = [zero(); 16];

        // SAFETY: this crate requires the `avx` cpu feature
        powers[0] = unsafe { gf128_big_endian(u128_to_m128i(h)) };
        for i in 1..16 {
            // SAFETY: this crate requires the `avx` and `pclmulqdq` cpu features
            powers[i] = unsafe { _mul(powers[i - 1], powers[0]) };
        }

        // SAFETY: avx512f checked by caller
        let powers = unsafe {
            [
                join512(powers[0], powers[1], powers[2], powers[3]),
                join512(powers[4], powers[5], powers[6], powers[7]),
                join512(powers[8], powers[9], powers[10], powers[11]),
                join512(powers[12], powers[13], powers[14], powers[15]),
            ]
        };

        Self { powers, token }
    }
}

pub(crate) struct Ghash<'a> {
    pub(crate) table: &'a GhashTable,
    /// The running hash in GHASH's byte order: aws-lc's `Xi`.
    pub(crate) xi: [u8; 16],
}

impl<'a> Ghash<'a> {
    pub(crate) fn new(table: &'a GhashTable) -> Self {
        Self { table, xi: [0; 16] }
    }

    /// Input `bytes` to the computation.
    ///
    /// `bytes` is zero-padded, if required.
    pub(crate) fn add(&mut self, bytes: &[u8]) {
        let (blocks, tail) = bytes.as_chunks::<16>();
        self.table.ghash(&mut self.xi, blocks);
        if !tail.is_empty() {
            let mut last = [0u8; 16];
            last[..tail.len()].copy_from_slice(tail);
            self.table.ghash(&mut self.xi, &[last]);
        }
    }

    pub(crate) fn into_bytes(self) -> [u8; 16] {
        self.xi
    }
}

macro_rules! mul {
    ($lo:ident, $mi:ident, $hi:ident, $x:ident, $h:expr, $hx:expr) => {
        let tlo = _mm_clmulepi64_si128($x, $h, 0x00);
        $lo = _mm_xor_si128(tlo, $lo);

        let xx = _mm_shuffle_epi32($x, 0b01_00_11_10);
        let xx = _mm_xor_si128(xx, $x);

        let thi = _mm_clmulepi64_si128($x, $h, 0x11);
        $hi = _mm_xor_si128(thi, $hi);

        let tmi = _mm_clmulepi64_si128(xx, $hx, 0x00);
        $mi = _mm_xor_si128(tmi, $mi);
    };
}

macro_rules! reduce {
    ($lo:ident, $mi:ident, $hi:ident) => {{
        let $mi = _mm_xor_si128($mi, $lo);
        let $mi = _mm_xor_si128($mi, $hi);

        let ls = _mm_shuffle_epi32($lo, 0b01_00_11_10);
        let $lo = _mm_clmulepi64_si128(GF128_POLY_HI, $lo, 0x00);
        let $mi = _mm_xor_si128($mi, ls);
        let $mi = _mm_xor_si128($mi, $lo);

        let ms = _mm_shuffle_epi32($mi, 0b01_00_11_10);
        let $mi = _mm_clmulepi64_si128(GF128_POLY_HI, $mi, 0x00);
        let $hi = _mm_xor_si128($hi, ms);
        let $hi = _mm_xor_si128($hi, $mi);
        $hi
    }};
}

#[inline]
#[target_feature(enable = "pclmulqdq,avx")]
fn _mul(a: __m128i, b: __m128i) -> __m128i {
    // SAFETY: intrinsics. see [crate::low::inline_assembly_safety#safety-of-intrinsics] for safety info.
    let (mut lo, mut mi, mut hi) = (zero(), zero(), zero());
    let bx = xor_halves(b);
    mul!(lo, mi, hi, a, b, bx);
    reduce!(lo, mi, hi)
}

#[inline]
#[target_feature(enable = "vpclmulqdq,avx512f,avx512vl")]
pub(crate) fn _mul16(
    table: &GhashTableAvx512,
    x0123: __m512i,
    x4567: __m512i,
    x89ab: __m512i,
    xcdef: __m512i,
) -> __m128i {
    let gfpoly = _mm512_broadcast_i32x4(GF128_POLY_LO);

    let lo0 = _mm512_clmulepi64_epi128(x0123, table.powers[3], 0x00);
    let lo1 = _mm512_clmulepi64_epi128(x4567, table.powers[2], 0x00);
    let lo2 = _mm512_clmulepi64_epi128(x89ab, table.powers[1], 0x00);

    let lo01 = _mm512_xor_epi32(lo0, lo1);
    let lo3 = _mm512_clmulepi64_epi128(xcdef, table.powers[0], 0x00);
    let lo = _mm512_ternarylogic_epi64(lo2, lo3, lo01, TERNARY_XOR);
    let mi0 = _mm512_clmulepi64_epi128(x0123, table.powers[3], 0x01);

    let mi1 = _mm512_clmulepi64_epi128(x4567, table.powers[2], 0x01);
    let mi2 = _mm512_clmulepi64_epi128(x89ab, table.powers[1], 0x01);
    let mi012 = _mm512_ternarylogic_epi32(mi0, mi1, mi2, TERNARY_XOR);
    let mi3 = _mm512_clmulepi64_epi128(xcdef, table.powers[0], 0x01);

    let mi4 = _mm512_clmulepi64_epi128(x0123, table.powers[3], 0x10);
    let mi01234 = _mm512_ternarylogic_epi32(mi012, mi3, mi4, TERNARY_XOR);
    let mi5 = _mm512_clmulepi64_epi128(x4567, table.powers[2], 0x10);
    let mi6 = _mm512_clmulepi64_epi128(x89ab, table.powers[1], 0x10);

    let mi = _mm512_ternarylogic_epi64(mi01234, mi5, mi6, TERNARY_XOR);
    let lo_r = _mm512_clmulepi64_epi128(gfpoly, lo, 0x01);
    let mi7 = _mm512_clmulepi64_epi128(xcdef, table.powers[0], 0x10);
    let mi = _mm512_xor_epi32(mi7, mi);

    let lo_s = _mm512_shuffle_epi32(lo, 0b01_00_11_10);
    let hi0 = _mm512_clmulepi64_epi128(x0123, table.powers[3], 0x11);
    let hi1 = _mm512_clmulepi64_epi128(x4567, table.powers[2], 0x11);
    let hi2 = _mm512_clmulepi64_epi128(x89ab, table.powers[1], 0x11);

    let mi = _mm512_ternarylogic_epi32(lo_r, lo_s, mi, TERNARY_XOR);
    let hi3 = _mm512_clmulepi64_epi128(xcdef, table.powers[0], 0x11);
    let hi012 = _mm512_ternarylogic_epi32(hi0, hi1, hi2, TERNARY_XOR);
    let mi_r = _mm512_clmulepi64_epi128(gfpoly, mi, 0x01);

    let hi = _mm512_xor_epi32(hi012, hi3);
    let mi_s = _mm512_shuffle_epi32(mi, 0b01_00_11_10);
    let r = _mm512_ternarylogic_epi32(mi_r, mi_s, hi, TERNARY_XOR);

    // xor together all terms of `r`
    let a = _mm512_extracti32x4_epi32::<0>(r);
    let b = _mm512_extracti32x4_epi32::<1>(r);
    let c = _mm512_extracti32x4_epi32::<2>(r);
    let d = _mm512_extracti32x4_epi32::<3>(r);
    let ab = _mm_xor_si128(a, b);
    _mm_ternarylogic_epi32(ab, c, d, TERNARY_XOR)
}

#[target_feature(enable = "avx")]
fn gf128_big_endian(h: __m128i) -> __m128i {
    // takes a raw hash subkey, and arranges that it can
    // be used in big endian ordering.
    let t = _mm_shuffle_epi32(h, 0b11_01_00_11);
    let t = _mm_srai_epi32(t, 31);
    let h = _mm_add_epi64(h, h);
    let t = _mm_and_si128(GF128_POLY_CARRY_MASK, t);
    _mm_xor_si128(h, t)
}

#[target_feature(enable = "avx")]
fn xor_halves(h: __m128i) -> __m128i {
    let hx = _mm_shuffle_epi32(h, 0b01_00_11_10);
    _mm_xor_si128(hx, h)
}

#[inline]
fn zero() -> __m128i {
    // SAFETY: this crate requires the `avx` cpu feature
    unsafe { _mm_setzero_si128() }
}

#[inline]
#[target_feature(enable = "avx512f")]
fn join512(a: __m128i, b: __m128i, c: __m128i, d: __m128i) -> __m512i {
    let r = _mm512_inserti32x4(_mm512_setzero_epi32(), d, 0);
    let r = _mm512_inserti32x4(r, c, 1);
    let r = _mm512_inserti32x4(r, b, 2);
    _mm512_inserti32x4(r, a, 3)
}

#[inline]
fn u128_to_m128i(v: u128) -> __m128i {
    // SAFETY: sizeof(u128) == sizeof(__m128i), all bits have same meaning
    unsafe { mem::transmute(v) }
}

/// Constant for vpternlogd which is three-operand XOR.
///
/// Find `xorABC` in Table 5.2, Intel Volume 2C: Instruction Set Reference, V
/// <https://cdrdv2-public.intel.com/825761/326018-sdm-vol-2c.pdf>
const TERNARY_XOR: i32 = 0x96;

/// The high half of the ghash polynomial R, rotated left by one
///
/// R is 0xe100..00u128
///
/// We need this in a __m128i, but only the bottom 64-bits are used.
// SAFETY: sizeof(u128) == sizeof(__m128i), all bits have same meaning
const GF128_POLY_HI: __m128i = unsafe { mem::transmute(0xc2000000_00000000u128) };

/// The same as GF128_POLY_HI, but in the top qword.
// SAFETY: sizeof(u128) == sizeof(__m128i), all bits have same meaning
const GF128_POLY_LO: __m128i =
    unsafe { mem::transmute([0xc2000000_00000000_00000000_00000000u128]) };

/// This is, again, R rotated left by one, but with a 2^64 term
// SAFETY: sizeof(u128) == sizeof(__m128i), all bits have same meaning
const GF128_POLY_CARRY_MASK: __m128i =
    unsafe { mem::transmute(0xc2000000_00000001_00000000_00000001u128) };

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::low::generic::ghash as model;

    #[test]
    fn pairwise() {
        check(0, b"");
        check(0, b"hello");
        check(1, b"");
        check(1, b"hello");
        let k = 0x00112233_44556677_8899aabb_ccddeeffu128;
        check(k, b"hello");
        check(k, b"hello world!");
        check(k, &[b'a'; 32]);
        check(k, &[b'b'; 64]);
        check(k, &[b'c'; 512 + 64 + 32 + 16]);

        let mut pattern = [0; 512 + 64 + 32 + 16];
        for (i, p) in pattern.iter_mut().enumerate() {
            *p = i as u8;
        }
        check(k, &pattern);

        let k = 0xffeeeedd_ffeeeedd_ff0000dd_ff0000ddu128;
        for (i, p) in pattern.iter_mut().enumerate() {
            *p = 0xf0 | (i & 0xf) as u8;
        }
        check(k, &pattern);
    }

    fn check(key: u128, input: &[u8]) {
        println!("check: input={input:02x?}");
        let ta = GhashTable::new(key);
        let tb = model::GhashTable::new(key);
        let mut a = Ghash::new(&ta);
        let mut b = model::Ghash::new(&tb);
        a.add(input);
        b.add(input);

        let fa = a.into_bytes();
        let fb = b.into_bytes();

        if fa != fb {
            panic!("for input: {input:02x?}:\n\n impl  {fa:02x?}\n    !=\nmodel  {fb:02x?}");
        }
    }
}
