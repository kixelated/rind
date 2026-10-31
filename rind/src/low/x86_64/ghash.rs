// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
//
//! Refs.
//! - <https://www.intel.com/content/dam/www/public/us/en/documents/software-support/enabling-high-performance-gcm.pdf>
//! - <https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf>
//! - <https://patchwork.kernel.org/project/linux-crypto/patch/20240527075626.142576-3-ebiggers@kernel.org/>
//! - <https://github.com/google/boringssl/blob/d5440dd2c2c500ac2d3bba4afec47a054b4d99ae/crypto/fipsmodule/aes/asm/aes-gcm-avx512-x86_64.pl>
//!
//! The latter two especially, as we're using the arithmetic from those.

use core::arch::x86_64::*;
use core::mem;

use super::aes_gcm_vaes::VaesKernel;
use super::cpu::{HaveAvx512ForAesGcm, HaveVaesAvx2ForAesGcm};
use crate::low;

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

#[expect(clippy::large_enum_variant)]
pub(crate) enum GhashTable {
    Avx(GhashTableAvx),
    /// VAES without AVX-512: the AVX path for short messages, and
    /// BoringSSL's 256-bit kernel for long ones.
    VaesAvx2(GhashTableAvx, VaesKernel),
    Avx512(GhashTableAvx512),
}

impl GhashTable {
    pub(crate) fn new(h: u128) -> Self {
        if let Some(token) = HaveAvx512ForAesGcm::check() {
            return Self::Avx512(GhashTableAvx512::new(h, token));
        }
        if let Some(token) = HaveVaesAvx2ForAesGcm::check() {
            return Self::VaesAvx2(GhashTableAvx::new(h), VaesKernel::avx2(h, token));
        }

        Self::Avx(GhashTableAvx::new(h))
    }

    pub(crate) fn avx(&self) -> &GhashTableAvx {
        match self {
            Self::Avx(table) | Self::VaesAvx2(table, _) => table,
            Self::Avx512(table) => &table.avx,
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

pub(crate) struct GhashTableAvx {
    /// H, H^2, H^3, H^4, ... H^8
    powers: [__m128i; 8],

    /// `powers_xor[i]` is `powers[i].lo64 ^ powers[i].hi64`
    ///
    /// This can be used directly in the middle Karatsuba term.
    powers_xor: [__m128i; 8],
}

impl GhashTableAvx {
    pub(crate) fn new(h: u128) -> Self {
        let mut powers = [zero(); 8];
        let mut powers_xor = powers;
        let h = u128_to_m128i(h);

        // SAFETY: this crate requires the `avx` cpu feature
        let h = unsafe { gf128_big_endian(h) };
        powers[0] = h;

        for i in 1..8 {
            // SAFETY: this crate requires the `avx` and `pclmulqdq` cpu features
            powers[i] = unsafe { _mul(powers[i - 1], h) };
        }

        for i in 0..8 {
            // SAFETY: this crate requires the `avx` cpu feature
            powers_xor[i] = unsafe { xor_halves(powers[i]) };
        }

        Self { powers, powers_xor }
    }

    fn add(&self, bytes: &[u8], mut current: __m128i) -> __m128i {
        let (eight_blocks, remainder) = bytes.as_chunks::<128>();

        for chunk8 in eight_blocks {
            let u1 = u128::from_be_bytes(chunk8[0..16].try_into().unwrap());
            let u2 = u128::from_be_bytes(chunk8[16..32].try_into().unwrap());
            let u3 = u128::from_be_bytes(chunk8[32..48].try_into().unwrap());
            let u4 = u128::from_be_bytes(chunk8[48..64].try_into().unwrap());
            let u5 = u128::from_be_bytes(chunk8[64..80].try_into().unwrap());
            let u6 = u128::from_be_bytes(chunk8[80..96].try_into().unwrap());
            let u7 = u128::from_be_bytes(chunk8[96..112].try_into().unwrap());
            let u8 = u128::from_be_bytes(chunk8[112..128].try_into().unwrap());

            let b1 = u128_to_m128i(u1);
            let b2 = u128_to_m128i(u2);
            let b3 = u128_to_m128i(u3);
            let b4 = u128_to_m128i(u4);
            let b5 = u128_to_m128i(u5);
            let b6 = u128_to_m128i(u6);
            let b7 = u128_to_m128i(u7);
            let b8 = u128_to_m128i(u8);

            // SAFETY: this crate requires the `avx` and `pclmulqdq` cpu features
            unsafe {
                let b1 = _mm_xor_si128(current, b1);
                current = _mul8(self, b1, b2, b3, b4, b5, b6, b7, b8);
            }
        }

        // SAFETY: this crate requires the `avx` and `pclmulqdq` cpu features
        unsafe { self.add_tail(remainder, current) }
    }

    /// Hashes the fewer than eight blocks after `add`'s chunks, zero-padding
    /// the last: block `i` of `n` is multiplied by H^(n-i), so the sum needs
    /// one reduction rather than one per block.
    #[target_feature(enable = "pclmulqdq,avx")]
    fn add_tail(&self, bytes: &[u8], current: __m128i) -> __m128i {
        if bytes.is_empty() {
            return current;
        }

        let (blocks, partial) = bytes.as_chunks::<16>();
        let mut powers = self
            .powers
            .iter()
            .zip(&self.powers_xor)
            .take(bytes.len().div_ceil(16))
            .rev();

        let (mut lo, mut mi, mut hi) = (zero(), zero(), zero());
        let mut x = current;
        for (block, (h, hx)) in blocks.iter().zip(&mut powers) {
            let b = _mm_xor_si128(x, u128_to_m128i(u128::from_be_bytes(*block)));
            mul!(lo, mi, hi, b, *h, *hx);
            x = zero();
        }
        // Only a partial block pays for the copy that pads it.
        if let Some((h, hx)) = powers.next() {
            let mut last = [0u8; 16];
            last[..partial.len()].copy_from_slice(partial);
            let b = _mm_xor_si128(x, u128_to_m128i(u128::from_be_bytes(last)));
            mul!(lo, mi, hi, b, *h, *hx);
        }
        reduce!(lo, mi, hi)
    }
}

pub(crate) struct GhashTableAvx512 {
    /// H^16, H^15, ... H^1: descending, so a tail of `n` blocks multiplies
    /// by the last `n`
    powers: [__m512i; 4],
    avx: GhashTableAvx,
    /// BoringSSL's 512-bit kernel, for long messages.
    pub(crate) vaes: VaesKernel,
    pub(crate) token: HaveAvx512ForAesGcm,
}

impl GhashTableAvx512 {
    pub(crate) fn new(h: u128, token: HaveAvx512ForAesGcm) -> Self {
        // This builds on the AVX version, which is perhaps not the most
        // efficient option.
        let avx = GhashTableAvx::new(h);

        let mut powers = [zero(); 16];

        powers[..8].copy_from_slice(&avx.powers);

        for i in 8..16 {
            // SAFETY: necessary features mandated by crate
            powers[i] = unsafe { _mul(powers[i - 1], powers[0]) };
        }

        // SAFETY: avx512f checked by caller
        let powers = unsafe {
            [
                join512(powers[12], powers[13], powers[14], powers[15]),
                join512(powers[8], powers[9], powers[10], powers[11]),
                join512(powers[4], powers[5], powers[6], powers[7]),
                join512(powers[0], powers[1], powers[2], powers[3]),
            ]
        };

        Self {
            powers,
            avx,
            vaes: VaesKernel::avx512(h, token),
            token,
        }
    }

    #[target_feature(enable = "vpclmulqdq,avx512bw,avx512f,avx512vl")]
    fn add(&self, bytes: &[u8], mut current: __m128i) -> __m128i {
        let bswap_mask = _mm512_broadcast_i32x4(BYTESWAP);

        let (by_16_blocks, remainder) = bytes.as_chunks::<256>();
        for chunk16 in by_16_blocks {
            // SAFETY: `chunk16` is 256 bytes and readable, via `chunks_exact`
            let (m0123, m4567, m89ab, mcdef) = unsafe {
                (
                    _mm512_loadu_epi8(chunk16.as_ptr().add(0).cast()),
                    _mm512_loadu_epi8(chunk16.as_ptr().add(64).cast()),
                    _mm512_loadu_epi8(chunk16.as_ptr().add(128).cast()),
                    _mm512_loadu_epi8(chunk16.as_ptr().add(192).cast()),
                )
            };

            let m0123 = _mm512_shuffle_epi8(m0123, bswap_mask);
            let m4567 = _mm512_shuffle_epi8(m4567, bswap_mask);
            let m89ab = _mm512_shuffle_epi8(m89ab, bswap_mask);
            let mcdef = _mm512_shuffle_epi8(mcdef, bswap_mask);

            let c0___ = _mm512_inserti32x4::<0>(_mm512_setzero_si512(), current);
            let m0123 = _mm512_xor_epi64(m0123, c0___);

            current = _mul16(self, m0123, m4567, m89ab, mcdef);
        }

        // A short input, such as AAD or the length block, has too few blocks
        // to fill vectors, so it is quicker to hash it by the AVX path.
        self.avx.add(remainder, current)
    }
}

pub(crate) struct Ghash<'a> {
    pub(crate) table: &'a GhashTable,
    pub(crate) current: __m128i,
}

impl<'a> Ghash<'a> {
    pub(crate) fn new(table: &'a GhashTable) -> Self {
        Self {
            table,
            current: zero(),
        }
    }

    /// Input `bytes` to the computation.
    ///
    /// `bytes` is zero-padded, if required.
    pub(crate) fn add(&mut self, bytes: &[u8]) {
        self.current = match self.table {
            GhashTable::Avx(avx) | GhashTable::VaesAvx2(avx, _) => avx.add(bytes, self.current),
            // SAFETY: avx512.token proves features were dynamically checked
            GhashTable::Avx512(avx512) => unsafe { avx512.add(bytes, self.current) },
        };
    }

    pub(crate) fn into_bytes(self) -> [u8; 16] {
        self.xi()
    }

    /// The state in GCM's byte order, as BoringSSL's `Xi`.
    pub(crate) fn xi(&self) -> [u8; 16] {
        // SAFETY: this crate requires the `ssse3` cpu feature
        m128i_to_u128(unsafe { byteswap(self.current) }).to_le_bytes()
    }

    /// Sets the state from GCM's byte order, as BoringSSL's `Xi`.
    pub(crate) fn set_xi(&mut self, xi: [u8; 16]) {
        // SAFETY: this crate requires the `ssse3` cpu feature
        self.current = unsafe { byteswap(u128_to_m128i(u128::from_le_bytes(xi))) };
    }
}

#[target_feature(enable = "ssse3")]
fn byteswap(x: __m128i) -> __m128i {
    _mm_shuffle_epi8(x, BYTESWAP)
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
#[target_feature(enable = "pclmulqdq,avx")]
pub(crate) fn _mul8(
    table: &GhashTableAvx,
    x1: __m128i,
    x2: __m128i,
    x3: __m128i,
    x4: __m128i,
    x5: __m128i,
    x6: __m128i,
    x7: __m128i,
    x8: __m128i,
) -> __m128i {
    let (mut lo, mut mi, mut hi) = (zero(), zero(), zero());
    mul!(lo, mi, hi, x1, table.powers[7], table.powers_xor[7]);
    mul!(lo, mi, hi, x2, table.powers[6], table.powers_xor[6]);
    mul!(lo, mi, hi, x3, table.powers[5], table.powers_xor[5]);
    mul!(lo, mi, hi, x4, table.powers[4], table.powers_xor[4]);
    mul!(lo, mi, hi, x5, table.powers[3], table.powers_xor[3]);
    mul!(lo, mi, hi, x6, table.powers[2], table.powers_xor[2]);
    mul!(lo, mi, hi, x7, table.powers[1], table.powers_xor[1]);
    mul!(lo, mi, hi, x8, table.powers[0], table.powers_xor[0]);
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

    let lo0 = _mm512_clmulepi64_epi128(x0123, table.powers[0], 0x00);
    let lo1 = _mm512_clmulepi64_epi128(x4567, table.powers[1], 0x00);
    let lo2 = _mm512_clmulepi64_epi128(x89ab, table.powers[2], 0x00);

    let lo01 = _mm512_xor_epi32(lo0, lo1);
    let lo3 = _mm512_clmulepi64_epi128(xcdef, table.powers[3], 0x00);
    let lo = _mm512_ternarylogic_epi64(lo2, lo3, lo01, TERNARY_XOR);
    let mi0 = _mm512_clmulepi64_epi128(x0123, table.powers[0], 0x01);

    let mi1 = _mm512_clmulepi64_epi128(x4567, table.powers[1], 0x01);
    let mi2 = _mm512_clmulepi64_epi128(x89ab, table.powers[2], 0x01);
    let mi012 = _mm512_ternarylogic_epi32(mi0, mi1, mi2, TERNARY_XOR);
    let mi3 = _mm512_clmulepi64_epi128(xcdef, table.powers[3], 0x01);

    let mi4 = _mm512_clmulepi64_epi128(x0123, table.powers[0], 0x10);
    let mi01234 = _mm512_ternarylogic_epi32(mi012, mi3, mi4, TERNARY_XOR);
    let mi5 = _mm512_clmulepi64_epi128(x4567, table.powers[1], 0x10);
    let mi6 = _mm512_clmulepi64_epi128(x89ab, table.powers[2], 0x10);

    let mi = _mm512_ternarylogic_epi64(mi01234, mi5, mi6, TERNARY_XOR);
    let lo_r = _mm512_clmulepi64_epi128(gfpoly, lo, 0x01);
    let mi7 = _mm512_clmulepi64_epi128(xcdef, table.powers[3], 0x10);
    let mi = _mm512_xor_epi32(mi7, mi);

    let lo_s = _mm512_shuffle_epi32(lo, 0b01_00_11_10);
    let hi0 = _mm512_clmulepi64_epi128(x0123, table.powers[0], 0x11);
    let hi1 = _mm512_clmulepi64_epi128(x4567, table.powers[1], 0x11);
    let hi2 = _mm512_clmulepi64_epi128(x89ab, table.powers[2], 0x11);

    let mi = _mm512_ternarylogic_epi32(lo_r, lo_s, mi, TERNARY_XOR);
    let hi3 = _mm512_clmulepi64_epi128(xcdef, table.powers[3], 0x11);
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

/// Hashes a tail of `len` bytes, under 256, into `current`.
///
/// `x` holds the tail's blocks byte-reversed and zero-padded, so the vectors
/// past it are zero. Block `i` of `n` is multiplied by H^(n-i), so the sum
/// needs one reduction rather than one per block.
#[inline]
#[target_feature(enable = "vpclmulqdq,avx512f,avx512vl")]
pub(crate) fn _mul_tail(
    table: &GhashTableAvx512,
    current: __m128i,
    x: [__m512i; 4],
    len: usize,
) -> __m128i {
    let n = len.div_ceil(16);
    if n == 0 {
        return current;
    }

    // `table.powers` descends to H^1, so H^n is `n` blocks before its end.
    let powers = table.powers.as_ptr().cast::<__m128i>();
    let (mut lo, mut mi, mut hi) = (
        _mm512_setzero_si512(),
        _mm512_setzero_si512(),
        _mm512_setzero_si512(),
    );
    for (j, x) in x.into_iter().enumerate().take(n.div_ceil(4)) {
        let x = match j {
            0 => _mm512_xor_epi64(x, _mm512_inserti32x4::<0>(_mm512_setzero_si512(), current)),
            _ => x,
        };
        // Two quadwords per block, for up to four blocks left from here on.
        let mask = u8::MAX >> (8 - 2 * (n - 4 * j).min(4));
        // SAFETY: the vector starts at H^(n-4j), within `table.powers`, and
        // the mask stops it at H^1, the last; masked-off lanes are not read.
        let h = unsafe { _mm512_maskz_loadu_epi64(mask, powers.add(16 - n + 4 * j).cast()) };
        lo = _mm512_xor_epi32(lo, _mm512_clmulepi64_epi128(x, h, 0x00));
        mi = _mm512_ternarylogic_epi32(
            mi,
            _mm512_clmulepi64_epi128(x, h, 0x01),
            _mm512_clmulepi64_epi128(x, h, 0x10),
            TERNARY_XOR,
        );
        hi = _mm512_xor_epi32(hi, _mm512_clmulepi64_epi128(x, h, 0x11));
    }

    let gfpoly = _mm512_broadcast_i32x4(GF128_POLY_LO);
    let lo_r = _mm512_clmulepi64_epi128(gfpoly, lo, 0x01);
    let lo_s = _mm512_shuffle_epi32(lo, 0b01_00_11_10);
    let mi = _mm512_ternarylogic_epi32(lo_r, lo_s, mi, TERNARY_XOR);
    let mi_r = _mm512_clmulepi64_epi128(gfpoly, mi, 0x01);
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

#[inline]
fn m128i_to_u128(v: __m128i) -> u128 {
    // SAFETY: sizeof(u128) == sizeof(__m128i), all bits have same meaning
    unsafe { mem::transmute(v) }
}

// SAFETY: sizeof(u128) == sizeof(__m128i), all bits have same meaning
const BYTESWAP: __m128i = unsafe { mem::transmute(0x00010203_04050607_08090a0b_0c0d0e0fu128) };

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
