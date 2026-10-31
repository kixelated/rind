// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
//
//! AES-GCM, composed as aws-lc's `CRYPTO_gcm128_encrypt_ctr32` does on
//! x86_64: aws-lc's stitched AES-NI and AVX kernel for the bulk, then its
//! counter mode and GHASH for the remaining blocks. Where the CPU has
//! AVX-512 with VAES, Graviola's by-16 kernel runs the bulk instead.

use core::arch::x86_64::*;
use core::mem;

use super::aes::AesKey;
use super::aws_lc;
use super::ghash::{self, Bulk, Ghash, GhashTableAvx512};

pub(crate) fn encrypt(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    initial_counter: &[u8; 16],
    aad: &[u8],
    cipher_inout: &mut [u8],
) {
    cipher::<true>(key, ghash, initial_counter, aad, cipher_inout)
}

pub(crate) fn decrypt(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    initial_counter: &[u8; 16],
    aad: &[u8],
    cipher_inout: &mut [u8],
) {
    cipher::<false>(key, ghash, initial_counter, aad, cipher_inout)
}

// AES-GCM encrypt (if `ENC` is `true`) or decrypt.
fn cipher<const ENC: bool>(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    initial_counter: &[u8; 16],
    aad: &[u8],
    cipher_inout: &mut [u8],
) {
    ghash.add(aad);

    let mut ivec = *initial_counter;
    add_ctr32(&mut ivec, 1);

    let table = ghash.table;
    let bulk = match &table.bulk {
        // SAFETY: this crate requires the `aes`, `ssse3`, `pclmulqdq`, `avx`
        // and `avx2` cpu features; `token` proves the rest were checked.
        Bulk::Avx512(avx512) => unsafe {
            by16::<ENC>(
                key,
                avx512,
                &mut ghash.xi,
                &mut ivec,
                cipher_inout,
                avx512.token,
            )
        },
        Bulk::Stitched(_) => {
            let p = cipher_inout.as_mut_ptr();
            let len = cipher_inout.len();
            let (key, htable, xi) = (key as *const AesKey, &table.htable, &mut ghash.xi);
            // SAFETY: `p` is `len` readable and writable bytes, which aws-lc
            // allows to be the input and output both. It reads `key` as its
            // `AES_KEY` and `htable` as `gcm_init_avx` wrote it, and updates
            // `ivec` and `xi`. This crate requires the `aes`, `pclmulqdq`
            // and `avx` cpu features, and the token proves `movbe`.
            unsafe {
                match ENC {
                    true => aws_lc::aesni_gcm_encrypt(p, p, len, key, &mut ivec, htable, xi),
                    false => aws_lc::aesni_gcm_decrypt(p, p, len, key, &mut ivec, htable, xi),
                }
            }
        }
        Bulk::Separate => 0,
    };

    let (blocks, tail) = cipher_inout[bulk..].as_chunks_mut::<16>();
    if !ENC {
        table.ghash(&mut ghash.xi, blocks);
    }
    if !blocks.is_empty() {
        // SAFETY: `blocks` is `blocks.len()` readable and writable blocks,
        // which aws-lc allows to alias. This crate requires the `aes` cpu
        // feature.
        unsafe {
            aws_lc::aes_hw_ctr32_encrypt_blocks(
                blocks.as_ptr().cast(),
                blocks.as_mut_ptr().cast(),
                blocks.len(),
                key,
                &ivec,
            )
        };
        add_ctr32(&mut ivec, blocks.len());
    }
    if ENC {
        table.ghash(&mut ghash.xi, blocks);
    }

    if !tail.is_empty() {
        if !ENC {
            ghash.add(tail);
        }
        key.encrypt_block(&mut ivec);
        for (c, k) in tail.iter_mut().zip(ivec) {
            *c ^= k;
        }
        if ENC {
            ghash.add(tail);
        }
    }
}

/// Adds `n` to the big-endian 32-bit counter in the last four bytes of `block`.
///
/// `check_gcm_lengths` keeps a message's counters from wrapping.
fn add_ctr32(block: &mut [u8; 16], n: usize) {
    let (_, ctr) = block.split_last_chunk_mut::<4>().unwrap();
    *ctr = u32::from_be_bytes(*ctr)
        .wrapping_add(n as u32)
        .to_be_bytes();
}

/// Encrypts or decrypts the whole 256-byte chunks of `cipher_inout`, and
/// returns how many bytes that was.
#[target_feature(
    enable = "aes,avx,avx2,avx512bw,avx512f,avx512vl,sse3,ssse3,pclmulqdq,vaes,vpclmulqdq"
)]
fn by16<const ENC: bool>(
    key: &AesKey,
    table: &GhashTableAvx512,
    xi: &mut [u8; 16],
    ivec: &mut [u8; 16],
    cipher_inout: &mut [u8],
    _feature_token: super::cpu::HaveAvx512ForAesGcm,
) -> usize {
    let round_keys = key.round_keys_512();
    let (rk_first, rks, rk_last) = round_keys.split();

    let mut counter = Counter512::new(ivec);
    // SAFETY: `xi` is 16 readable bytes
    let mut current = _mm_shuffle_epi8(unsafe { _mm_loadu_si128(xi.as_ptr().cast()) }, BYTESWAP);
    let (by16_iter, _) = cipher_inout.as_chunks_mut::<256>();

    for blocks in by16_iter.iter_mut() {
        // prefetch to avoid any stall later
        super::cpu::prefetch(blocks, 256);

        let c0123 = counter.next4();
        let c4567 = counter.next4();
        let c89ab = counter.next4();
        let ccdef = counter.next4();

        let mut c0123 = _mm512_xor_epi32(c0123, rk_first);
        let mut c4567 = _mm512_xor_epi32(c4567, rk_first);
        let mut c89ab = _mm512_xor_epi32(c89ab, rk_first);
        let mut ccdef = _mm512_xor_epi32(ccdef, rk_first);

        for rk in rks {
            c0123 = _mm512_aesenc_epi128(c0123, *rk);
            c4567 = _mm512_aesenc_epi128(c4567, *rk);
            c89ab = _mm512_aesenc_epi128(c89ab, *rk);
            ccdef = _mm512_aesenc_epi128(ccdef, *rk);
        }

        let c0123 = _mm512_aesenclast_epi128(c0123, rk_last);
        let c4567 = _mm512_aesenclast_epi128(c4567, rk_last);
        let c89ab = _mm512_aesenclast_epi128(c89ab, rk_last);
        let ccdef = _mm512_aesenclast_epi128(ccdef, rk_last);

        // SAFETY: `blocks` is 256 bytes due to `as_chunks_mut`
        let (p0123, p4567, p89ab, pcdef) = unsafe {
            (
                _mm512_loadu_si512(blocks.as_ptr().add(0).cast()),
                _mm512_loadu_si512(blocks.as_ptr().add(64).cast()),
                _mm512_loadu_si512(blocks.as_ptr().add(128).cast()),
                _mm512_loadu_si512(blocks.as_ptr().add(192).cast()),
            )
        };

        let c0123 = _mm512_xor_epi32(c0123, p0123);
        let c4567 = _mm512_xor_epi32(c4567, p4567);
        let c89ab = _mm512_xor_epi32(c89ab, p89ab);
        let ccdef = _mm512_xor_epi32(ccdef, pcdef);

        // SAFETY: `blocks` is 256 bytes and writable due to `as_chunks_mut`
        unsafe {
            _mm512_storeu_si512(blocks.as_mut_ptr().add(0).cast(), c0123);
            _mm512_storeu_si512(blocks.as_mut_ptr().add(64).cast(), c4567);
            _mm512_storeu_si512(blocks.as_mut_ptr().add(128).cast(), c89ab);
            _mm512_storeu_si512(blocks.as_mut_ptr().add(192).cast(), ccdef);
        }

        let (a0123, a4567, a89ab, acdef) = if ENC {
            (c0123, c4567, c89ab, ccdef)
        } else {
            (p0123, p4567, p89ab, pcdef)
        };

        let a0123 = _mm512_shuffle_epi8(a0123, BYTESWAP_512);
        let a4567 = _mm512_shuffle_epi8(a4567, BYTESWAP_512);
        let a89ab = _mm512_shuffle_epi8(a89ab, BYTESWAP_512);
        let acdef = _mm512_shuffle_epi8(acdef, BYTESWAP_512);

        let c0___ = _mm512_inserti32x4::<0>(_mm512_setzero_si512(), current);
        let a0123 = _mm512_xor_epi64(a0123, c0___);

        current = ghash::_mul16(table, a0123, a4567, a89ab, acdef);
    }

    // SAFETY: `xi` is 16 writable bytes
    unsafe { _mm_storeu_si128(xi.as_mut_ptr().cast(), _mm_shuffle_epi8(current, BYTESWAP)) };
    add_ctr32(ivec, by16_iter.len() * 16);
    by16_iter.len() * 256
}

/// This stores the current four counter values, in big endian.
#[derive(Debug)]
struct Counter512(__m512i);

impl Counter512 {
    /// Starts at the counter block `ivec`.
    #[inline]
    #[target_feature(enable = "ssse3,avx512f")]
    fn new(ivec: &[u8; 16]) -> Self {
        // SAFETY: `ivec` is 16 readable bytes
        let c = _mm_shuffle_epi8(
            unsafe { _mm_loadu_si128(ivec.as_ptr().cast()) },
            BYTESWAP_EPI64,
        );
        Self(_mm512_add_epi64(
            _mm512_broadcast_i32x4(c),
            COUNTER_512_0123,
        ))
    }

    #[target_feature(enable = "sse3,ssse3,avx,avx2,avx512f,avx512bw")]
    #[must_use]
    #[inline]
    fn next4(&mut self) -> __m512i {
        let r = _mm512_shuffle_epi8(self.0, BYTESWAP_512_EPI64);
        self.0 = _mm512_add_epi64(self.0, COUNTER_512_4);
        r
    }
}

// SAFETY: [u8; 64] and __m512i have the same size
const COUNTER_512_0123: __m512i = unsafe {
    mem::transmute([
        0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
        0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, //
        0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, //
        0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, //
    ])
};

// SAFETY: [u8; 64] and __m512i have the same size
const COUNTER_512_4: __m512i = unsafe {
    mem::transmute([
        0u8, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, //
        0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, //
        0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, //
        0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, //
    ])
};

// SAFETY: both u128 and __m128i have the same size and all bits mean the same thing
const BYTESWAP: __m128i = unsafe { mem::transmute(0x00010203_04050607_08090a0b_0c0d0e0fu128) };

// SAFETY: both u128 and __m128i have the same size and all bits mean the same thing
const BYTESWAP_EPI64: __m128i =
    unsafe { mem::transmute(0x08090a0b_0c0d0e0f_00010203_04050607u128) };

// SAFETY: [u8; 64] and __m512i have the same size
const BYTESWAP_512: __m512i = unsafe {
    mem::transmute([
        15u8, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, //
        31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, //
        47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, //
        63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, //
    ])
};

// SAFETY: [u8; 64] and __m512i have the same size
const BYTESWAP_512_EPI64: __m512i = unsafe {
    mem::transmute([
        7, 6, 5, 4, 3, 2, 1, 0, 15u8, 14, 13, 12, 11, 10, 9, 8, //
        23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24, //
        39, 38, 37, 36, 35, 34, 33, 32, 47, 46, 45, 44, 43, 42, 41, 40, //
        55, 54, 53, 52, 51, 50, 49, 48, 63, 62, 61, 60, 59, 58, 57, 56,
    ])
};
