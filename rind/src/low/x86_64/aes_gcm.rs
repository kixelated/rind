// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
//
//! Ref. <https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/communications-ia-cryptographic-paper.pdf>

use core::arch::x86_64::*;
use core::mem;

use super::aes::AesKey;
use super::ghash::{self, Ghash, GhashTable, GhashTableAvx};

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

// AES-GCM encrypt (if `ENC` is `true`) or decrypt, on the kernel the GHASH
// key was made for.
fn cipher<const ENC: bool>(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    initial_counter: &[u8; 16],
    aad: &[u8],
    cipher_inout: &mut [u8],
) {
    ghash.add(aad);
    match ghash.table {
        GhashTable::Vaes(table) if cipher_inout.len() >= VAES_MINIMUM_CIPHER_LEN => {
            table.cipher::<ENC>(key, initial_counter, ghash, cipher_inout)
        }
        // SAFETY: this crate requires the `aes`, `ssse3`, `pclmulqdq` and `avx` cpu features
        table => unsafe { _cipher::<ENC>(key, ghash, table.avx(), initial_counter, cipher_inout) },
    }
}

/// How many message bytes a VAES kernel needs to beat the AVX path.
const VAES_MINIMUM_CIPHER_LEN: usize = 1;

#[target_feature(enable = "aes,ssse3,pclmulqdq,avx")]
fn _cipher<const ENC: bool>(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    avx_ghash_table: &GhashTableAvx,
    initial_counter: &[u8; 16],
    cipher_inout: &mut [u8],
) {
    let (rk_first, rks, rk_last) = key.round_keys();

    let mut counter = Counter::new(initial_counter);
    let (by8_iter, remainder) = cipher_inout.as_chunks_mut::<128>();

    for blocks in by8_iter {
        // prefetch to avoid any stall later
        super::cpu::prefetch(blocks, 64);

        let c1 = counter.next();
        let c2 = counter.next();
        let c3 = counter.next();
        let c4 = counter.next();
        let c5 = counter.next();
        let c6 = counter.next();
        let c7 = counter.next();
        let c8 = counter.next();

        let mut c1 = _mm_xor_si128(c1, rk_first);
        let mut c2 = _mm_xor_si128(c2, rk_first);
        let mut c3 = _mm_xor_si128(c3, rk_first);
        let mut c4 = _mm_xor_si128(c4, rk_first);
        let mut c5 = _mm_xor_si128(c5, rk_first);
        let mut c6 = _mm_xor_si128(c6, rk_first);
        let mut c7 = _mm_xor_si128(c7, rk_first);
        let mut c8 = _mm_xor_si128(c8, rk_first);

        for rk in rks {
            c1 = _mm_aesenc_si128(c1, *rk);
            c2 = _mm_aesenc_si128(c2, *rk);
            c3 = _mm_aesenc_si128(c3, *rk);
            c4 = _mm_aesenc_si128(c4, *rk);
            c5 = _mm_aesenc_si128(c5, *rk);
            c6 = _mm_aesenc_si128(c6, *rk);
            c7 = _mm_aesenc_si128(c7, *rk);
            c8 = _mm_aesenc_si128(c8, *rk);
        }

        let c1 = _mm_aesenclast_si128(c1, rk_last);
        let c2 = _mm_aesenclast_si128(c2, rk_last);
        let c3 = _mm_aesenclast_si128(c3, rk_last);
        let c4 = _mm_aesenclast_si128(c4, rk_last);
        let c5 = _mm_aesenclast_si128(c5, rk_last);
        let c6 = _mm_aesenclast_si128(c6, rk_last);
        let c7 = _mm_aesenclast_si128(c7, rk_last);
        let c8 = _mm_aesenclast_si128(c8, rk_last);

        // SAFETY: `blocks` is 128 bytes and readable
        let (p1, p2, p3, p4, p5, p6, p7, p8) = unsafe {
            (
                _mm_loadu_si128(blocks.as_ptr().add(0).cast()),
                _mm_loadu_si128(blocks.as_ptr().add(16).cast()),
                _mm_loadu_si128(blocks.as_ptr().add(32).cast()),
                _mm_loadu_si128(blocks.as_ptr().add(48).cast()),
                _mm_loadu_si128(blocks.as_ptr().add(64).cast()),
                _mm_loadu_si128(blocks.as_ptr().add(80).cast()),
                _mm_loadu_si128(blocks.as_ptr().add(96).cast()),
                _mm_loadu_si128(blocks.as_ptr().add(112).cast()),
            )
        };

        let c1 = _mm_xor_si128(c1, p1);
        let c2 = _mm_xor_si128(c2, p2);
        let c3 = _mm_xor_si128(c3, p3);
        let c4 = _mm_xor_si128(c4, p4);
        let c5 = _mm_xor_si128(c5, p5);
        let c6 = _mm_xor_si128(c6, p6);
        let c7 = _mm_xor_si128(c7, p7);
        let c8 = _mm_xor_si128(c8, p8);

        // SAFETY: `blocks` is 128 bytes and writable, due to `as_chunks_mut`
        unsafe {
            _mm_storeu_si128(blocks.as_mut_ptr().add(0).cast(), c1);
            _mm_storeu_si128(blocks.as_mut_ptr().add(16).cast(), c2);
            _mm_storeu_si128(blocks.as_mut_ptr().add(32).cast(), c3);
            _mm_storeu_si128(blocks.as_mut_ptr().add(48).cast(), c4);
            _mm_storeu_si128(blocks.as_mut_ptr().add(64).cast(), c5);
            _mm_storeu_si128(blocks.as_mut_ptr().add(80).cast(), c6);
            _mm_storeu_si128(blocks.as_mut_ptr().add(96).cast(), c7);
            _mm_storeu_si128(blocks.as_mut_ptr().add(112).cast(), c8);
        }

        let (a1, a2, a3, a4, a5, a6, a7, a8) = if ENC {
            (c1, c2, c3, c4, c5, c6, c7, c8)
        } else {
            (p1, p2, p3, p4, p5, p6, p7, p8)
        };

        let a1 = _mm_shuffle_epi8(a1, BYTESWAP);
        let a2 = _mm_shuffle_epi8(a2, BYTESWAP);
        let a3 = _mm_shuffle_epi8(a3, BYTESWAP);
        let a4 = _mm_shuffle_epi8(a4, BYTESWAP);
        let a5 = _mm_shuffle_epi8(a5, BYTESWAP);
        let a6 = _mm_shuffle_epi8(a6, BYTESWAP);
        let a7 = _mm_shuffle_epi8(a7, BYTESWAP);
        let a8 = _mm_shuffle_epi8(a8, BYTESWAP);

        let a1 = _mm_xor_si128(ghash.current, a1);
        ghash.current = ghash::_mul8(avx_ghash_table, a1, a2, a3, a4, a5, a6, a7, a8);
    }

    let cipher_inout = remainder;

    if !ENC {
        ghash.add(cipher_inout);
    }

    {
        let (blocks_iter, remainder) = cipher_inout.as_chunks_mut::<16>();
        for block in blocks_iter {
            let c1 = counter.next();

            let mut c1 = _mm_xor_si128(c1, rk_first);

            for rk in rks {
                c1 = _mm_aesenc_si128(c1, *rk);
            }

            let c1 = _mm_aesenclast_si128(c1, rk_last);

            // SAFETY: `block` is 16 bytes due to `as_chunks_mut`
            let p1 = unsafe { _mm_loadu_si128(block.as_ptr().cast()) };
            let c1 = _mm_xor_si128(c1, p1);

            // SAFETY: `block` is 16 bytes and writable, due to `as_chunks_mut`
            unsafe { _mm_storeu_si128(block.as_mut_ptr().cast(), c1) };
        }

        let cipher_inout = remainder;
        if !cipher_inout.is_empty() {
            let mut block = [0u8; 16];
            let len = cipher_inout.len();
            debug_assert!(len < 16);
            block[..len].copy_from_slice(cipher_inout);

            let c1 = counter.next();
            let mut c1 = _mm_xor_si128(c1, rk_first);

            for rk in rks {
                c1 = _mm_aesenc_si128(c1, *rk);
            }

            let c1 = _mm_aesenclast_si128(c1, rk_last);

            // SAFETY: `block` is 16 bytes and writable.
            let p1 = unsafe { _mm_loadu_si128(block.as_ptr().cast()) };
            let c1 = _mm_xor_si128(c1, p1);

            // SAFETY: `block` is 16 bytes and writable.
            unsafe {
                _mm_storeu_si128(block.as_mut_ptr().cast(), c1);
            }

            cipher_inout.copy_from_slice(&block[..len]);
        }
    }

    if ENC {
        ghash.add(cipher_inout);
    }
}

/// This stores the current counter value, in big endian.
#[derive(Clone, Copy, Debug)]
struct Counter(__m128i);

impl Counter {
    #[inline]
    #[target_feature(enable = "sse2,sse3,ssse3")]
    fn new(bytes: &[u8; 16]) -> Self {
        // SAFETY: `bytes` is a 128-bit value and can be loaded from
        let c = unsafe { _mm_lddqu_si128(bytes.as_ptr().cast()) };
        let c = _mm_shuffle_epi8(c, BYTESWAP_EPI64);
        let c = _mm_add_epi32(c, COUNTER_1); // skip first counter (it was already used as y0)

        Self(c)
    }

    #[target_feature(enable = "sse2,ssse3")]
    #[must_use]
    #[inline]
    fn next(&mut self) -> __m128i {
        let r = _mm_shuffle_epi8(self.0, BYTESWAP_EPI64);
        self.0 = _mm_add_epi32(self.0, COUNTER_1);
        r
    }
}

// SAFETY: both u128 and __m128i have the same size and all bits mean the same thing
const COUNTER_1: __m128i = unsafe { mem::transmute(1u128 << 64) };

// SAFETY: both u128 and __m128i have the same size and all bits mean the same thing
const BYTESWAP: __m128i = unsafe { mem::transmute(0x00010203_04050607_08090a0b_0c0d0e0fu128) };

// SAFETY: both u128 and __m128i have the same size and all bits mean the same thing
const BYTESWAP_EPI64: __m128i =
    unsafe { mem::transmute(0x08090a0b_0c0d0e0f_00010203_04050607u128) };
