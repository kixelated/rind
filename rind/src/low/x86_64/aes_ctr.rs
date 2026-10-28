// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::x86_64::*;

use super::aes::AesKey;

/// XORs eight blocks of AES-CTR keystream into `inout`.
///
/// The counter blocks are `nonce` followed by the big-endian `counter`,
/// `counter + 1`, ... `counter + 7`, wrapping within 32 bits.
pub(crate) fn apply_8(key: &AesKey, nonce: &[u8; 12], counter: u32, inout: &mut [u8; 128]) {
    let (rk_first, rks, rk_last) = key.round_keys();
    // SAFETY: this crate requires the `aes` & `avx` cpu features
    unsafe { _apply_8(rk_first, rks, rk_last, nonce, counter, inout) }
}

#[target_feature(enable = "aes,avx")]
fn _apply_8(
    rk_first: __m128i,
    rks: &[__m128i],
    rk_last: __m128i,
    nonce: &[u8; 12],
    counter: u32,
    inout: &mut [u8; 128],
) {
    let mut base = [0u8; 16];
    base[..12].copy_from_slice(nonce);
    // SAFETY: `base` is 16 bytes and readable
    let base = unsafe { _mm_loadu_si128(base.as_ptr().cast()) };
    // lane 3 holds bytes 12..16 little-endian, so swap to store big-endian
    let block = |i: u32| {
        let c = _mm_insert_epi32::<3>(base, counter.wrapping_add(i).swap_bytes() as i32);
        _mm_xor_si128(c, rk_first)
    };

    let mut b0 = block(0);
    let mut b1 = block(1);
    let mut b2 = block(2);
    let mut b3 = block(3);
    let mut b4 = block(4);
    let mut b5 = block(5);
    let mut b6 = block(6);
    let mut b7 = block(7);

    for rk in rks {
        b0 = _mm_aesenc_si128(b0, *rk);
        b1 = _mm_aesenc_si128(b1, *rk);
        b2 = _mm_aesenc_si128(b2, *rk);
        b3 = _mm_aesenc_si128(b3, *rk);
        b4 = _mm_aesenc_si128(b4, *rk);
        b5 = _mm_aesenc_si128(b5, *rk);
        b6 = _mm_aesenc_si128(b6, *rk);
        b7 = _mm_aesenc_si128(b7, *rk);
    }

    let b0 = _mm_aesenclast_si128(b0, rk_last);
    let b1 = _mm_aesenclast_si128(b1, rk_last);
    let b2 = _mm_aesenclast_si128(b2, rk_last);
    let b3 = _mm_aesenclast_si128(b3, rk_last);
    let b4 = _mm_aesenclast_si128(b4, rk_last);
    let b5 = _mm_aesenclast_si128(b5, rk_last);
    let b6 = _mm_aesenclast_si128(b6, rk_last);
    let b7 = _mm_aesenclast_si128(b7, rk_last);

    // SAFETY: `inout` is 128 bytes and readable
    let (p0, p1, p2, p3, p4, p5, p6, p7) = unsafe {
        (
            _mm_loadu_si128(inout.as_ptr().add(0).cast()),
            _mm_loadu_si128(inout.as_ptr().add(16).cast()),
            _mm_loadu_si128(inout.as_ptr().add(32).cast()),
            _mm_loadu_si128(inout.as_ptr().add(48).cast()),
            _mm_loadu_si128(inout.as_ptr().add(64).cast()),
            _mm_loadu_si128(inout.as_ptr().add(80).cast()),
            _mm_loadu_si128(inout.as_ptr().add(96).cast()),
            _mm_loadu_si128(inout.as_ptr().add(112).cast()),
        )
    };

    // SAFETY: `inout` is 128 bytes and writable
    unsafe {
        _mm_storeu_si128(inout.as_mut_ptr().add(0).cast(), _mm_xor_si128(b0, p0));
        _mm_storeu_si128(inout.as_mut_ptr().add(16).cast(), _mm_xor_si128(b1, p1));
        _mm_storeu_si128(inout.as_mut_ptr().add(32).cast(), _mm_xor_si128(b2, p2));
        _mm_storeu_si128(inout.as_mut_ptr().add(48).cast(), _mm_xor_si128(b3, p3));
        _mm_storeu_si128(inout.as_mut_ptr().add(64).cast(), _mm_xor_si128(b4, p4));
        _mm_storeu_si128(inout.as_mut_ptr().add(80).cast(), _mm_xor_si128(b5, p5));
        _mm_storeu_si128(inout.as_mut_ptr().add(96).cast(), _mm_xor_si128(b6, p6));
        _mm_storeu_si128(inout.as_mut_ptr().add(112).cast(), _mm_xor_si128(b7, p7));
    }
}
