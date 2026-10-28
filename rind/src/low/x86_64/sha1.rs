// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::x86_64::*;

pub(in crate::low) fn sha1_compress_blocks_shaext(
    state: &mut [u32; 5],
    blocks: &[u8],
    _token: super::cpu::HaveSha1,
) {
    debug_assert!(blocks.len().is_multiple_of(64));
    // SAFETY: `_token` proves the caller checked the `sha` feature;
    // this crate requires the `sse4.1` and `ssse3` features
    unsafe { sha1(state, blocks) }
}

/// Four rounds: `$e` gains the next message words, `$e_next` saves `$abcd`
/// to seed the following four.
macro_rules! rounds4 {
    ($abcd:ident, $e:ident, $e_next:ident, $msg:ident, $func:literal) => {
        $e = _mm_sha1nexte_epu32($e, $msg);
        $e_next = $abcd;
        $abcd = _mm_sha1rnds4_epu32::<$func>($abcd, $e);
    };
}

// The message schedule is interleaved with the rounds as in Intel's
// "Intel SHA Extensions" paper (2013): for each group `g` of four rounds,
// `sha1msg2` finishes W for group g+1, `sha1msg1` starts W for g+3, and the
// xor folds W[t-8] into W for g+2.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn sha1(state: &mut [u32; 5], blocks: &[u8]) {
    // Reverses all 16 bytes: big-endian words, with W[0] in the top lane.
    let byte_reverse = _mm_set_epi64x(0x0001020304050607, 0x08090a0b0c0d0e0f);

    // SAFETY: `state` is 5 32-bit words, so the first 4 are readable
    let abcd = unsafe { _mm_loadu_si128(state[0..4].as_ptr().cast()) };
    let mut abcd = _mm_shuffle_epi32(abcd, 0b00_01_10_11);
    let mut e0 = _mm_set_epi32(state[4] as i32, 0, 0, 0);

    let (chunks, _) = blocks.as_chunks::<64>();
    for block in chunks {
        let abcd_prev = abcd;
        let e0_prev = e0;

        // SAFETY: `block` is 64 bytes and readable
        let (msg0, msg1, msg2, msg3) = unsafe {
            (
                _mm_loadu_si128(block[0..].as_ptr().cast()),
                _mm_loadu_si128(block[16..].as_ptr().cast()),
                _mm_loadu_si128(block[32..].as_ptr().cast()),
                _mm_loadu_si128(block[48..].as_ptr().cast()),
            )
        };
        let mut msg0 = _mm_shuffle_epi8(msg0, byte_reverse);
        let mut msg1 = _mm_shuffle_epi8(msg1, byte_reverse);
        let mut msg2 = _mm_shuffle_epi8(msg2, byte_reverse);
        let mut msg3 = _mm_shuffle_epi8(msg3, byte_reverse);

        // Rounds 0-3: the first group adds `e` directly, since it is not
        // derived from a previous `abcd`.
        e0 = _mm_add_epi32(e0, msg0);
        let mut e1 = abcd;
        abcd = _mm_sha1rnds4_epu32::<0>(abcd, e0);

        // Rounds 4-7
        rounds4!(abcd, e1, e0, msg1, 0);
        msg0 = _mm_sha1msg1_epu32(msg0, msg1);

        // Rounds 8-11
        rounds4!(abcd, e0, e1, msg2, 0);
        msg1 = _mm_sha1msg1_epu32(msg1, msg2);
        msg0 = _mm_xor_si128(msg0, msg2);

        // Rounds 12-15
        msg0 = _mm_sha1msg2_epu32(msg0, msg3);
        rounds4!(abcd, e1, e0, msg3, 0);
        msg2 = _mm_sha1msg1_epu32(msg2, msg3);
        msg1 = _mm_xor_si128(msg1, msg3);

        // Rounds 16-19
        msg1 = _mm_sha1msg2_epu32(msg1, msg0);
        rounds4!(abcd, e0, e1, msg0, 0);
        msg3 = _mm_sha1msg1_epu32(msg3, msg0);
        msg2 = _mm_xor_si128(msg2, msg0);

        // Rounds 20-23
        msg2 = _mm_sha1msg2_epu32(msg2, msg1);
        rounds4!(abcd, e1, e0, msg1, 1);
        msg0 = _mm_sha1msg1_epu32(msg0, msg1);
        msg3 = _mm_xor_si128(msg3, msg1);

        // Rounds 24-27
        msg3 = _mm_sha1msg2_epu32(msg3, msg2);
        rounds4!(abcd, e0, e1, msg2, 1);
        msg1 = _mm_sha1msg1_epu32(msg1, msg2);
        msg0 = _mm_xor_si128(msg0, msg2);

        // Rounds 28-31
        msg0 = _mm_sha1msg2_epu32(msg0, msg3);
        rounds4!(abcd, e1, e0, msg3, 1);
        msg2 = _mm_sha1msg1_epu32(msg2, msg3);
        msg1 = _mm_xor_si128(msg1, msg3);

        // Rounds 32-35
        msg1 = _mm_sha1msg2_epu32(msg1, msg0);
        rounds4!(abcd, e0, e1, msg0, 1);
        msg3 = _mm_sha1msg1_epu32(msg3, msg0);
        msg2 = _mm_xor_si128(msg2, msg0);

        // Rounds 36-39
        msg2 = _mm_sha1msg2_epu32(msg2, msg1);
        rounds4!(abcd, e1, e0, msg1, 1);
        msg0 = _mm_sha1msg1_epu32(msg0, msg1);
        msg3 = _mm_xor_si128(msg3, msg1);

        // Rounds 40-43
        msg3 = _mm_sha1msg2_epu32(msg3, msg2);
        rounds4!(abcd, e0, e1, msg2, 2);
        msg1 = _mm_sha1msg1_epu32(msg1, msg2);
        msg0 = _mm_xor_si128(msg0, msg2);

        // Rounds 44-47
        msg0 = _mm_sha1msg2_epu32(msg0, msg3);
        rounds4!(abcd, e1, e0, msg3, 2);
        msg2 = _mm_sha1msg1_epu32(msg2, msg3);
        msg1 = _mm_xor_si128(msg1, msg3);

        // Rounds 48-51
        msg1 = _mm_sha1msg2_epu32(msg1, msg0);
        rounds4!(abcd, e0, e1, msg0, 2);
        msg3 = _mm_sha1msg1_epu32(msg3, msg0);
        msg2 = _mm_xor_si128(msg2, msg0);

        // Rounds 52-55
        msg2 = _mm_sha1msg2_epu32(msg2, msg1);
        rounds4!(abcd, e1, e0, msg1, 2);
        msg0 = _mm_sha1msg1_epu32(msg0, msg1);
        msg3 = _mm_xor_si128(msg3, msg1);

        // Rounds 56-59
        msg3 = _mm_sha1msg2_epu32(msg3, msg2);
        rounds4!(abcd, e0, e1, msg2, 2);
        msg1 = _mm_sha1msg1_epu32(msg1, msg2);
        msg0 = _mm_xor_si128(msg0, msg2);

        // Rounds 60-63
        msg0 = _mm_sha1msg2_epu32(msg0, msg3);
        rounds4!(abcd, e1, e0, msg3, 3);
        msg2 = _mm_sha1msg1_epu32(msg2, msg3);
        msg1 = _mm_xor_si128(msg1, msg3);

        // Rounds 64-67
        msg1 = _mm_sha1msg2_epu32(msg1, msg0);
        rounds4!(abcd, e0, e1, msg0, 3);
        msg3 = _mm_sha1msg1_epu32(msg3, msg0);
        msg2 = _mm_xor_si128(msg2, msg0);

        // Rounds 68-71
        msg2 = _mm_sha1msg2_epu32(msg2, msg1);
        rounds4!(abcd, e1, e0, msg1, 3);
        msg3 = _mm_xor_si128(msg3, msg1);

        // Rounds 72-75
        msg3 = _mm_sha1msg2_epu32(msg3, msg2);
        rounds4!(abcd, e0, e1, msg2, 3);

        // Rounds 76-79
        rounds4!(abcd, e1, e0, msg3, 3);

        e0 = _mm_sha1nexte_epu32(e0, e0_prev);
        abcd = _mm_add_epi32(abcd, abcd_prev);
    }

    let abcd = _mm_shuffle_epi32(abcd, 0b00_01_10_11);
    // SAFETY: `state` is 5 32-bit words, so the first 4 are writable
    unsafe { _mm_storeu_si128(state[0..4].as_mut_ptr().cast(), abcd) };
    state[4] = _mm_extract_epi32::<3>(e0) as u32;
}
