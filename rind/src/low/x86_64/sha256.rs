// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::x86_64::*;

pub(in crate::low) fn sha256_compress_blocks_shaext(
    state: &mut [u32; 8],
    blocks: &[u8],
    _token: super::cpu::HaveSha256,
) {
    debug_assert!(blocks.len().is_multiple_of(64));
    // SAFETY: `_token` proves the caller checked the `sha` feature;
    // this crate requires the `sse4.1` and `ssse3` features
    unsafe { sha256(state, blocks) }
}

macro_rules! k {
    ($k:literal) => {
        // SAFETY: `$k` is a compile-time constant and results in a valid index
        // into the const table `K`.  `K` has proper alignment for this aligned
        // load.
        unsafe { _mm_load_si128(K.0.as_ptr().add($k * 4).cast()) }
    };
}

macro_rules! round {
    ($msg_cur:ident, $state0:ident, $state1:ident, $k:ident) => {
        let msg = _mm_add_epi32($msg_cur, $k);
        $state1 = _mm_sha256rnds2_epu32($state1, $state0, msg);
        let msg = _mm_shuffle_epi32(msg, 0b00_00_11_10);
        $state0 = _mm_sha256rnds2_epu32($state0, $state1, msg);
    };

    ($msg_cur:ident, $msg_prev:ident, $state0:ident, $state1:ident, $k:ident) => {
        round!($msg_cur, $state0, $state1, $k);
        let $msg_prev = _mm_sha256msg1_epu32($msg_prev, $msg_cur);
    };

    ($msg_cur:ident, $msg_prev:ident, $msg_next:ident, $state0:ident, $state1:ident, $k:ident) => {
        let msg = _mm_add_epi32($msg_cur, $k);
        $state1 = _mm_sha256rnds2_epu32($state1, $state0, msg);
        let tmp = _mm_alignr_epi8($msg_cur, $msg_prev, 4);
        let $msg_next = _mm_add_epi32($msg_next, tmp);
        let $msg_next = _mm_sha256msg2_epu32($msg_next, $msg_cur);
        let msg = _mm_shuffle_epi32(msg, 0b00_00_11_10);
        $state0 = _mm_sha256rnds2_epu32($state0, $state1, msg);
        let $msg_prev = _mm_sha256msg1_epu32($msg_prev, $msg_cur);
    };
}

#[target_feature(enable = "sha,sse4.1,ssse3")]
fn sha256(state: &mut [u32; 8], blocks: &[u8]) {
    let little_endian_shuffle = _mm_set_epi64x(0x0c0d0e0f08090a0b, 0x0405060700010203);

    // SAFETY: `state` is 8 32-bit words and readable
    let (state0, state1) = unsafe {
        (
            _mm_loadu_si128(state[0..4].as_ptr().cast()),
            _mm_loadu_si128(state[4..8].as_ptr().cast()),
        )
    };

    let tmp = _mm_shuffle_epi32(state0, 0b10_11_00_01);
    let state1 = _mm_shuffle_epi32(state1, 0b00_01_10_11);
    let mut state0 = _mm_alignr_epi8(tmp, state1, 8);
    let mut state1 = _mm_blend_epi16(state1, tmp, 0xf0);

    let k0 = k!(0);
    let k1 = k!(1);
    let k2 = k!(2);
    let k3 = k!(3);
    let k4 = k!(4);
    let k5 = k!(5);
    let k6 = k!(6);
    let k7 = k!(7);
    let k8 = k!(8);
    let k9 = k!(9);
    let k10 = k!(10);
    let k11 = k!(11);
    let k12 = k!(12);
    let k13 = k!(13);
    let k14 = k!(14);
    let k15 = k!(15);

    let (chunks, _) = blocks.as_chunks::<64>();
    for block in chunks {
        let state0_prev = state0;
        let state1_prev = state1;

        // SAFETY: `block` is 64 bytes and readable
        let (msg0, msg1, msg2, msg3) = unsafe {
            (
                _mm_loadu_si128(block[0..].as_ptr().cast()),
                _mm_loadu_si128(block[16..].as_ptr().cast()),
                _mm_loadu_si128(block[32..].as_ptr().cast()),
                _mm_loadu_si128(block[48..].as_ptr().cast()),
            )
        };

        let msg0 = _mm_shuffle_epi8(msg0, little_endian_shuffle);
        let msg1 = _mm_shuffle_epi8(msg1, little_endian_shuffle);
        let msg2 = _mm_shuffle_epi8(msg2, little_endian_shuffle);
        let msg3 = _mm_shuffle_epi8(msg3, little_endian_shuffle);

        round!(msg0, state0, state1, k0);
        round!(msg1, msg0, state0, state1, k1);
        round!(msg2, msg1, state0, state1, k2);
        round!(msg3, msg2, msg0, state0, state1, k3);
        round!(msg0, msg3, msg1, state0, state1, k4);
        round!(msg1, msg0, msg2, state0, state1, k5);
        round!(msg2, msg1, msg3, state0, state1, k6);
        round!(msg3, msg2, msg0, state0, state1, k7);
        round!(msg0, msg3, msg1, state0, state1, k8);
        round!(msg1, msg0, msg2, state0, state1, k9);
        round!(msg2, msg1, msg3, state0, state1, k10);
        round!(msg3, msg2, msg0, state0, state1, k11);
        round!(msg0, msg3, msg1, state0, state1, k12);
        round!(msg1, msg0, msg2, state0, state1, k13);
        round!(msg2, msg1, msg3, state0, state1, k14);
        round!(msg3, state0, state1, k15);
        let _ = msg1;
        let _ = msg0;

        state0 = _mm_add_epi32(state0, state0_prev);
        state1 = _mm_add_epi32(state1, state1_prev);
    }

    let tmp = _mm_shuffle_epi32(state0, 0b00_01_10_11);
    let state1 = _mm_shuffle_epi32(state1, 0b10_11_00_01);
    let state0 = _mm_blend_epi16(tmp, state1, 0xf0);
    let state1 = _mm_alignr_epi8(state1, tmp, 8);

    // SAFETY: `state` is 8 32-bit words and writable
    unsafe {
        _mm_storeu_si128(state[0..4].as_mut_ptr().cast(), state0);
        _mm_storeu_si128(state[4..8].as_mut_ptr().cast(), state1);
    }
}

/// SHA-256 without the SHA extensions, structured as aws-lc's
/// `sha256_block_data_order_avx2`: AVX2 computes the message schedule of two
/// blocks at once, one per 128-bit lane, interleaved with the scalar rounds
/// of the first block; the second block's rounds then read their half.
pub(in crate::low) fn sha256_compress_blocks_avx2(state: &mut [u32; 8], blocks: &[u8]) {
    debug_assert!(blocks.len().is_multiple_of(64));
    // SAFETY: this crate requires the `avx2` and `bmi2` cpu features
    unsafe { sha256_avx2(state, blocks) }
}

#[target_feature(enable = "avx,avx2,bmi2")]
fn sha256_avx2(state: &mut [u32; 8], blocks: &[u8]) {
    let (blocks, _) = blocks.as_chunks::<64>();
    let (pairs, last) = blocks.as_chunks::<2>();
    let mut wk = [[[0; 4]; 2]; 16];
    for [first, second] in pairs {
        schedule_and_rounds(state, &mut wk, first, second);
        second_rounds(state, &wk);
    }
    // An odd last block fills both lanes, and only its first runs.
    if let [last] = last {
        schedule_and_rounds(state, &mut wk, last, last);
    }
}

/// W[t] + K[t] for rounds `4g..4g + 4` of two blocks: `[g][0]` for the first
/// block, `[g][1]` for the second.
type Schedule = [[[u32; 4]; 2]; 16];

/// One round of FIPS 180-4, 6.2.2, given W[t] + K[t]. Rather than moving
/// every variable, each round names them one place further along.
///
/// MAJ(a, b, c) = b ^ ((a ^ b) & (b ^ c)), and this round's a ^ b is the
/// next round's b ^ c, so `$bc` carries it.
macro_rules! round {
    ($a:ident $b:ident $c:ident $d:ident $e:ident $f:ident $g:ident $h:ident, $bc:ident, $wk:expr) => {
        $h = $h
            .wrapping_add($wk)
            .wrapping_add($e.rotate_right(6) ^ $e.rotate_right(11) ^ $e.rotate_right(25))
            .wrapping_add($g ^ ($e & ($f ^ $g)));
        $d = $d.wrapping_add($h);
        let ab = $a ^ $b;
        $h = $h
            .wrapping_add($a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22))
            .wrapping_add($b ^ (ab & $bc));
        $bc = ab;
    };
}

/// Four rounds, given their W + K. After them, `e f g h a b c d` name what
/// `a b c d e f g h` did.
macro_rules! rounds4 {
    ($a:ident $b:ident $c:ident $d:ident $e:ident $f:ident $g:ident $h:ident, $bc:ident, $wk:expr) => {
        let wk: [u32; 4] = $wk;
        round!($a $b $c $d $e $f $g $h, $bc, wk[0]);
        round!($h $a $b $c $d $e $f $g, $bc, wk[1]);
        round!($g $h $a $b $c $d $e $f, $bc, wk[2]);
        round!($f $g $h $a $b $c $d $e, $bc, wk[3]);
    };
}

/// Fills `wk` from `first` and `second`, running the first block's rounds as
/// each group of four is ready, so the vector work overlaps the serial
/// scalar rounds.
#[inline]
#[target_feature(enable = "avx,avx2,bmi2")]
fn schedule_and_rounds(
    state: &mut [u32; 8],
    wk: &mut Schedule,
    first: &[u8; 64],
    second: &[u8; 64],
) {
    let mut w0 = load(first, second, 0);
    let mut w1 = load(first, second, 1);
    let mut w2 = load(first, second, 2);
    let mut w3 = load(first, second, 3);
    store(wk, 0, w0);
    store(wk, 1, w1);
    store(wk, 2, w2);
    store(wk, 3, w3);

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    let mut bc = b ^ c;
    for i in (0..12).step_by(4) {
        rounds4!(a b c d e f g h, bc, wk[i][0]);
        w0 = schedule(w0, w1, w2, w3);
        store(wk, i + 4, w0);
        rounds4!(e f g h a b c d, bc, wk[i + 1][0]);
        w1 = schedule(w1, w2, w3, w0);
        store(wk, i + 5, w1);
        rounds4!(a b c d e f g h, bc, wk[i + 2][0]);
        w2 = schedule(w2, w3, w0, w1);
        store(wk, i + 6, w2);
        rounds4!(e f g h a b c d, bc, wk[i + 3][0]);
        w3 = schedule(w3, w0, w1, w2);
        store(wk, i + 7, w3);
    }
    rounds4!(a b c d e f g h, bc, wk[12][0]);
    rounds4!(e f g h a b c d, bc, wk[13][0]);
    rounds4!(a b c d e f g h, bc, wk[14][0]);
    rounds4!(e f g h a b c d, bc, wk[15][0]);

    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

/// Runs the second block's rounds from a filled `wk`.
#[inline]
#[target_feature(enable = "bmi2")]
fn second_rounds(state: &mut [u32; 8], wk: &Schedule) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    let mut bc = b ^ c;
    for i in (0..16).step_by(2) {
        rounds4!(a b c d e f g h, bc, wk[i][1]);
        rounds4!(e f g h a b c d, bc, wk[i + 1][1]);
    }

    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

/// W[4i..4i + 4] of both blocks: the message's big-endian words.
#[inline]
#[target_feature(enable = "avx,avx2")]
fn load(first: &[u8; 64], second: &[u8; 64], i: usize) -> __m256i {
    let byte_reverse = _mm256_set_epi64x(
        0x0c0d0e0f_08090a0b,
        0x04050607_00010203,
        0x0c0d0e0f_08090a0b,
        0x04050607_00010203,
    );
    let (first, second) = (
        &first.as_chunks::<16>().0[i],
        &second.as_chunks::<16>().0[i],
    );
    // SAFETY: `first` and `second` are 16 bytes and readable
    let (lo, hi) = unsafe {
        (
            _mm_loadu_si128(first.as_ptr().cast()),
            _mm_loadu_si128(second.as_ptr().cast()),
        )
    };
    let words = _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(lo), hi);
    _mm256_shuffle_epi8(words, byte_reverse)
}

/// Stores W[4g..4g + 4] + K[4g..4g + 4] of both blocks as group `g` of `wk`.
#[inline]
#[target_feature(enable = "avx,avx2")]
fn store(wk: &mut Schedule, g: usize, w: __m256i) {
    let k = &K.0.as_chunks::<4>().0[g];
    // SAFETY: `k` is 4 32-bit words, so 16 bytes are readable
    let k = _mm256_broadcastsi128_si256(unsafe { _mm_loadu_si128(k.as_ptr().cast()) });
    // SAFETY: `wk[g]` is 8 32-bit words, so 32 bytes are writable
    unsafe { _mm256_storeu_si256(wk[g].as_mut_ptr().cast(), _mm256_add_epi32(w, k)) };
}

/// The next four words of each block's schedule, from the sixteen before:
/// W[t] = SSIG1(W[t-2]) + W[t-7] + SSIG0(W[t-15]) + W[t-16] (FIPS 180-4,
/// 6.2.2). Every AVX2 op used here works within its 128-bit lane, so the two
/// blocks never mix.
#[inline]
#[target_feature(enable = "avx,avx2")]
fn schedule(w16: __m256i, w12: __m256i, w8: __m256i, w4: __m256i) -> __m256i {
    let x = _mm256_add_epi32(
        _mm256_add_epi32(w16, _mm256_alignr_epi8::<4>(w4, w8)),
        ssig0(_mm256_alignr_epi8::<4>(w12, w16)),
    );
    // W[t+2] and W[t+3] need W[t] and W[t+1] from this same group, so the
    // SSIG1 term is added a pair at a time: words 0 and 1 first, from the
    // last two words of `w4`, then words 2 and 3 from those.
    let place_low = _mm256_set_epi64x(-1, 0x0b0a0908_03020100, -1, 0x0b0a0908_03020100);
    let place_high = _mm256_set_epi64x(0x0b0a0908_03020100, -1, 0x0b0a0908_03020100, -1);
    let x = _mm256_add_epi32(
        x,
        ssig1_pair(_mm256_shuffle_epi32::<0b11_11_10_10>(w4), place_low),
    );
    _mm256_add_epi32(
        x,
        ssig1_pair(_mm256_shuffle_epi32::<0b01_01_00_00>(x), place_high),
    )
}

/// SSIG0 of each 32-bit word: ROTR7 ^ ROTR18 ^ SHR3.
#[inline]
#[target_feature(enable = "avx,avx2")]
fn ssig0(x: __m256i) -> __m256i {
    _mm256_xor_si256(
        _mm256_xor_si256(
            _mm256_xor_si256(_mm256_srli_epi32::<7>(x), _mm256_slli_epi32::<25>(x)),
            _mm256_xor_si256(_mm256_srli_epi32::<18>(x), _mm256_slli_epi32::<14>(x)),
        ),
        _mm256_srli_epi32::<3>(x),
    )
}

/// SSIG1 (ROTR17 ^ ROTR19 ^ SHR10) of two words per lane, each given twice
/// as a 64-bit half of `pairs`, so a 64-bit shift rotates it. The `place`
/// shuffle moves the two results into position and zeroes the other words.
#[inline]
#[target_feature(enable = "avx,avx2")]
fn ssig1_pair(pairs: __m256i, place: __m256i) -> __m256i {
    let x = _mm256_xor_si256(
        _mm256_xor_si256(
            _mm256_srli_epi64::<17>(pairs),
            _mm256_srli_epi64::<19>(pairs),
        ),
        _mm256_srli_epi32::<10>(pairs),
    );
    _mm256_shuffle_epi8(x, place)
}

#[repr(align(16))]
struct Aligned([u32; 64]);

static K: Aligned = Aligned([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::low::generic;

    // The SHA extensions, where present, would hide this path from every
    // other test, so it is checked against the portable code directly: odd
    // and even block counts, with distinct bytes in every block.
    #[test]
    fn avx2_matches_generic() {
        let blocks: Vec<u8> = (0..5 * 64u32)
            .map(|i| (i.wrapping_mul(0x9e3779b9) >> 24) as u8)
            .collect();
        for n in 0..=5 {
            let mut wanted = [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ];
            let mut got = wanted;
            generic::sha256::sha256_compress_blocks(&mut wanted, &blocks[..n * 64]);
            sha256_compress_blocks_avx2(&mut got, &blocks[..n * 64]);
            assert_eq!(got, wanted, "{n} blocks");
        }
    }
}
