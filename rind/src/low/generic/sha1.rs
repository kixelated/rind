// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::low::zeroise;

macro_rules! CH {
    ($x:expr, $y:expr, $z:expr) => {
        $z ^ ($x & ($y ^ $z))
    };
}

macro_rules! PARITY {
    ($x:expr, $y:expr, $z:expr) => {
        $x ^ $y ^ $z
    };
}

macro_rules! MAJ {
    ($x:expr, $y:expr, $z:expr) => {
        ($x & $y) | ($z & ($x | $y))
    };
}

/// `w` is a 16-word window into the whole W array.
fn sha1_compress_block(state: &mut [u32; 5], block: &[u8; 64], w: &mut [u32; 16]) {
    let (words, _) = block.as_chunks::<4>();
    for (w, word) in w.iter_mut().zip(words) {
        *w = u32::from_be_bytes(*word);
    }

    // W[t] = ROTL1(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]),
    // with all W indices reduced mod 16 into our window.
    macro_rules! w {
        ($t:expr) => {{
            let t = $t;
            if t >= 16 {
                w[t & 15] = (w[(t + 13) & 15] ^ w[(t + 8) & 15] ^ w[(t + 2) & 15] ^ w[t & 15])
                    .rotate_left(1);
            }
            w[t & 15]
        }};
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;

    // Five rounds from `$t`.  Rather than shifting a..e along after every
    // round, each round renames them, so the names line up again after five.
    macro_rules! rounds5 {
        ($f:ident, $k:literal, $t:expr) => {
            let t = $t;
            e = e
                .wrapping_add(a.rotate_left(5))
                .wrapping_add($f!(b, c, d))
                .wrapping_add($k)
                .wrapping_add(w!(t));
            b = b.rotate_left(30);
            d = d
                .wrapping_add(e.rotate_left(5))
                .wrapping_add($f!(a, b, c))
                .wrapping_add($k)
                .wrapping_add(w!(t + 1));
            a = a.rotate_left(30);
            c = c
                .wrapping_add(d.rotate_left(5))
                .wrapping_add($f!(e, a, b))
                .wrapping_add($k)
                .wrapping_add(w!(t + 2));
            e = e.rotate_left(30);
            b = b
                .wrapping_add(c.rotate_left(5))
                .wrapping_add($f!(d, e, a))
                .wrapping_add($k)
                .wrapping_add(w!(t + 3));
            d = d.rotate_left(30);
            a = a
                .wrapping_add(b.rotate_left(5))
                .wrapping_add($f!(c, d, e))
                .wrapping_add($k)
                .wrapping_add(w!(t + 4));
            c = c.rotate_left(30);
        };
    }

    for t in (0..20).step_by(5) {
        rounds5!(CH, 0x5a827999, t);
    }
    for t in (20..40).step_by(5) {
        rounds5!(PARITY, 0x6ed9eba1, t);
    }
    for t in (40..60).step_by(5) {
        rounds5!(MAJ, 0x8f1bbcdc, t);
    }
    for t in (60..80).step_by(5) {
        rounds5!(PARITY, 0xca62c1d6, t);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

pub(crate) fn sha1_compress_blocks(state: &mut [u32; 5], blocks: &[u8]) {
    debug_assert!(blocks.len().is_multiple_of(64));

    // W holds the hashed input, which may be a secret such as an HMAC key.
    let mut w = [0u32; 16];
    let (chunks, _) = blocks.as_chunks::<64>();
    for block in chunks {
        sha1_compress_block(state, block, &mut w);
    }
    zeroise(&mut w);
}
