// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! X25519 over curve25519-dalek, which clamps the scalar and masks the
//! point's top bit as RFC7748 requires.

use curve25519_dalek::montgomery::MontgomeryPoint;

// curve25519-dalek chooses its backend from cfgs that a build's RUSTFLAGS set
// for every crate, rind included, so refuse those that would replace the
// serial 32-bit backend it picks for this target.
#[cfg(any(curve25519_dalek_bits = "64", curve25519_dalek_backend = "fiat"))]
compile_error!(
    "rind runs curve25519-dalek's serial 32-bit backend on 32-bit ARM: \
     remove the curve25519_dalek_bits and curve25519_dalek_backend cfgs"
);

/// res := X25519(scalar, point), in little-endian words.
pub(crate) fn curve25519_x25519(res: &mut [u64; 4], scalar: &[u64; 4], point: &[u64; 4]) {
    let out = MontgomeryPoint(to_bytes(point)).mul_clamped(to_bytes(scalar));
    *res = from_bytes(&out.0);
}

/// res := X25519(scalar, 9), in little-endian words.
pub(crate) fn curve25519_x25519base(res: &mut [u64; 4], scalar: &[u64; 4]) {
    *res = from_bytes(&MontgomeryPoint::mul_base_clamped(to_bytes(scalar)).0);
}

fn to_bytes(words: &[u64; 4]) -> [u8; 32] {
    let mut r = [0u8; 32];
    for (chunk, word) in r.as_chunks_mut::<8>().0.iter_mut().zip(words) {
        *chunk = word.to_le_bytes();
    }
    r
}

fn from_bytes(bytes: &[u8; 32]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for (word, chunk) in r.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    r
}
