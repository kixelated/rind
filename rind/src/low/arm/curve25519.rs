// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! X25519 over HACL*'s `Curve25519_51`, which clamps the scalar and
//! masks the point's top bit as RFC7748 requires.

use libcrux_hacl_rs::curve25519_51;

use crate::low::zeroise;

/// res := X25519(scalar, point), in little-endian words.
pub(crate) fn curve25519_x25519(res: &mut [u64; 4], scalar: &[u64; 4], point: &[u64; 4]) {
    let mut scalar = to_bytes(scalar);
    let mut out = [0u8; 32];
    curve25519_51::scalarmult(&mut out, &scalar, &to_bytes(point));
    *res = from_bytes(&out);
    zeroise(&mut scalar);
    zeroise(&mut out);
}

/// res := X25519(scalar, 9), in little-endian words.
pub(crate) fn curve25519_x25519base(res: &mut [u64; 4], scalar: &[u64; 4]) {
    let mut scalar = to_bytes(scalar);
    let mut out = [0u8; 32];
    curve25519_51::secret_to_public(&mut out, &scalar);
    *res = from_bytes(&out);
    zeroise(&mut scalar);
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
