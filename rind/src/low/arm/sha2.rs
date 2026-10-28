// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! SHA-2 compression over HACL*'s `Hash_SHA2`, sharing rind's padding and
//! buffering in `mid::sha2`.

use libcrux_sha2::hacl;

/// Compress whole 64-byte `blocks` into `state`.
pub(crate) fn sha256_compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    debug_assert_eq!(blocks.len() % 64, 0);
    // `usize` is 32 bits here, so the length always fits.
    hacl::sha256_update_nblocks(blocks.len() as u32, blocks, state);
}

/// Compress whole 128-byte `blocks` into `state`.
pub(crate) fn sha512_compress_blocks(state: &mut [u64; 8], blocks: &[u8]) {
    debug_assert_eq!(blocks.len() % 128, 0);
    hacl::sha512_update_nblocks(blocks.len() as u32, blocks, state);
}
