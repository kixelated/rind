// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! SHA-1 and SHA-256 compression with the AArch32 crypto extension where the
//! CPU has it, using aws-lc's `sha1-armv4-large` and `sha256-armv4` routines,
//! and rind's portable code otherwise. SHA-512 compression with aws-lc's
//! `sha512-armv4` routines: NEON where the CPU has it, and scalar code
//! otherwise.
//!
//! The assembly is aws-lc's, imported by `admin/import-aws-lc`. It is not
//! formally verified: its correctness rests on its use and testing in OpenSSL,
//! BoringSSL, and aws-lc, and on rind's tests of it against the portable code,
//! CAVP, and aws-lc-rs.

use super::cpu::{HaveCryptoExt, HaveNeon};
use crate::low::generic;

unsafe extern "C" {
    #[link_name = aws_lc_symbol!("sha1_block_data_order_hw")]
    fn sha1_block_data_order_hw(state: *mut [u32; 5], data: *const u8, blocks: usize);

    #[link_name = aws_lc_symbol!("sha256_block_data_order_hw")]
    fn sha256_block_data_order_hw(state: *mut [u32; 8], data: *const u8, blocks: usize);

    #[link_name = aws_lc_symbol!("sha512_block_data_order_nohw")]
    fn sha512_block_data_order_nohw(state: *mut [u64; 8], data: *const u8, blocks: usize);

    #[link_name = aws_lc_symbol!("sha512_block_data_order_neon")]
    fn sha512_block_data_order_neon(state: *mut [u64; 8], data: *const u8, blocks: usize);
}

// As in `aesv8_armx`: ARM mode with NEON, then the target's `.fpu` again.
core::arch::global_asm!(
    ".text",
    ".fpu neon",
    ".code 32",
    include_str!("aws_lc/sha1-armv4-large.s"),
    include_str!("aws_lc/sha256-armv4.s"),
    include_str!("aws_lc/sha512-armv4.s"),
    ".fpu vfpv3",
    sha1_block_data_order_hw = sym sha1_block_data_order_hw,
    sha256_block_data_order_hw = sym sha256_block_data_order_hw,
    sha512_block_data_order_nohw = sym sha512_block_data_order_nohw,
    sha512_block_data_order_neon = sym sha512_block_data_order_neon,
);

pub(crate) fn sha1_compress_blocks(state: &mut [u32; 5], blocks: &[u8]) {
    debug_assert!(blocks.len().is_multiple_of(64));
    match HaveCryptoExt::check() {
        // Both routines run their loop at least once, so zero blocks would
        // read past `blocks`.
        Some(_) if !blocks.is_empty() => {
            // SAFETY: `blocks` is `blocks.len() / 64` readable blocks, and the
            // token proves the CPU has the SHA-1 instructions.
            unsafe { sha1_block_data_order_hw(state, blocks.as_ptr(), blocks.len() / 64) }
        }
        Some(_) => {}
        None => generic::sha1::sha1_compress_blocks(state, blocks),
    }
}

pub(crate) fn sha256_compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    debug_assert!(blocks.len().is_multiple_of(64));
    match HaveCryptoExt::check() {
        Some(_) if !blocks.is_empty() => {
            // SAFETY: `blocks` is `blocks.len() / 64` readable blocks, and the
            // token proves the CPU has the SHA-256 instructions.
            unsafe { sha256_block_data_order_hw(state, blocks.as_ptr(), blocks.len() / 64) }
        }
        Some(_) => {}
        None => generic::sha256::sha256_compress_blocks(state, blocks),
    }
}

pub(crate) fn sha512_compress_blocks(state: &mut [u64; 8], blocks: &[u8]) {
    debug_assert!(blocks.len().is_multiple_of(128));
    // Both routines run their loop at least once, so zero blocks would read
    // past `blocks`.
    if blocks.is_empty() {
        return;
    }
    let (data, num) = (blocks.as_ptr(), blocks.len() / 128);
    match HaveNeon::check() {
        // SAFETY: `blocks` is `num` readable blocks, and the token proves the
        // CPU has NEON.
        Some(_) => unsafe { sha512_block_data_order_neon(state, data, num) },
        // SAFETY: `blocks` is `num` readable blocks.
        None => unsafe { sha512_block_data_order_nohw(state, data, num) },
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    // Every other test sees only the path the CPU picks, so the crypto
    // extension's SHA is checked against the portable code here: odd and even
    // block counts, with distinct bytes in every block.
    #[test]
    fn hw_matches_portable() {
        if HaveCryptoExt::check().is_none() {
            return;
        }
        let blocks: Vec<u8> = (0..5 * 64u32)
            .map(|i| (i.wrapping_mul(0x9e3779b9) >> 24) as u8)
            .collect();
        for n in 1..=5 {
            let blocks = &blocks[..n * 64];

            let mut want = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
            let mut got = want;
            generic::sha1::sha1_compress_blocks(&mut want, blocks);
            // SAFETY: `blocks` is `n` blocks, and the CPU has the extension.
            unsafe { sha1_block_data_order_hw(&mut got, blocks.as_ptr(), n) };
            assert_eq!(got, want, "sha1, {n} blocks");

            let mut want = [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ];
            let mut got = want;
            generic::sha256::sha256_compress_blocks(&mut want, blocks);
            // SAFETY: as above.
            unsafe { sha256_block_data_order_hw(&mut got, blocks.as_ptr(), n) };
            assert_eq!(got, want, "sha256, {n} blocks");
        }
    }

    // Likewise for SHA-512's two routines, against each other.
    #[test]
    fn sha512_neon_matches_nohw() {
        if HaveNeon::check().is_none() {
            return;
        }
        let blocks: Vec<u8> = (0..5 * 128u32)
            .map(|i| (i.wrapping_mul(0x9e3779b9) >> 24) as u8)
            .collect();
        for n in 1..=5 {
            let mut want = [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ];
            let mut got = want;
            // SAFETY: `blocks` holds at least `n` blocks, and the CPU has NEON.
            unsafe {
                sha512_block_data_order_nohw(&mut want, blocks.as_ptr(), n);
                sha512_block_data_order_neon(&mut got, blocks.as_ptr(), n);
            }
            assert_eq!(got, want, "{n} blocks");
        }
    }
}
