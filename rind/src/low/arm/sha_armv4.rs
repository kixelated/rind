// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! SHA-1 and SHA-256 compression with the AArch32 crypto extension where the
//! CPU has it, using aws-lc's `sha1-armv4-large` and `sha256-armv4` routines,
//! and rind's portable code otherwise.
//!
//! The assembly is aws-lc's, imported by `admin/import-aws-lc-arm`. It is not
//! formally verified: its correctness rests on its use and testing in OpenSSL,
//! BoringSSL, and aws-lc, and on rind's tests of it against the portable code,
//! CAVP, and aws-lc-rs.

use super::cpu::HaveCryptoExt;
use crate::low::generic;

// Each symbol carries rind's version, so two semver-incompatible copies of
// rind can link into one binary.
unsafe extern "C" {
    #[link_name = concat!("rind_", env!("CARGO_PKG_VERSION"), "_sha1_block_data_order_hw")]
    fn sha1_block_data_order_hw(state: *mut [u32; 5], data: *const u8, blocks: usize);

    #[link_name = concat!("rind_", env!("CARGO_PKG_VERSION"), "_sha256_block_data_order_hw")]
    fn sha256_block_data_order_hw(state: *mut [u32; 8], data: *const u8, blocks: usize);
}

// As in `aesv8_armx`: ARM mode with NEON, then the target's `.fpu` again.
core::arch::global_asm!(
    ".text",
    ".fpu neon",
    ".code 32",
    include_str!("aws_lc/sha1-armv4-large.s"),
    include_str!("aws_lc/sha256-armv4.s"),
    ".fpu vfpv3",
    sha1_block_data_order_hw = sym sha1_block_data_order_hw,
    sha256_block_data_order_hw = sym sha256_block_data_order_hw,
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
}
