// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! SHA-512 compression with aws-lc's `sha512_block_data_order_avx`, imported by
//! `admin/import-aws-lc`.
//!
//! aws-lc-verification's SAW proof covers this routine, as aws-lc builds it,
//! on CPUs with AVX, which rind requires on x86_64.

pub(crate) fn sha512_compress_blocks(state: &mut [u64; 8], blocks: &[u8]) {
    debug_assert!(blocks.len().is_multiple_of(128));
    // The routine runs its loop at least once, so zero blocks would read past
    // `blocks`.
    if blocks.is_empty() {
        return;
    }
    // SAFETY: `blocks` is `blocks.len() / 128` readable blocks, and rind
    // requires AVX on x86_64.
    unsafe { sha512_block_data_order_avx(state, blocks.as_ptr(), blocks.len() / 128) }
}

/// The round constants, each pair twice for the vector additions, then the
/// byte-swap mask, as the routine loads them.
#[repr(C, align(64))]
struct Table([u64; 164]);

static K512: Table = Table(include!("aws_lc/sha512-x86_64.K512.rs"));

/// The System V ABI on every OS, since the routine is aws-lc's ELF and Mach-O
/// text, which takes its arguments in the System V registers.
#[unsafe(naked)]
unsafe extern "sysv64" fn sha512_block_data_order_avx(
    state: *mut [u64; 8],
    data: *const u8,
    blocks: usize,
) {
    #[cfg(not(target_vendor = "apple"))]
    core::arch::naked_asm!(
        include_str!("aws_lc/sha512_block_data_order_avx.linux.s"),
        K512 = sym K512,
        options(att_syntax),
    );
    #[cfg(target_vendor = "apple")]
    core::arch::naked_asm!(
        include_str!("aws_lc/sha512_block_data_order_avx.apple.s"),
        K512 = sym K512,
        options(att_syntax),
    );
}
