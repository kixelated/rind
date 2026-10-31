// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! aws-lc's x86_64 AES-GCM: its AES-NI and AVX stitched CTR and GHASH,
//! its GHASH, and its counter mode, imported by `admin/import-aws-lc-x86_64`.
//!
//! aws-lc's own CI proves these routines with SAW, for AES-256 on CPUs
//! without AVX-512: see `rind/README.md`'s Sources.
//!
//! They follow the System V calling convention on every target, so Windows
//! calls them as `sysv64`, saving the vector registers its own convention
//! preserves. None of them reads or writes below the stack pointer, where
//! Windows has no red zone.

use super::aes::AesKey;

// The assembly reads `AesKey`'s `__m128i` round keys as the 16-byte blocks
// they are.
#[expect(improper_ctypes)]
unsafe extern "sysv64" {
    #[link_name = aws_lc_symbol!("aesni_gcm_encrypt")]
    pub(super) fn aesni_gcm_encrypt(
        input: *const u8,
        output: *mut u8,
        len: usize,
        key: *const AesKey,
        ivec: *mut [u8; 16],
        htable: *const Htable,
        xi: *mut [u8; 16],
    ) -> usize;

    #[link_name = aws_lc_symbol!("aesni_gcm_decrypt")]
    pub(super) fn aesni_gcm_decrypt(
        input: *const u8,
        output: *mut u8,
        len: usize,
        key: *const AesKey,
        ivec: *mut [u8; 16],
        htable: *const Htable,
        xi: *mut [u8; 16],
    ) -> usize;

    #[link_name = aws_lc_symbol!("gcm_init_avx")]
    pub(super) fn gcm_init_avx(htable: *mut Htable, h: *const [u64; 2]);

    #[link_name = aws_lc_symbol!("gcm_ghash_avx")]
    pub(super) fn gcm_ghash_avx(
        xi: *mut [u8; 16],
        htable: *const Htable,
        input: *const u8,
        len: usize,
    );

    #[link_name = aws_lc_symbol!("aes_hw_ctr32_encrypt_blocks")]
    pub(super) fn aes_hw_ctr32_encrypt_blocks(
        input: *const u8,
        output: *mut u8,
        blocks: usize,
        key: *const AesKey,
        ivec: *const [u8; 16],
    );
}

core::arch::global_asm!(
    ".text",
    include_str!("aws_lc/aesni-gcm-x86_64.s"),
    aesni_gcm_encrypt = sym aesni_gcm_encrypt,
    aesni_gcm_decrypt = sym aesni_gcm_decrypt,
    options(att_syntax),
);

core::arch::global_asm!(
    ".text",
    include_str!("aws_lc/ghash-x86_64.s"),
    gcm_init_avx = sym gcm_init_avx,
    gcm_ghash_avx = sym gcm_ghash_avx,
    options(att_syntax),
);

core::arch::global_asm!(
    ".text",
    include_str!("aws_lc/aesni-x86_64.s"),
    aes_hw_ctr32_encrypt_blocks = sym aes_hw_ctr32_encrypt_blocks,
    options(att_syntax),
);

/// Powers of a GHASH key, for `gcm_ghash_avx` and `aesni_gcm_*`: aws-lc's
/// `u128 Htable[16]`.
#[repr(C, align(16))]
pub(crate) struct Htable(pub(super) [[u64; 2]; 16]);
