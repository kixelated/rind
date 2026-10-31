// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! AES with the AArch32 crypto extension, using aws-lc's `aesv8-armx` routines.
//!
//! The assembly is aws-lc's, imported by `admin/import-aws-lc`. It is not
//! formally verified: its correctness rests on its use and testing in OpenSSL,
//! BoringSSL, and aws-lc, and on rind's tests of it against the portable code,
//! Wycheproof, and aws-lc-rs.

use super::cpu::HaveCryptoExt;
use crate::low;

unsafe extern "C" {
    #[link_name = aws_lc_symbol!("aes_hw_set_encrypt_key")]
    fn aes_hw_set_encrypt_key(user_key: *const u8, bits: i32, key: *mut AesHwKey) -> i32;

    #[link_name = aws_lc_symbol!("aes_hw_encrypt")]
    fn aes_hw_encrypt(input: *const u8, output: *mut u8, key: *const AesHwKey);

    #[link_name = aws_lc_symbol!("aes_hw_ctr32_encrypt_blocks")]
    fn aes_hw_ctr32_encrypt_blocks(
        input: *const u8,
        output: *mut u8,
        blocks: usize,
        key: *const AesHwKey,
        ivec: *const [u8; 16],
    );
}

// aws-lc assembles these in ARM mode with NEON, encoding the ARMv8
// instructions as bytes. Restoring `.fpu` afterwards keeps the object's build
// attributes at the target's ARMv7 VFPv3, rather than marking it as needing
// NEON.
core::arch::global_asm!(
    ".text",
    ".fpu neon",
    ".code 32",
    include_str!("aws_lc/aesv8-armx.s"),
    ".fpu vfpv3",
    aes_hw_set_encrypt_key = sym aes_hw_set_encrypt_key,
    aes_hw_encrypt = sym aes_hw_encrypt,
    aes_hw_ctr32_encrypt_blocks = sym aes_hw_ctr32_encrypt_blocks,
);

/// An expanded AES-128 or AES-256 encryption key: aws-lc's `AES_KEY`.
#[repr(C, align(16))]
pub(crate) struct AesHwKey {
    rd_key: [u32; 60],
    rounds: u32,
}

impl AesHwKey {
    /// Expands a 16- or 32-byte key.
    pub(crate) fn new(key: &[u8], _: HaveCryptoExt) -> Self {
        let bits = match key.len() {
            16 => 128,
            32 => 256,
            _ => unreachable!("callers check the AES key length"),
        };
        let mut r = Self {
            rd_key: [0; 60],
            rounds: 0,
        };
        // SAFETY: `key` holds `bits / 8` bytes and `r` is an `AES_KEY`. The
        // token proves the CPU has the AES instructions.
        let ret = unsafe { aes_hw_set_encrypt_key(key.as_ptr(), bits, &mut r) };
        // aws-lc refuses only a null pointer or another key size.
        debug_assert_eq!(ret, 0);
        r
    }

    /// Encrypts one block in place.
    pub(crate) fn encrypt_block(&self, inout: &mut [u8; 16]) {
        // SAFETY: `inout` is one readable and writable block, which aws-lc
        // allows to alias. Only a `HaveCryptoExt` token builds `self`.
        unsafe { aes_hw_encrypt(inout.as_ptr(), inout.as_mut_ptr(), self) }
    }

    /// XORs counter-mode keystream into whole blocks.
    ///
    /// The counter blocks are `ivec`, then `ivec` with its last four bytes,
    /// a big-endian counter, incremented with 32-bit wrapping.
    pub(crate) fn ctr32(&self, ivec: &[u8; 16], inout: &mut [[u8; 16]]) {
        // SAFETY: `inout` is `inout.len()` readable and writable blocks, which
        // aws-lc allows to alias. Only a `HaveCryptoExt` token builds `self`.
        unsafe {
            aes_hw_ctr32_encrypt_blocks(
                inout.as_ptr().cast(),
                inout.as_mut_ptr().cast(),
                inout.len(),
                self,
                ivec,
            )
        }
    }
}

impl Drop for AesHwKey {
    fn drop(&mut self) {
        low::zeroise_value(self);
    }
}

impl low::generic::zeroise::Zeroable for AesHwKey {}
