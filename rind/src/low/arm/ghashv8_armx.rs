// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! GHASH with the AArch32 crypto extension's PMULL, using aws-lc's
//! `ghashv8-armx` routines.
//!
//! The assembly is aws-lc's, imported by `admin/import-aws-lc-arm`. It is not
//! formally verified: its correctness rests on its use and testing in OpenSSL,
//! BoringSSL, and aws-lc, and on rind's tests of it against the portable code,
//! Wycheproof, and aws-lc-rs.

use super::cpu::HaveCryptoExt;
use crate::low;

unsafe extern "C" {
    #[link_name = aws_lc_symbol!("gcm_init_v8")]
    fn gcm_init_v8(htable: *mut GhashTable, h: *const [u64; 2]);

    #[link_name = aws_lc_symbol!("gcm_ghash_v8")]
    fn gcm_ghash_v8(xi: *mut [u8; 16], htable: *const GhashTable, input: *const u8, len: usize);
}

// As in `aesv8_armx`: ARM mode with NEON, then the target's `.fpu` again.
core::arch::global_asm!(
    ".text",
    ".fpu neon",
    ".code 32",
    include_str!("aws_lc/ghashv8-armx.s"),
    ".fpu vfpv3",
    gcm_init_v8 = sym gcm_init_v8,
    gcm_ghash_v8 = sym gcm_ghash_v8,
);

/// Powers of a GHASH key: aws-lc's `u128 Htable[16]`.
#[repr(C, align(16))]
pub(crate) struct GhashTable([[u64; 2]; 16]);

impl GhashTable {
    /// Precomputes for the GHASH key `h`, AES's encryption of the zero block.
    pub(crate) fn new(h: &[u8; 16], _: HaveCryptoExt) -> Self {
        let (hi, lo) = h.split_at(8);
        let h = [
            u64::from_be_bytes(hi.try_into().unwrap()),
            u64::from_be_bytes(lo.try_into().unwrap()),
        ];
        let mut r = Self([[0; 2]; 16]);
        // SAFETY: `r` is an `Htable` and `h` two words. The token proves the
        // CPU has PMULL.
        unsafe { gcm_init_v8(&mut r, &h) };
        r
    }

    /// Folds whole blocks of `input` into the GHASH state `xi`.
    pub(crate) fn ghash(&self, xi: &mut [u8; 16], input: &[[u8; 16]]) {
        // aws-lc loads the first block before checking the length.
        if input.is_empty() {
            return;
        }
        // SAFETY: `input` is `size_of_val(input)` readable bytes, a multiple
        // of 16. Only a `HaveCryptoExt` token builds `self`.
        unsafe { gcm_ghash_v8(xi, self, input.as_ptr().cast(), size_of_val(input)) }
    }
}

impl Drop for GhashTable {
    fn drop(&mut self) {
        low::zeroise_value(self);
    }
}

impl low::generic::zeroise::Zeroable for GhashTable {}
