// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! The ChaCha20 keystream past one block, using aws-lc's `chacha-armv4`
//! routines: NEON from 192 bytes where the CPU has it, as aws-lc chooses, and
//! the integer routine otherwise.
//!
//! The assembly is aws-lc's, imported by `admin/import-aws-lc-arm`. It is not
//! formally verified: its correctness rests on its use and testing in OpenSSL,
//! BoringSSL, and aws-lc, and on rind's tests of it against RFC 8439,
//! Wycheproof, and aws-lc-rs.

use super::cpu::HaveNeon;

unsafe extern "C" {
    #[link_name = aws_lc_symbol!("ChaCha20_ctr32_nohw")]
    fn ChaCha20_ctr32_nohw(
        out: *mut u8,
        input: *const u8,
        len: usize,
        key: *const u32,
        counter_nonce: *const u32,
    );

    #[link_name = aws_lc_symbol!("ChaCha20_ctr32_neon")]
    fn ChaCha20_ctr32_neon(
        out: *mut u8,
        input: *const u8,
        len: usize,
        key: *const u32,
        counter_nonce: *const u32,
    );
}

// As in `aesv8_armx`: ARM mode with NEON, then the target's `.fpu` again.
core::arch::global_asm!(
    ".text",
    ".fpu neon",
    ".code 32",
    include_str!("aws_lc/chacha-armv4.s"),
    ".fpu vfpv3",
    ChaCha20_ctr32_nohw = sym ChaCha20_ctr32_nohw,
    ChaCha20_ctr32_neon = sym ChaCha20_ctr32_neon,
);

/// Below this length aws-lc runs the integer routine even with NEON, which
/// computes three blocks at a time plus one in integer registers.
const NEON_MIN_LEN: usize = 192;

/// XORs the keystream for `state` into `buffer`.
///
/// `state` is the ChaCha20 input block: the constants, key, block counter,
/// and nonce. The routines' 32-bit counter wraps unspecified past 2^32
/// blocks, which callers rule out with `mid::chacha20::check_counter`.
pub(super) fn chacha20_ctr32(state: &[u32; 16], buffer: &mut [u8], neon: Option<HaveNeon>) {
    let len = buffer.len();
    // Both routines require at least one byte.
    if len == 0 {
        return;
    }
    let ptr = buffer.as_mut_ptr();
    let key = state[4..12].as_ptr();
    let counter_nonce = state[12..].as_ptr();
    match neon {
        // SAFETY: `buffer` is `len` readable and writable bytes, which the
        // routine allows to alias exactly, and `key` and `counter_nonce` are
        // 8 and 4 aligned words. The token proves NEON.
        Some(_) if len >= NEON_MIN_LEN => unsafe {
            ChaCha20_ctr32_neon(ptr, ptr, len, key, counter_nonce)
        },
        // SAFETY: as above; this routine needs only ARMv7.
        _ => unsafe { ChaCha20_ctr32_nohw(ptr, ptr, len, key, counter_nonce) },
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::low::ct;

    // Every other test sees only the routine the length picks, so NEON is
    // checked against the integer routine here: around its block and
    // three-block boundaries, and on to the last block before the counter
    // wraps. The key and input are secret, so under `admin/ctgrind` this also
    // checks both routines are constant time in them.
    #[test]
    fn neon_matches_nohw() {
        if HaveNeon::check().is_none() {
            return;
        }
        let key: [u32; 8] = core::array::from_fn(|i| 0x0101_0101u32.wrapping_mul(i as u32 + 1));
        let input: Vec<u8> = (0..1100u32)
            .map(|i| (i.wrapping_mul(0x9e3779b9) >> 24) as u8)
            .collect();
        ct::secret_slice(&key);
        ct::secret_slice(&input);
        for counter in [0, 1, u32::MAX - 16] {
            let counter_nonce = [counter, 0x4a00_0000, 0x0900_0000, 0x0700_0000];
            for len in (1..=320).chain([511, 512, 513, 1023, 1024, 1025, 1088]) {
                let mut want = input[..len].to_vec();
                let mut got = want.clone();
                // SAFETY: each buffer is `len` bytes, and the CPU has NEON.
                unsafe {
                    ChaCha20_ctr32_nohw(
                        want.as_mut_ptr(),
                        want.as_ptr(),
                        len,
                        key.as_ptr(),
                        counter_nonce.as_ptr(),
                    );
                    ChaCha20_ctr32_neon(
                        got.as_mut_ptr(),
                        got.as_ptr(),
                        len,
                        key.as_ptr(),
                        counter_nonce.as_ptr(),
                    );
                }
                ct::public_slice(&want);
                ct::public_slice(&got);
                assert_eq!(got, want, "counter {counter}, {len} bytes");
            }
        }
    }
}
