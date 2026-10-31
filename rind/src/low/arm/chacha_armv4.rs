// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! The ChaCha20 keystream, using aws-lc's `chacha-armv4` routines: NEON from
//! 192 bytes where the CPU has it, as aws-lc chooses, and the integer
//! routine otherwise.
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
        key: *const [u32; 8],
        counter_nonce: *const [u32; 4],
    );

    #[link_name = aws_lc_symbol!("ChaCha20_ctr32_neon")]
    fn ChaCha20_ctr32_neon(
        out: *mut u8,
        input: *const u8,
        len: usize,
        key: *const [u32; 8],
        counter_nonce: *const [u32; 4],
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

pub(crate) struct ChaCha20 {
    key: [u32; 8],
    /// The block counter, then the 96-bit nonce.
    counter_nonce: [u32; 4],
    neon: Option<HaveNeon>,
}

impl ChaCha20 {
    /// `nonce` is the little-endian block counter followed by the 96-bit nonce.
    pub(crate) fn new(key: &[u8; 32], nonce: &[u8; 16]) -> Self {
        let mut words = [0u32; 8];
        for (w, k) in words.iter_mut().zip(key.as_chunks::<4>().0) {
            *w = u32::from_le_bytes(*k);
        }
        let mut counter_nonce = [0u32; 4];
        for (w, n) in counter_nonce.iter_mut().zip(nonce.as_chunks::<4>().0) {
            *w = u32::from_le_bytes(*n);
        }
        Self {
            key: words,
            counter_nonce,
            neon: HaveNeon::check(),
        }
    }

    /// XORs the keystream into `buffer`, starting at the current block, then
    /// moves the counter past every block it touched.
    ///
    /// The routines' 32-bit counter wraps unspecified past 2^32 blocks, which
    /// callers rule out with `mid::chacha20::check_counter`.
    pub(crate) fn cipher(&mut self, buffer: &mut [u8]) {
        let len = buffer.len();
        // Both routines require at least one byte.
        if len == 0 {
            return;
        }
        let ptr = buffer.as_mut_ptr();
        match self.neon {
            // SAFETY: `buffer` is `len` readable and writable bytes, which the
            // routine allows to alias exactly. The token proves NEON.
            Some(_) if len >= NEON_MIN_LEN => unsafe {
                ChaCha20_ctr32_neon(ptr, ptr, len, &self.key, &self.counter_nonce)
            },
            // SAFETY: as above; this routine needs only ARMv7.
            _ => unsafe { ChaCha20_ctr32_nohw(ptr, ptr, len, &self.key, &self.counter_nonce) },
        }
        self.counter_nonce[0] = self.counter_nonce[0].wrapping_add(len.div_ceil(64) as u32);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    // Every other test sees only the routine the length picks, so NEON is
    // checked against the integer routine here: around its block and
    // three-block boundaries, and on to the last block before the counter
    // wraps.
    #[test]
    fn neon_matches_nohw() {
        if HaveNeon::check().is_none() {
            return;
        }
        let key: [u32; 8] = core::array::from_fn(|i| 0x0101_0101u32.wrapping_mul(i as u32 + 1));
        let input: Vec<u8> = (0..1100u32)
            .map(|i| (i.wrapping_mul(0x9e3779b9) >> 24) as u8)
            .collect();
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
                        &key,
                        &counter_nonce,
                    );
                    ChaCha20_ctr32_neon(got.as_mut_ptr(), got.as_ptr(), len, &key, &counter_nonce);
                }
                assert_eq!(got, want, "counter {counter}, {len} bytes");
            }
        }
    }
}
