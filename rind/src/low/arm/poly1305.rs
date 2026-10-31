// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! Poly1305 with aws-lc's NEON code where the CPU has NEON, and HACL*'s
//! verified streaming `Hacl_MAC_Poly1305`, as libcrux-poly1305 ships it,
//! otherwise.

use libcrux_hacl_rs::streaming_types::error_code;
use libcrux_poly1305::hacl::mac_poly1305::{self, state_t};

use super::cpu::HaveNeon;
use super::poly1305_arm::Poly1305Neon;
use crate::low::zeroise;

pub(crate) enum Poly1305 {
    Neon(Poly1305Neon),
    Portable(Hacl),
}

impl Poly1305 {
    pub(crate) fn new(key: &[u8; 32]) -> Self {
        match HaveNeon::check() {
            Some(token) => Self::Neon(Poly1305Neon::new(key, token)),
            None => Self::Portable(Hacl::new(key)),
        }
    }

    pub(crate) fn add_bytes(&mut self, bytes: &[u8]) {
        match self {
            Self::Neon(p) => p.add_bytes(bytes),
            Self::Portable(p) => p.add_bytes(bytes),
        }
    }

    pub(crate) fn finish(self) -> [u8; 16] {
        match self {
            Self::Neon(p) => p.finish(),
            Self::Portable(p) => p.finish(),
        }
    }
}

pub(crate) struct Hacl([state_t; 1]);

impl Hacl {
    fn new(key: &[u8; 32]) -> Self {
        let mut state = [state_t {
            block_state: [0; 25],
            buf: [0; 16],
            total_len: 0,
            p_key: [0; 32],
        }];
        mac_poly1305::reset(&mut state, key);
        Self(state)
    }

    fn add_bytes(&mut self, bytes: &[u8]) {
        // `usize` is 32 bits here. HACL refuses more than `u32::MAX` bytes in
        // total, which the AEADs cannot reach: their AAD and message are
        // disjoint slices in the same address space as this state, plus at
        // most 46 bytes of padding and lengths.
        let result = mac_poly1305::update(&mut self.0, bytes, bytes.len() as u32);
        assert!(result == error_code::Success, "Poly1305 input fits 32 bits");
    }

    fn finish(self) -> [u8; 16] {
        let mut tag = [0u8; 16];
        mac_poly1305::digest(&self.0, &mut tag);
        tag
    }
}

impl Drop for Hacl {
    fn drop(&mut self) {
        let state = &mut self.0[0];
        zeroise(&mut state.block_state);
        zeroise(&mut state.p_key);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::low::ct;

    // Every other test sees only the path the CPU picks, so the NEON code is
    // checked against HACL*'s here: every length up to 200 bytes, plus some
    // past the assembly's 64-byte and 32-byte loops, each fed whole and in
    // ragged pieces that cross its 32-byte buffer. The key and message are
    // secret, so under `admin/ctgrind` this also checks both are constant
    // time in them.
    #[test]
    fn neon_matches_portable() {
        let Some(token) = HaveNeon::check() else {
            return;
        };
        let key: [u8; 32] = core::array::from_fn(|i| 0xa5 ^ (i as u8).wrapping_mul(29));
        let msg: Vec<u8> = (0..1100u32)
            .map(|i| (i.wrapping_mul(0x9e3779b9) >> 24) as u8)
            .collect();
        ct::secret_slice(&key);
        ct::secret_slice(&msg);
        for len in (0..=200).chain([255, 256, 257, 1023, 1024, 1025, 1100]) {
            let msg = &msg[..len];
            let mut want = Hacl::new(&key);
            want.add_bytes(msg);
            let want = ct::into_public(want.finish());

            for piece in [len.max(1), 1, 7, 16, 31, 32, 33, 65] {
                let mut got = Poly1305Neon::new(&key, token);
                for chunk in msg.chunks(piece) {
                    got.add_bytes(chunk);
                }
                assert_eq!(
                    ct::into_public(got.finish()),
                    want,
                    "{len} bytes in pieces of {piece}"
                );
            }
        }

        // All-ones blocks and key push the accumulator to its largest values
        // before the final reduction.
        let ones = [0xff; 32];
        let msg = [0xff; 1100];
        for len in [16, 17, 32, 64, 1100] {
            let mut want = Hacl::new(&ones);
            want.add_bytes(&msg[..len]);
            let mut got = Poly1305Neon::new(&ones, token);
            got.add_bytes(&msg[..len]);
            assert_eq!(
                ct::into_public(got.finish()),
                ct::into_public(want.finish()),
                "{len} bytes of ones"
            );
        }
    }
}
