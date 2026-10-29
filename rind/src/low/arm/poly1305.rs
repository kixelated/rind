// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! Poly1305 over HACL*'s verified streaming `Hacl_MAC_Poly1305`, as
//! libcrux-poly1305 ships it.

use libcrux_hacl_rs::streaming_types::error_code;
use libcrux_poly1305::hacl::mac_poly1305::{self, state_t};

use crate::low::zeroise;

pub(crate) struct Poly1305([state_t; 1]);

impl Poly1305 {
    pub(crate) fn new(key: &[u8; 32]) -> Self {
        let mut state = [state_t {
            block_state: [0; 25],
            buf: [0; 16],
            total_len: 0,
            p_key: [0; 32],
        }];
        mac_poly1305::reset(&mut state, key);
        Self(state)
    }

    pub(crate) fn add_bytes(&mut self, bytes: &[u8]) {
        // `usize` is 32 bits here. HACL refuses more than `u32::MAX` bytes in
        // total, which the AEADs cannot reach: their AAD and message are
        // disjoint slices in the same address space as this state, plus at
        // most 46 bytes of padding and lengths.
        let result = mac_poly1305::update(&mut self.0, bytes, bytes.len() as u32);
        assert!(result == error_code::Success, "Poly1305 input fits 32 bits");
    }

    pub(crate) fn finish(self) -> [u8; 16] {
        let mut tag = [0u8; 16];
        mac_poly1305::digest(&self.0, &mut tag);
        tag
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        let state = &mut self.0[0];
        zeroise(&mut state.block_state);
        zeroise(&mut state.buf);
        zeroise(&mut state.p_key);
    }
}
