// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::aarch64::*;

use super::aes::{_aes128_8_blocks, _aes256_8_blocks};
use crate::low::AesKey;

/// XORs eight blocks of AES-CTR keystream into `inout`.
///
/// The counter blocks are `nonce` followed by the big-endian `counter`,
/// `counter + 1`, ... `counter + 7`, wrapping within 32 bits.
pub(crate) fn apply_8(key: &AesKey, nonce: &[u8; 12], counter: u32, inout: &mut [u8; 128]) {
    // SAFETY: this crate requires the `aes` & `neon` cpu features
    unsafe { _apply_8(key, nonce, counter, inout) }
}

#[target_feature(enable = "aes,neon")]
fn _apply_8(key: &AesKey, nonce: &[u8; 12], counter: u32, inout: &mut [u8; 128]) {
    let mut base = [0u8; 16];
    base[..12].copy_from_slice(nonce);
    // SAFETY: `base` is 16 bytes and readable
    let base = vreinterpretq_u32_u8(unsafe { vld1q_u8(base.as_ptr()) });
    // lane 3 holds bytes 12..16 little-endian, so swap to store big-endian
    let block = |i: u32| {
        vreinterpretq_u8_u32(vsetq_lane_u32::<3>(
            counter.wrapping_add(i).swap_bytes(),
            base,
        ))
    };

    let (b0, b1, b2, b3, b4, b5, b6, b7) = (
        block(0),
        block(1),
        block(2),
        block(3),
        block(4),
        block(5),
        block(6),
        block(7),
    );
    let (b0, b1, b2, b3, b4, b5, b6, b7) = match key {
        AesKey::Aes128(a128) => _aes128_8_blocks(a128.round_keys(), b0, b1, b2, b3, b4, b5, b6, b7),
        AesKey::Aes256(a256) => _aes256_8_blocks(a256.round_keys(), b0, b1, b2, b3, b4, b5, b6, b7),
    };

    // SAFETY: `inout` is 128 bytes, readable and writable
    unsafe {
        let p = inout.as_mut_ptr();
        vst1q_u8(p.add(0), veorq_u8(b0, vld1q_u8(p.add(0))));
        vst1q_u8(p.add(16), veorq_u8(b1, vld1q_u8(p.add(16))));
        vst1q_u8(p.add(32), veorq_u8(b2, vld1q_u8(p.add(32))));
        vst1q_u8(p.add(48), veorq_u8(b3, vld1q_u8(p.add(48))));
        vst1q_u8(p.add(64), veorq_u8(b4, vld1q_u8(p.add(64))));
        vst1q_u8(p.add(80), veorq_u8(b5, vld1q_u8(p.add(80))));
        vst1q_u8(p.add(96), veorq_u8(b6, vld1q_u8(p.add(96))));
        vst1q_u8(p.add(112), veorq_u8(b7, vld1q_u8(p.add(112))));
    }
}
