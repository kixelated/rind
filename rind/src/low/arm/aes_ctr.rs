// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::low::AesKey;

/// XORs eight blocks of AES-CTR keystream into `inout`.
///
/// The counter blocks are `nonce` followed by the big-endian `counter`,
/// `counter + 1`, ... `counter + 7`, wrapping within 32 bits.
pub(crate) fn apply_8(key: &AesKey, nonce: &[u8; 12], counter: u32, inout: &mut [u8; 128]) {
    let mut keystream = [0u8; 16];
    for (i, block) in (0u32..).zip(inout.as_chunks_mut::<16>().0) {
        keystream[..12].copy_from_slice(nonce);
        keystream[12..].copy_from_slice(&counter.wrapping_add(i).to_be_bytes());
        key.encrypt_block(&mut keystream);
        for (b, k) in block.iter_mut().zip(keystream) {
            *b ^= k;
        }
    }
}
