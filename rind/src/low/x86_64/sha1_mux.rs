// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::low::x86_64;

pub(crate) fn sha1_compress_blocks(state: &mut [u32; 5], blocks: &[u8]) {
    if let Some(token) = x86_64::cpu::HaveSha1::check() {
        x86_64::sha1::sha1_compress_blocks_shaext(state, blocks, token)
    } else {
        x86_64::sha1::sha1_compress_blocks_avx2(state, blocks)
    }
}
