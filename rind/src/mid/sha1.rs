// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! SHA1, for legacy protocols only.
//!
//! SHA1 is described in [FIPS180](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
//! Its collision resistance is broken, so it must not be used where that
//! matters, such as in signatures.

use crate::low::Blockwise;
use crate::low::cpu::verify_cpu_features;

/// A context for incremental computation of SHA1.
#[derive(Clone)]
pub(crate) struct Sha1Context {
    h: [u32; 5],
    blockwise: Blockwise<{ Self::BLOCK_SZ }>,
    nblocks: usize,
}

impl Sha1Context {
    /// Start a new SHA1 hash computation.
    pub(crate) const fn new() -> Self {
        Self {
            h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            blockwise: Blockwise::new(),
            nblocks: 0,
        }
    }

    /// Add `bytes` to the ongoing hash computation.
    pub(crate) fn update(&mut self, bytes: &[u8]) {
        if self.blockwise.used() == 0 && bytes.len().is_multiple_of(Self::BLOCK_SZ) {
            self.update_blocks(bytes);
            return;
        }

        let bytes = self.blockwise.add_leading(bytes);

        if let Some(block) = self.blockwise.take() {
            self.update_blocks(&block);
        }

        let (whole_blocks, remainder) = {
            let whole_len = bytes.len() - (bytes.len() & (Self::BLOCK_SZ - 1));
            (&bytes[..whole_len], &bytes[whole_len..])
        };

        self.update_blocks(whole_blocks);

        self.blockwise.add_trailing(remainder);
    }

    /// Complete the SHA1 computation, returning the hash output.
    pub(crate) fn finish(mut self) -> [u8; Self::OUTPUT_SZ] {
        let bytes = self
            .nblocks
            .checked_mul(Self::BLOCK_SZ)
            .and_then(|bytes| bytes.checked_add(self.blockwise.used()))
            .unwrap();

        let bits = bytes
            .checked_mul(8)
            .expect("excess data processed by hash function");

        let last_blocks = self
            .blockwise
            .md_pad_with_length(&(bits as u64).to_be_bytes());
        self.update_blocks(last_blocks.as_ref());

        let mut r = [0u8; Self::OUTPUT_SZ];
        let (chunks, _) = r.as_chunks_mut::<4>();
        for (out, state) in chunks.iter_mut().zip(self.h.iter()) {
            out.copy_from_slice(&state.to_be_bytes());
        }
        r
    }

    fn update_blocks(&mut self, blocks: &[u8]) {
        debug_assert!(blocks.len().is_multiple_of(Self::BLOCK_SZ));
        if !blocks.is_empty() {
            verify_cpu_features();
            crate::low::sha1_compress_blocks(&mut self.h, blocks);
            self.nblocks = self.nblocks.saturating_add(blocks.len() / Self::BLOCK_SZ);
        }
    }

    /// The internal block size of SHA1.
    pub(crate) const BLOCK_SZ: usize = 64;

    /// The output size of SHA1.
    pub(crate) const OUTPUT_SZ: usize = 20;
}
