// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

pub use crate::mid::aes::{Aes, AesCtr};
pub use crate::mid::chacha20::ChaCha20;

/// An AES key size, which fixes the key length a key must have.
#[derive(Debug)]
pub struct Algorithm {
    pub(crate) key_len: usize,
}

/// AES with a 16-byte key.
pub static AES_128: Algorithm = Algorithm { key_len: 16 };

/// AES with a 32-byte key.
pub static AES_256: Algorithm = Algorithm { key_len: 32 };
