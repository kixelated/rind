// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::aes128_gcm_dec::aes128_gcm_dec;
use super::aes128_gcm_enc::aes128_gcm_enc;
use super::aes256_gcm_dec::aes256_gcm_dec;
use super::aes256_gcm_enc::aes256_gcm_enc;
use crate::low::AesKey;
use crate::low::ghash::Ghash;

pub(crate) fn encrypt(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    initial_counter: &[u8; 16],
    aad: &[u8],
    cipher_inout: &mut [u8],
) {
    cipher::<true>(key, ghash, initial_counter, aad, cipher_inout)
}

pub(crate) fn decrypt(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    initial_counter: &[u8; 16],
    aad: &[u8],
    cipher_inout: &mut [u8],
) {
    cipher::<false>(key, ghash, initial_counter, aad, cipher_inout)
}

/// Blocks copied aside per call of the s2n-bignum kernels.
///
/// Their proofs require the input and output not to overlap, so in-place
/// operation goes through this bounce buffer. Each call fills and drains the
/// kernel's pipeline: on Neoverse N2, 64 blocks ran 16 KiB 5% faster than 32
/// and 11% faster than 16.
const CHUNK_BLOCKS: usize = 64;

// AES-GCM encrypt (if `ENC` is `true`) or decrypt.
fn cipher<const ENC: bool>(
    key: &AesKey,
    ghash: &mut Ghash<'_>,
    initial_counter: &[u8; 16],
    aad: &[u8],
    cipher_inout: &mut [u8],
) {
    ghash.add(aad);

    let mut counter = *initial_counter;
    inc32(&mut counter);

    let (blocks, remainder) = cipher_inout.as_chunks_mut::<16>();

    if !blocks.is_empty() {
        let mut tag = ghash.state();
        let mut bounce = [[0u8; 16]; CHUNK_BLOCKS];

        for chunk in blocks.chunks_mut(CHUNK_BLOCKS) {
            let input = &mut bounce[..chunk.len()];
            input.copy_from_slice(chunk);

            let htable = &ghash.table.htable;
            // SAFETY: this crate requires the `aes` cpu feature
            unsafe {
                match (key, ENC) {
                    (AesKey::Aes128(k), true) => {
                        aes128_gcm_enc(input, chunk, &mut tag, &mut counter, k.round_keys(), htable)
                    }
                    (AesKey::Aes128(k), false) => {
                        aes128_gcm_dec(input, chunk, &mut tag, &mut counter, k.round_keys(), htable)
                    }
                    (AesKey::Aes256(k), true) => {
                        aes256_gcm_enc(input, chunk, &mut tag, &mut counter, k.round_keys(), htable)
                    }
                    (AesKey::Aes256(k), false) => {
                        aes256_gcm_dec(input, chunk, &mut tag, &mut counter, k.round_keys(), htable)
                    }
                }
            }
        }

        ghash.set_state(tag);
    }

    if !remainder.is_empty() {
        if !ENC {
            ghash.add(remainder);
        }

        let mut keystream = counter;
        key.encrypt_block(&mut keystream);
        for (c, k) in remainder.iter_mut().zip(keystream) {
            *c ^= k;
        }

        if ENC {
            ghash.add(remainder);
        }
    }
}

/// Increments the big-endian 32-bit counter in the last four bytes of `block`.
fn inc32(block: &mut [u8; 16]) {
    let b = u128::from_be_bytes(*block);
    let ctr = (b as u32).wrapping_add(1);
    *block = (b & !0xffff_ffff | ctr as u128).to_be_bytes();
}
