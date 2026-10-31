// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use super::aes128_gcm_dec::aes128_gcm_dec;
use super::aes128_gcm_enc::aes128_gcm_enc;
use super::aes256_gcm_dec::aes256_gcm_dec;
use super::aes256_gcm_dec_alt::aes256_gcm_dec_alt;
use super::aes256_gcm_enc::aes256_gcm_enc;
use super::aes256_gcm_enc_alt::aes256_gcm_enc_alt;
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
        let htable = &ghash.table.htable;
        let [htable4 @ .., _, _, _, _, _, _] = htable;
        let (inout, len) = (blocks.as_mut_ptr(), blocks.len());
        // SAFETY: this crate requires the `aes` cpu feature, `eight_way`
        // proves `sha3`, and `inout` is valid for reads and writes of `len`
        // blocks. The kernels' proofs assume the input and output do not
        // overlap, but every path through them loads each input block before
        // storing its output block and never reads an output back, so in
        // place they compute the same.
        unsafe {
            match (key, ENC, ghash.table.eight_way) {
                (AesKey::Aes128(k), true, _) => {
                    aes128_gcm_enc(inout, len, &mut tag, &mut counter, k.round_keys(), htable4)
                }
                (AesKey::Aes128(k), false, _) => {
                    aes128_gcm_dec(inout, len, &mut tag, &mut counter, k.round_keys(), htable4)
                }
                (AesKey::Aes256(k), true, None) => {
                    aes256_gcm_enc(inout, len, &mut tag, &mut counter, k.round_keys(), htable4)
                }
                (AesKey::Aes256(k), false, None) => {
                    aes256_gcm_dec(inout, len, &mut tag, &mut counter, k.round_keys(), htable4)
                }
                (AesKey::Aes256(k), true, Some(_)) => {
                    aes256_gcm_enc_alt(inout, len, &mut tag, &mut counter, k.round_keys(), htable)
                }
                (AesKey::Aes256(k), false, Some(_)) => {
                    aes256_gcm_dec_alt(inout, len, &mut tag, &mut counter, k.round_keys(), htable)
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
