// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::Error;
use crate::low::{self, AesKey, Entry, zeroise};

/// An AES key that encrypts single blocks.
///
/// This is the bare block cipher. Use it only where a protocol specifies
/// AES on one block, such as QUIC header protection, DTLS 1.3 record number
/// protection, or SRTP key derivation.
pub struct Aes(AesKey);

impl Aes {
    /// Expands a 16- or 32-byte key into an AES-128 or AES-256 key.
    ///
    /// Any other length, including AES-192's 24 bytes, is an error.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        let _entry = Entry::new_secret();
        expand_key(key).map(Self)
    }

    /// Encrypts one block in place.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let _entry = Entry::new_secret();
        low::ct::secret_slice(block);
        self.0.encrypt_block(block);
        low::ct::public_slice(block);
    }
}

/// An AES key for counter mode, with a 96-bit nonce and a 32-bit block counter.
///
/// Each counter block is the nonce followed by the big-endian counter, as in
/// RFC 3686 and SRTP's AES-CM. Counter mode is unauthenticated, so pair it with
/// a MAC.
pub struct AesCtr(AesKey);

impl AesCtr {
    /// Expands a 16- or 32-byte key into an AES-128 or AES-256 key.
    ///
    /// Any other length, including AES-192's 24 bytes, is an error.
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        let _entry = Entry::new_secret();
        expand_key(key).map(Self)
    }

    /// XORs the keystream for `nonce`, starting at block `counter`, into `inout`.
    ///
    /// Encryption and decryption are the same operation. The nonce and counter
    /// are not secret.
    ///
    /// Fails with [`Error::WrongLength`], leaving `inout` unchanged, if `inout`
    /// needs more blocks than remain before the counter wraps: wrapping would
    /// repeat keystream.
    pub fn apply_keystream(
        &self,
        nonce: &[u8; 12],
        counter: u32,
        inout: &mut [u8],
    ) -> Result<(), Error> {
        let _entry = Entry::new_secret();
        if u64::from(counter) + inout.len().div_ceil(16) as u64 > 1 << 32 {
            return Err(Error::WrongLength);
        }
        low::ct::secret_slice(inout);

        // A short final chunk also takes the pipelined eight-block path: the
        // unused blocks cost less than encrypting it one serial block at a
        // time. Counters past the last used block may wrap; they are discarded.
        let (by8, tail) = inout.as_chunks_mut::<128>();
        let mut counter = counter;
        for chunk in by8 {
            low::aes_ctr::apply_8(&self.0, nonce, counter, chunk);
            counter = counter.wrapping_add(8);
        }

        if !tail.is_empty() {
            let mut buf = [0u8; 128];
            buf[..tail.len()].copy_from_slice(tail);
            low::aes_ctr::apply_8(&self.0, nonce, counter, &mut buf);
            tail.copy_from_slice(&buf[..tail.len()]);
            // the unused part is bare keystream
            zeroise(&mut buf);
        }

        low::ct::public_slice(inout);
        Ok(())
    }
}

fn expand_key(key: &[u8]) -> Result<AesKey, Error> {
    if !matches!(key.len(), 16 | 32) {
        return Err(Error::WrongLength);
    }

    // Mark a copy: the caller's buffer may be shared, or a promoted constant.
    let mut copy = [0u8; 32];
    let copy_key = &mut copy[..key.len()];
    copy_key.copy_from_slice(key);
    low::ct::secret_slice(copy_key);
    let expanded = AesKey::new(copy_key);
    zeroise(&mut copy);
    Ok(expanded)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::test::*;

    #[test]
    fn rejects_unsupported_key_lengths() {
        let key = [0u8; 33];
        for len in 0..=key.len() {
            let supported = len == 16 || len == 32;
            assert_eq!(Aes::new(&key[..len]).is_ok(), supported, "len {len}");
            assert_eq!(AesCtr::new(&key[..len]).is_ok(), supported, "len {len}");
        }
    }

    #[test]
    fn cavp() {
        #[derive(Default)]
        struct State {
            mct: bool,
            decrypt: bool,
            key: Vec<u8>,
            pt: Vec<u8>,
            ct: Vec<u8>,
        }

        impl State {
            fn check(&self) {
                // MCT decryption chains the inverse cipher, which this API lacks.
                if self.mct && self.decrypt {
                    return;
                }
                let aes = Aes::new(&self.key).unwrap();
                let mut block: [u8; 16] = self.pt[..].try_into().unwrap();
                for _ in 0..if self.mct { 1000 } else { 1 } {
                    aes.encrypt_block(&mut block);
                }
                assert_eq!(block, &self.ct[..]);
            }
        }

        impl CavpSink for State {
            fn on_meta(&mut self, meta: &str) {
                self.decrypt = meta == "DECRYPT";
            }

            fn on_value(&mut self, name: &str, value: Value<'_>) {
                match name {
                    "COUNT" => {}
                    "KEY" => self.key = value.bytes(),
                    // decryption entries list the ciphertext first
                    "PLAINTEXT" => {
                        self.pt = value.bytes();
                        if self.decrypt {
                            self.check();
                        }
                    }
                    "CIPHERTEXT" => {
                        self.ct = value.bytes();
                        if !self.decrypt {
                            self.check();
                        }
                    }
                    _ => todo!("unhandled value {name} = {value:?}"),
                }
            }
        }

        for bits in [128, 256] {
            for kind in ["GFSbox", "KeySbox", "VarKey", "VarTxt", "MCT"] {
                let mut state = State {
                    mct: kind == "MCT",
                    ..Default::default()
                };
                process_cavp(
                    format!("../thirdparty/cavp/aes/ECB{kind}{bits}.rsp"),
                    &mut state,
                );
            }
        }
    }

    #[test]
    fn quic_header_protection_masks() {
        // RFC 9001 appendices A.2 and A.3
        for (key, sample, mask) in [
            (
                "9f50449e04a0e810283a1e9933adedd2",
                "d1b1c98dd7689fb8ec11d242b123dc9b",
                "437b9aec36",
            ),
            (
                "c206b8d9b9f0f37644430b490eeaa314",
                "2cd0991cd25b0aac406a5816b6394100",
                "2ec0d8356a",
            ),
        ] {
            let aes = Aes::new(&hex::decode(key).unwrap()).unwrap();
            let mut block: [u8; 16] = hex::decode(sample).unwrap().try_into().unwrap();
            aes.encrypt_block(&mut block);
            assert_eq!(hex::encode(&block[..5]), mask);
        }
    }

    #[test]
    fn rfc3686() {
        // test vectors #3 and #9: three blocks, the last one partial
        for (key, nonce, ct) in [
            (
                "7691be035e5020a8ac6e618529f9a0dc",
                "00e0017b27777f3f4a1786f0",
                "c1cf48a89f2ffdd9cf4652e9efdb72d74540a42bde6d7836d59a5ceaaef3105325b2072f",
            ),
            (
                "ff7a617ce69148e4f1726e2f43581de2aa62d9f805532edff1eed687fb54153d",
                "001cc5b751a51d70a1c11148",
                "eb6c52821d0bbbf7ce7594462aca4faab407df866569fd07f48cc0b583d6071f1ec0e6b8",
            ),
        ] {
            let ctr = AesCtr::new(&hex::decode(key).unwrap()).unwrap();
            let nonce: [u8; 12] = hex::decode(nonce).unwrap().try_into().unwrap();
            let mut buf: Vec<u8> = (0u8..36).collect();
            ctr.apply_keystream(&nonce, 1, &mut buf).unwrap();
            assert_eq!(hex::encode(&buf), ct);
        }
    }

    #[test]
    fn srtp_aes_cm() {
        // RFC 3711 appendix B.2 and RFC 6188 section 7.1: one 65282-block
        // keystream segment, checked at both ends.
        for (key, first, last) in [
            (
                "2b7e151628aed2a6abf7158809cf4f3c",
                "e03ead0935c95e80e166b16dd92b4eb4d23513162b02d0f72a43a2fe4a5f97ab41e95b3bb0a2e8dd477901e4fca894c0",
                "ec8cdf7398607cb0f2d21675ea9ea1e4362b7c3c6773516318a077d7fc5073ae6a2cc3787889374fbeb4c81b17ba6c44",
            ),
            (
                "57f82fe3613fd170a85ec93c40b1f0922ec4cb0dc025b58272147cc438944a98",
                "92bdd28a93c3f52511c677d08b5515a49da71b2378a854f67050756ded165bac63c4868b7096d88421b563b8c94c9a31",
                "cea518c90fd91ced9cbb18c078a547113dbc4814f4da5f00a08772b63c6a046d6eb246913062a16891433e97dd01a57f",
            ),
        ] {
            let ctr = AesCtr::new(&hex::decode(key).unwrap()).unwrap();
            let iv = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfd0000").unwrap();
            let (nonce, counter) = iv.split_at(12);
            let mut keystream = vec![0u8; 65282 * 16];
            ctr.apply_keystream(
                nonce.try_into().unwrap(),
                u32::from_be_bytes(counter.try_into().unwrap()),
                &mut keystream,
            )
            .unwrap();
            assert_eq!(hex::encode(&keystream[..48]), first);
            assert_eq!(hex::encode(&keystream[keystream.len() - 48..]), last);
        }
    }

    #[test]
    fn aes_ctr_refuses_counter_wrap() {
        let key = [0x42u8; 16];
        let ctr = AesCtr::new(&key).unwrap();
        let nonce = [0x24u8; 12];

        let mut last_block = [0u8; 16];
        last_block[..12].copy_from_slice(&nonce);
        last_block[12..].copy_from_slice(&[0xff; 4]);
        Aes::new(&key).unwrap().encrypt_block(&mut last_block);

        // the final counter value is usable, without carrying into the nonce
        for (counter, len) in [(u32::MAX, 16), (u32::MAX - 7, 128), (u32::MAX - 8, 129)] {
            let mut buf = vec![0u8; len];
            ctr.apply_keystream(&nonce, counter, &mut buf).unwrap();
            let offset = (u32::MAX - counter) as usize * 16;
            assert_eq!(buf[offset..], last_block[..len - offset]);
        }

        for (counter, len) in [(u32::MAX, 17), (u32::MAX - 7, 129)] {
            let mut buf = vec![0xaau8; len];
            assert_eq!(
                ctr.apply_keystream(&nonce, counter, &mut buf),
                Err(Error::WrongLength)
            );
            assert!(buf.iter().all(|b| *b == 0xaa), "refused call wrote output");
        }
    }
}
