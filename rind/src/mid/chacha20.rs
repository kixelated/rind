// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::Error;
use crate::low::{self, Entry, zeroise};

/// A ChaCha20 key, for the bare stream cipher with a 96-bit nonce and a 32-bit block counter.
///
/// See [RFC8439](https://datatracker.ietf.org/doc/html/rfc8439). Use it only
/// where a protocol specifies ChaCha20 without Poly1305, such as QUIC header
/// protection or DTLS 1.3 record number protection.
pub struct ChaCha20 {
    key: [u8; 32],
}

impl ChaCha20 {
    /// Create a new [`ChaCha20`] from 32 bytes of key material.
    pub fn new(key: [u8; 32]) -> Self {
        low::ct::secret_slice(&key);
        Self { key }
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
        check_counter(counter, inout.len())?;
        low::ct::secret_slice(inout);

        let mut counter_nonce = [0u8; 16];
        counter_nonce[..4].copy_from_slice(&counter.to_le_bytes());
        counter_nonce[4..].copy_from_slice(nonce);
        low::chacha20::ChaCha20::new(&self.key, &counter_nonce).cipher(inout);

        low::ct::public_slice(inout);
        Ok(())
    }
}

/// Fails with [`Error::WrongLength`] if `len` bytes need more blocks than
/// remain from block `counter` before the 32-bit counter wraps.
pub(super) fn check_counter(counter: u32, len: usize) -> Result<(), Error> {
    if u64::from(counter) + len.div_ceil(64) as u64 > 1 << 32 {
        return Err(Error::WrongLength);
    }
    Ok(())
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        zeroise(&mut self.key);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn rfc8439() {
        // section 2.4.2: two blocks and a partial third, from counter 1
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = hex::decode("000000000000004a00000000").unwrap();
        let mut buf = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();

        ChaCha20::new(key)
            .apply_keystream(&nonce.try_into().unwrap(), 1, &mut buf)
            .unwrap();

        assert_eq!(
            hex::encode(&buf),
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d"
        );
    }

    #[test]
    fn quic_header_protection_mask() {
        // RFC 9001 appendix A.5: the counter is the sample's first four bytes,
        // little-endian, and the nonce is the rest.
        let key = hex::decode("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
            .unwrap();
        let sample = hex::decode("5e5cd55c41f69080575d7999c25a5bfb").unwrap();
        let (counter, nonce) = sample.split_at(4);

        let mut mask = [0u8; 5];
        ChaCha20::new(key.try_into().unwrap())
            .apply_keystream(
                nonce.try_into().unwrap(),
                u32::from_le_bytes(counter.try_into().unwrap()),
                &mut mask,
            )
            .unwrap();
        assert_eq!(hex::encode(mask), "aefefe7d03");
    }

    #[test]
    fn counter_limits() {
        assert_eq!(check_counter(u32::MAX, 64), Ok(()));
        assert_eq!(check_counter(u32::MAX, 65), Err(Error::WrongLength));

        // the AEADs start at block 1, after the Poly1305 key's
        #[cfg(target_pointer_width = "64")]
        {
            let max_aead = ((1 << 32) - 1) * 64;
            assert_eq!(check_counter(1, max_aead), Ok(()));
            assert_eq!(check_counter(1, max_aead + 1), Err(Error::WrongLength));
        }
    }
}
