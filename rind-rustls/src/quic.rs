use rind::aead;
use rind::cipher::{Aes, ChaCha20};
use rustls::Error;
use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::quic;

/// QUIC packet and header protection with AES-GCM, by key length in bytes.
pub(crate) struct AesGcm(pub(crate) usize);

impl quic::Algorithm for AesGcm {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(PacketKey {
            aead: aead::AesGcm::new(key.as_ref()).unwrap(),
            iv,
        })
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(HeaderProtectionKey(Aes::new(key.as_ref()).unwrap()))
    }

    fn aead_key_len(&self) -> usize {
        self.0
    }
}

/// QUIC packet and header protection with ChaCha20-Poly1305.
pub(crate) struct ChaCha20Poly1305;

impl quic::Algorithm for ChaCha20Poly1305 {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
        Box::new(PacketKey {
            aead: aead::ChaCha20Poly1305::new(key.as_ref().try_into().unwrap()),
            iv,
        })
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
        Box::new(HeaderProtectionKey(ChaCha20::new(
            key.as_ref().try_into().unwrap(),
        )))
    }

    fn aead_key_len(&self) -> usize {
        32
    }
}

/// An AEAD that protects QUIC packet payloads.
trait Aead: Send + Sync {
    /// RFC 9001 section 6.6
    const CONFIDENTIALITY_LIMIT: u64;
    /// RFC 9001 section 6.6
    const INTEGRITY_LIMIT: u64;

    fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        inout: &mut [u8],
        tag: &mut [u8; TAG_LEN],
    ) -> Result<(), rind::Error>;
    fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        inout: &mut [u8],
        tag: &[u8],
    ) -> Result<(), rind::Error>;
}

impl Aead for aead::AesGcm {
    const CONFIDENTIALITY_LIMIT: u64 = 1 << 23;
    const INTEGRITY_LIMIT: u64 = 1 << 52;

    fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        inout: &mut [u8],
        tag: &mut [u8; TAG_LEN],
    ) -> Result<(), rind::Error> {
        self.encrypt(nonce, aad, inout, tag)
    }

    fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        inout: &mut [u8],
        tag: &[u8],
    ) -> Result<(), rind::Error> {
        self.decrypt(nonce, aad, inout, tag)
    }
}

impl Aead for aead::ChaCha20Poly1305 {
    const CONFIDENTIALITY_LIMIT: u64 = u64::MAX;
    const INTEGRITY_LIMIT: u64 = 1 << 36;

    fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        inout: &mut [u8],
        tag: &mut [u8; TAG_LEN],
    ) -> Result<(), rind::Error> {
        self.encrypt(nonce, aad, inout, tag)
    }

    fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        inout: &mut [u8],
        tag: &[u8],
    ) -> Result<(), rind::Error> {
        self.decrypt(nonce, aad, inout, tag)
    }
}

struct PacketKey<A> {
    aead: A,
    iv: Iv,
}

impl<A: Aead> quic::PacketKey for PacketKey<A> {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        let nonce = Nonce::new(&self.iv, packet_number);
        let mut tag = [0u8; TAG_LEN];
        self.aead
            .encrypt(&nonce.0, header, payload, &mut tag)
            .map_err(|_| Error::EncryptError)?;
        Ok(quic::Tag::from(&tag[..]))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let plain_len = payload
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::DecryptError)?;
        let (plain, tag) = payload.split_at_mut(plain_len);
        let nonce = Nonce::new(&self.iv, packet_number);
        self.aead
            .decrypt(&nonce.0, header, plain, tag)
            .map_err(|_| Error::DecryptError)?;
        Ok(plain)
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        A::CONFIDENTIALITY_LIMIT
    }

    fn integrity_limit(&self) -> u64 {
        A::INTEGRITY_LIMIT
    }
}

/// A cipher that derives the QUIC header protection mask from a sample.
trait Mask: Send + Sync {
    fn mask(&self, sample: &[u8; SAMPLE_LEN]) -> Result<[u8; MASK_LEN], Error>;
}

/// RFC 9001 section 5.4.3
impl Mask for Aes {
    fn mask(&self, sample: &[u8; SAMPLE_LEN]) -> Result<[u8; MASK_LEN], Error> {
        let mut block = *sample;
        self.encrypt_block(&mut block);
        Ok(core::array::from_fn(|i| block[i]))
    }
}

/// RFC 9001 section 5.4.4
impl Mask for ChaCha20 {
    fn mask(&self, sample: &[u8; SAMPLE_LEN]) -> Result<[u8; MASK_LEN], Error> {
        let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
        let nonce: [u8; 12] = core::array::from_fn(|i| sample[4 + i]);
        let mut mask = [0u8; MASK_LEN];
        self.apply_keystream(&nonce, counter, &mut mask)
            .map_err(|_| Error::EncryptError)?;
        Ok(mask)
    }
}

struct HeaderProtectionKey<M>(M);

impl<M: Mask> HeaderProtectionKey<M> {
    /// RFC 9001 section 5.4.1, leaving `first` and `packet_number` unchanged on error.
    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<(), Error> {
        let sample: &[u8; SAMPLE_LEN] = sample
            .try_into()
            .map_err(|_| Error::General("sample of invalid length".into()))?;
        let [first_mask, pn_mask @ ..] = self.0.mask(sample)?;
        if packet_number.len() > pn_mask.len() {
            return Err(Error::General("packet number too long".into()));
        }

        // Long headers protect 4 bits of the first byte, short headers 5.
        let bits = match *first & 0x80 {
            0 => 0x1f,
            _ => 0x0f,
        };
        // The packet number length is in the unprotected first byte.
        let first_plain = match masked {
            true => *first ^ (first_mask & bits),
            false => *first,
        };
        let pn_len = (first_plain & 0x03) as usize + 1;

        *first ^= first_mask & bits;
        for (pn, mask) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
            *pn ^= mask;
        }
        Ok(())
    }
}

impl<M: Mask> quic::HeaderProtectionKey for HeaderProtectionKey<M> {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, true)
    }

    fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }
}

const TAG_LEN: usize = 16;
const SAMPLE_LEN: usize = 16;
const MASK_LEN: usize = 5;

#[cfg(test)]
mod tests {
    use rustls::Side;
    use rustls::SupportedCipherSuite;
    use rustls::quic::{Algorithm as _, DirectionalKeys, Keys, Version};

    use super::*;
    use crate::suites;

    fn initial_keys(suite: SupportedCipherSuite, side: Side) -> Keys {
        // RFC 9001 appendix A.1
        let dcid = hex::decode("8394c8f03e515708").unwrap();
        let suite = suite.tls13().unwrap().quic_suite().unwrap();
        suite.keys(&dcid, side, Version::V1)
    }

    /// Adds or removes header protection on `packet`, whose packet number starts at `pn_offset`.
    fn header_protection(
        key: &dyn quic::HeaderProtectionKey,
        packet: &mut [u8],
        pn_offset: usize,
        protect: bool,
    ) {
        // The sample assumes a 4-byte packet number (RFC 9001 section 5.4.2).
        let (header, rest) = packet.split_at_mut(pn_offset + 4);
        let sample = &rest[..key.sample_len()];
        let (first, rest) = header.split_first_mut().unwrap();
        let packet_number = &mut rest[pn_offset - 1..];
        match protect {
            true => key.encrypt_in_place(sample, first, packet_number),
            false => key.decrypt_in_place(sample, first, packet_number),
        }
        .unwrap();
    }

    /// Protects a packet with `send`, compares it to `expected`, then unprotects it with `recv`.
    fn check_packet(
        send: &DirectionalKeys,
        recv: &DirectionalKeys,
        packet_number: u64,
        header: &str,
        payload: &str,
        expected: &str,
    ) {
        let (header, payload) = (hex::decode(header).unwrap(), hex::decode(payload).unwrap());
        let pn_offset = header.len() - 1 - (header[0] & 0x03) as usize;

        let mut packet = [&header[..], &payload[..]].concat();
        let (head, body) = packet.split_at_mut(header.len());
        let tag = send
            .packet
            .encrypt_in_place(packet_number, head, body)
            .unwrap();
        packet.extend_from_slice(tag.as_ref());
        header_protection(&*send.header, &mut packet, pn_offset, true);
        assert_eq!(hex::encode(&packet), expected);

        header_protection(&*recv.header, &mut packet, pn_offset, false);
        let (head, body) = packet.split_at_mut(header.len());
        assert_eq!(head, &header[..]);
        let plain = recv
            .packet
            .decrypt_in_place(packet_number, head, body)
            .unwrap();
        assert_eq!(plain, &payload[..]);
    }

    #[test]
    fn rfc9001_client_initial_header() {
        // RFC 9001 appendix A.2, header protection only: the payload is padded to 1162 bytes.
        let keys = initial_keys(suites::TLS13_AES_128_GCM_SHA256, Side::Client);
        let sample = hex::decode("d1b1c98dd7689fb8ec11d242b123dc9b").unwrap();
        let (mut first, mut packet_number) = (0xc3, [0x00, 0x00, 0x00, 0x02]);

        keys.local
            .header
            .encrypt_in_place(&sample, &mut first, &mut packet_number)
            .unwrap();
        assert_eq!((first, packet_number), (0xc0, [0x7b, 0x9a, 0xec, 0x34]));
    }

    #[test]
    fn rfc9001_server_initial() {
        // RFC 9001 appendix A.3
        check_packet(
            &initial_keys(suites::TLS13_AES_128_GCM_SHA256, Side::Server).local,
            &initial_keys(suites::TLS13_AES_128_GCM_SHA256, Side::Client).remote,
            1,
            "c1000000010008f067a5502a4262b50040750001",
            "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739\
             88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94\
             0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00\
             020304",
            "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a\
             5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3\
             dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84\
             022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4\
             2158407dd074ee",
        );
    }

    #[test]
    fn rfc9001_chacha20_short_header() {
        // RFC 9001 appendix A.5
        let keys = || {
            let key = "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8";
            let iv = "e0459b3474bdd0e44a41c144";
            let hp = "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4";
            let key: [u8; 32] = hex::decode(key).unwrap().try_into().unwrap();
            let iv: [u8; 12] = hex::decode(iv).unwrap().try_into().unwrap();
            let hp: [u8; 32] = hex::decode(hp).unwrap().try_into().unwrap();
            DirectionalKeys {
                packet: ChaCha20Poly1305.packet_key(AeadKey::from(key), Iv::new(iv)),
                header: ChaCha20Poly1305.header_protection_key(AeadKey::from(hp)),
            }
        };
        check_packet(
            &keys(),
            &keys(),
            654360564,
            "4200bff4",
            "01",
            "4cfe4189655e5cd55c41f69080575d7999c25a5bfb",
        );
    }

    #[test]
    fn rejects_malformed_input() {
        for suite in [
            suites::TLS13_AES_128_GCM_SHA256,
            suites::TLS13_AES_256_GCM_SHA384,
            suites::TLS13_CHACHA20_POLY1305_SHA256,
        ] {
            let keys = initial_keys(suite, Side::Client).local;

            // A bad sample or an overlong packet number changes nothing.
            let (mut first, mut packet_number) = (0xc3, [0u8; 4]);
            let header = &keys.header;
            assert!(
                header
                    .encrypt_in_place(&[0; 15], &mut first, &mut packet_number)
                    .is_err()
            );
            assert!(
                header
                    .decrypt_in_place(&[0; 17], &mut first, &mut packet_number)
                    .is_err()
            );
            assert!(
                header
                    .encrypt_in_place(&[0; 16], &mut first, &mut [0; 5])
                    .is_err()
            );
            assert_eq!((first, packet_number), (0xc3, [0; 4]));

            let mut sealed = b"payload".to_vec();
            let tag = keys
                .packet
                .encrypt_in_place(7, b"header", &mut sealed)
                .unwrap();
            sealed.extend_from_slice(tag.as_ref());
            let open = |packet_number, header: &[u8], sealed: &[u8]| {
                let mut sealed = sealed.to_vec();
                let plain = keys
                    .packet
                    .decrypt_in_place(packet_number, header, &mut sealed);
                plain.map(<[u8]>::to_vec)
            };
            assert_eq!(open(7, b"header", &sealed).unwrap(), b"payload");
            assert!(open(8, b"header", &sealed).is_err());
            assert!(open(7, b"headex", &sealed).is_err());
            assert!(open(7, b"header", &sealed[..TAG_LEN - 1]).is_err());
        }
    }
}
