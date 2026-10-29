use rind::hashing::hmac::Hmac;
use rind::hashing::{Hash, LegacySha1, Sha256};
use str0m_proto::crypto::{Sha1HmacProvider, Sha1Provider, Sha256Provider};

pub(crate) static SHA1_HMAC: RindSha1Hmac = RindSha1Hmac;
pub(crate) static SHA1: RindSha1 = RindSha1;
pub(crate) static SHA256: RindSha256 = RindSha256;

#[derive(Debug)]
pub(crate) struct RindSha1Hmac;

impl Sha1HmacProvider for RindSha1Hmac {
    fn sha1_hmac(&self, key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
        let mut hmac = Hmac::<LegacySha1>::new(key);
        for payload in payloads {
            hmac.update(payload);
        }
        hmac.finish().as_ref().try_into().unwrap()
    }
}

#[derive(Debug)]
pub(crate) struct RindSha1;

impl Sha1Provider for RindSha1 {
    fn sha1(&self, data: &[u8]) -> [u8; 20] {
        LegacySha1::hash(data).as_ref().try_into().unwrap()
    }
}

#[derive(Debug)]
pub(crate) struct RindSha256;

impl Sha256Provider for RindSha256 {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        Sha256::hash(data).as_ref().try_into().unwrap()
    }
}
