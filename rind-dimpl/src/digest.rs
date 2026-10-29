use std::fmt;

use dimpl::crypto::{Buf, HashAlgorithm, HashProvider, HmacProvider, SecureRandom};
use dimpl::{CryptoError, CryptoOperation};
use rind::hashing::hmac::Hmac;
use rind::hashing::{Hash, HashContext, Sha256, Sha384};

#[derive(Debug)]
pub(crate) struct Hasher;

pub(crate) static HASH: Hasher = Hasher;

impl HashProvider for Hasher {
    fn create_hash(&self, algorithm: HashAlgorithm) -> Box<dyn dimpl::crypto::HashContext> {
        // dimpl only asks for the hash of a suite this provider offers.
        match algorithm {
            HashAlgorithm::SHA256 => Box::new(Running::Sha256(Sha256::new())),
            HashAlgorithm::SHA384 => Box::new(Running::Sha384(Sha384::new())),
            _ => panic!("no suite uses {algorithm:?}"),
        }
    }
}

#[derive(Clone)]
enum Running {
    Sha256(<Sha256 as Hash>::Context),
    Sha384(<Sha384 as Hash>::Context),
}

impl fmt::Debug for Running {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sha256(_) => "Sha256",
            Self::Sha384(_) => "Sha384",
        })
    }
}

impl dimpl::crypto::HashContext for Running {
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(ctx) => ctx.update(data),
            Self::Sha384(ctx) => ctx.update(data),
        }
    }

    fn clone_and_finalize(&self, out: &mut Buf) {
        let digest = match self.clone() {
            Self::Sha256(ctx) => ctx.finish(),
            Self::Sha384(ctx) => ctx.finish(),
        };
        out.clear();
        out.extend_from_slice(digest.as_ref());
    }
}

#[derive(Debug)]
pub(crate) struct Mac;

pub(crate) static HMAC: Mac = Mac;

impl HmacProvider for Mac {
    fn hmac(
        &self,
        hash: HashAlgorithm,
        key: &[u8],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let tag = match hash {
            HashAlgorithm::SHA256 => mac::<Sha256>(key, data),
            HashAlgorithm::SHA384 => mac::<Sha384>(key, data),
            _ => return Err(CryptoError::UnsupportedHmacHash(hash)),
        };
        let tag = tag.as_ref();
        out.get_mut(..tag.len())
            .ok_or(CryptoError::OperationFailed(CryptoOperation::ComputeHmac))?
            .copy_from_slice(tag);
        Ok(tag.len())
    }
}

fn mac<H: Hash>(key: &[u8], data: &[u8]) -> rind::hashing::HashOutput {
    let mut mac = Hmac::<H>::new(key);
    mac.update(data);
    mac.finish()
}

#[derive(Debug)]
pub(crate) struct Random;

pub(crate) static RANDOM: Random = Random;

impl SecureRandom for Random {
    fn fill(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
        rind::random::fill(buf)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::FillRandom))
    }
}
