use std::fmt;

use dimpl::crypto::{Buf, HashAlgorithm, HashProvider, HmacProvider, SecureRandom};
use dimpl::{CryptoError, CryptoOperation};
use rind::digest;
use rind::hashing::hmac::Hmac;
use rind::hashing::{Sha256, Sha384};

#[derive(Debug)]
pub(crate) struct Hasher;

pub(crate) static HASH: Hasher = Hasher;

impl HashProvider for Hasher {
    fn create_hash(&self, algorithm: HashAlgorithm) -> Box<dyn dimpl::crypto::HashContext> {
        // dimpl only asks for the hash of a suite this provider offers.
        let algorithm = match algorithm {
            HashAlgorithm::SHA256 => &digest::SHA256,
            HashAlgorithm::SHA384 => &digest::SHA384,
            _ => panic!("no suite uses {algorithm:?}"),
        };
        Box::new(Running(digest::Context::new(algorithm)))
    }
}

struct Running(digest::Context);

impl fmt::Debug for Running {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Running").finish_non_exhaustive()
    }
}

impl dimpl::crypto::HashContext for Running {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn clone_and_finalize(&self, out: &mut Buf) {
        let digest = self.0.clone().finish();
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
            HashAlgorithm::SHA256 => {
                let mut mac = Hmac::<Sha256>::new(key);
                mac.update(data);
                mac.finish()
            }
            HashAlgorithm::SHA384 => {
                let mut mac = Hmac::<Sha384>::new(key);
                mac.update(data);
                mac.finish()
            }
            _ => return Err(CryptoError::UnsupportedHmacHash(hash)),
        };
        let tag = tag.as_ref();
        out.get_mut(..tag.len())
            .ok_or(CryptoError::OperationFailed(CryptoOperation::ComputeHmac))?
            .copy_from_slice(tag);
        Ok(tag.len())
    }
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
