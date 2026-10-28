// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use crate::error::Error;
use crate::low;

pub(crate) struct SigningKey {
    seed: [u8; 32],
    verifying_key: VerifyingKey,
}

impl SigningKey {
    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        low::ct::secret_slice(seed);
        let mut bytes = [0u8; 32];
        libcrux_ed25519::secret_to_public(&mut bytes, seed);
        Self {
            seed: *seed,
            verifying_key: low::ct::into_public(VerifyingKey { bytes }),
        }
    }

    /// `PureEd25519` signing
    pub(crate) fn sign(&self, msg: &[u8]) -> [u8; 64] {
        // `usize` is 32 bits here, so every message length fits HACL's `u32`.
        let sig = libcrux_ed25519::sign(msg, &self.seed).expect("message length is within limits");
        low::ct::into_public(sig)
    }

    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    pub(crate) fn as_seed_bytes(&self) -> &[u8; 32] {
        &self.seed
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        low::zeroise(&mut self.seed);
        // clearly not necessary, but makes zeroisation easier to test
        low::zeroise(&mut self.verifying_key.bytes);
    }
}

/// An encoded point; libcrux decodes it, and refuses one off the curve,
/// only when verifying.
#[derive(Clone, Debug)]
pub(crate) struct VerifyingKey {
    bytes: [u8; 32],
}

impl VerifyingKey {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes = bytes.try_into().map_err(|_| Error::WrongLength)?;
        Ok(Self { bytes })
    }

    /// `PureEd25519` signature verification
    pub(crate) fn verify(&self, sig: &[u8; 64], msg: &[u8]) -> Result<(), Error> {
        libcrux_ed25519::verify(msg, &self.bytes, sig).map_err(|_| Error::BadSignature)
    }

    pub(crate) fn as_bytes(&self) -> [u8; 32] {
        self.bytes
    }
}
