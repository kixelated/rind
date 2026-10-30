// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! ML-KEM-768 as standardised by FIPS-203.

use core::fmt;

use libcrux_ml_kem::mlkem768::portable;
use libcrux_ml_kem::mlkem768::{MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};

use crate::mid::rng::{RandomSource, SystemRandom};
use crate::{Error, low};

/// An ML-KEM-768 decapsulation key.
pub(crate) struct DecapKey {
    dk: MlKem768PrivateKey,
    ek: EncapKey,
}

impl DecapKey {
    /// Generate a random [`DecapKey`] (which contains the corresponding [`EncapKey`]).
    ///
    /// This fails only if random material generation fails.
    pub(crate) fn generate() -> Result<Self, Error> {
        let _entry = low::Entry::new_secret();
        let mut seed = [0u8; 64];
        SystemRandom.fill(&mut seed)?;
        let key = Self::keygen_internal(&seed);
        low::zeroise(&mut seed);
        Ok(key)
    }

    /// Decapsulate ciphertext `c`, yielding a [`SharedSecret`].
    pub(crate) fn decaps(self, c: &Ciphertext) -> SharedSecret {
        let _entry = low::Entry::new_secret();
        self.decaps_internal(c)
    }

    /// Return the corresponding [`EncapKey`].
    pub(crate) fn encapsulation_key(&self) -> EncapKey {
        let _entry = low::Entry::new_public();
        self.ek.clone()
    }

    /// Encode the key as bytes.
    ///
    /// This is used for testing.
    #[cfg(test)]
    pub(crate) fn as_bytes(&self) -> [u8; 2400] {
        let _entry = low::Entry::new_secret();
        *self.dk.as_slice()
    }

    pub(crate) fn keygen_internal(seed: &[u8; 64]) -> Self {
        // libcrux takes `d || z`, as FIPS-203's ML-KEM.KeyGen_internal does.
        let (dk, ek) = portable::generate_key_pair(*seed).into_parts();
        // Mark the key after libcrux derives it, since its matrix sampling
        // branches on rho, which is public but derived from the secret seed.
        // `dk` is `dk_pke || ek || H(ek) || z`; only `dk_pke` and `z` are secret.
        low::ct::secret_slice(&dk.as_slice()[..1152]);
        low::ct::secret_slice(&dk.as_slice()[2368..]);
        Self {
            dk,
            ek: EncapKey(ek),
        }
    }

    fn decaps_internal(&self, c: &Ciphertext) -> SharedSecret {
        let c = MlKem768Ciphertext::from(&c.0);
        SharedSecret(portable::decapsulate(&self.dk, &c))
    }
}

// The public `ek` is wiped too, so the whole value is zero after drop.
impl Drop for DecapKey {
    fn drop(&mut self) {
        low::zeroise(&mut self.dk[0..]);
        low::zeroise(&mut self.ek.0[0..]);
    }
}

/// An ML-KEM-768 encapsulation key.
#[derive(Clone)]
pub(crate) struct EncapKey(MlKem768PublicKey);

impl EncapKey {
    /// Create a new [`EncapKey`] from bytes.
    pub(crate) fn from_bytes(input: &[u8; 1184]) -> Result<Self, Error> {
        let _entry = low::Entry::new_public();
        let ek = MlKem768PublicKey::from(input);
        // FIPS-203's modulus check.
        if !portable::validate_public_key(&ek) {
            return Err(Error::OutOfRange);
        }
        Ok(Self(ek))
    }

    /// Encapsulate a random shared secret, returning the shared secret and a ciphertext.
    ///
    /// The ciphertext can be returned to the holder of the [`DecapKey`] who can then
    /// derive the same [`SharedSecret`].
    pub(crate) fn encaps(&self) -> Result<(SharedSecret, Ciphertext), Error> {
        let _entry = low::Entry::new_secret();
        let mut m = Message([0; 32]);
        SystemRandom.fill(&mut m.0)?;
        Ok(self.encaps_internal(m))
    }

    /// Encode the [`EncapKey`] as bytes.
    pub(crate) fn as_bytes(&self) -> [u8; 1184] {
        let _entry = low::Entry::new_public();
        *self.0.as_slice()
    }

    pub(crate) fn encaps_internal(&self, m: Message) -> (SharedSecret, Ciphertext) {
        low::ct::secret_slice(&m.0);
        let (c, k) = portable::encapsulate(&self.0, m.0);
        (
            SharedSecret(k),
            Ciphertext(low::ct::into_public(*c.as_slice())),
        )
    }
}

/// An ML-KEM-768 ciphertext.
#[derive(Debug, Clone)]
pub(crate) struct Ciphertext([u8; 1088]);

impl From<[u8; 1088]> for Ciphertext {
    fn from(value: [u8; 1088]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8; 1088]> for Ciphertext {
    fn as_ref(&self) -> &[u8; 1088] {
        &self.0
    }
}

/// A K-PKE message.
pub(crate) struct Message(pub(crate) [u8; 32]);

impl Drop for Message {
    fn drop(&mut self) {
        low::zeroise(&mut self.0);
    }
}

/// An ML-KEM shared secret.
pub(crate) struct SharedSecret([u8; 32]);

impl AsRef<[u8; 32]> for SharedSecret {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SharedSecret").finish_non_exhaustive()
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        low::zeroise(&mut self.0);
    }
}
