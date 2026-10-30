// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::fmt;

use crate::Error;
use crate::mid::mlkem768;

/// A key encapsulation mechanism.
pub struct Algorithm {
    id: AlgorithmId,
}

#[derive(Clone, Copy, Debug)]
enum AlgorithmId {
    MlKem768,
}

impl fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.id.fmt(f)
    }
}

/// ML-KEM-768, as standardised by FIPS-203.
pub static ML_KEM_768: Algorithm = Algorithm {
    id: AlgorithmId::MlKem768,
};

/// A decapsulation key, used for one decapsulation and wiped on drop.
pub struct DecapsulationKey(mlkem768::DecapKey);

impl DecapsulationKey {
    /// Generates a decapsulation key for `algorithm` from the system random source.
    pub fn generate(algorithm: &'static Algorithm) -> Result<Self, Error> {
        match algorithm.id {
            AlgorithmId::MlKem768 => mlkem768::DecapKey::generate().map(Self),
        }
    }

    /// Returns the encapsulation key to send to the peer.
    pub fn encapsulation_key(&self) -> EncapsulationKey {
        EncapsulationKey::wrap(self.0.encapsulation_key())
    }

    /// Recovers the secret the peer encapsulated in `ciphertext`, consuming this key.
    ///
    /// A ciphertext of the wrong length is refused. Any other tampering
    /// yields an unrelated secret (FIPS-203's implicit rejection), so the
    /// peer learns nothing until the secret is used.
    ///
    /// Unlike aws-lc-rs, this consumes the key, as ephemeral key agreement
    /// does: rind's only consumer is a TLS key share, used once.
    pub fn decapsulate(self, ciphertext: Ciphertext<'_>) -> Result<SharedSecret, Error> {
        let ciphertext: [u8; 1088] = ciphertext
            .as_ref()
            .try_into()
            .map_err(|_| Error::WrongLength)?;
        Ok(SharedSecret(
            self.0.decaps(&mlkem768::Ciphertext::from(ciphertext)),
        ))
    }
}

impl fmt::Debug for DecapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecapsulationKey").finish_non_exhaustive()
    }
}

/// An encapsulation key, which anyone may encapsulate a secret to.
#[derive(Clone)]
pub struct EncapsulationKey {
    key: mlkem768::EncapKey,
    bytes: [u8; 1184],
}

impl EncapsulationKey {
    /// Parses a peer's encapsulation key for `algorithm`.
    ///
    /// Fails with [`Error::WrongLength`] for the wrong length, and
    /// [`Error::OutOfRange`] if it fails FIPS-203's modulus check.
    pub fn new(algorithm: &'static Algorithm, bytes: &[u8]) -> Result<Self, Error> {
        match algorithm.id {
            AlgorithmId::MlKem768 => {
                let bytes = bytes.try_into().map_err(|_| Error::WrongLength)?;
                mlkem768::EncapKey::from_bytes(bytes).map(Self::wrap)
            }
        }
    }

    fn wrap(key: mlkem768::EncapKey) -> Self {
        Self {
            bytes: key.as_bytes(),
            key,
        }
    }

    /// Returns the key's encoding.
    pub fn key_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Encapsulates a fresh random secret, returning the ciphertext to send
    /// to the key's holder and the secret.
    pub fn encapsulate(&self) -> Result<(Ciphertext<'static>, SharedSecret), Error> {
        let (secret, ciphertext) = self.key.encaps()?;
        Ok((
            Ciphertext(CiphertextBytes::Owned(ciphertext)),
            SharedSecret(secret),
        ))
    }
}

impl fmt::Debug for EncapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EncapsulationKey")
            .field(&self.key_bytes())
            .finish()
    }
}

/// A ciphertext carrying an encapsulated secret.
#[derive(Clone, Debug)]
pub struct Ciphertext<'a>(CiphertextBytes<'a>);

// Boxing the owned ciphertext would allocate, which rind's API does not.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
enum CiphertextBytes<'a> {
    Borrowed(&'a [u8]),
    Owned(mlkem768::Ciphertext),
}

impl<'a> From<&'a [u8]> for Ciphertext<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self(CiphertextBytes::Borrowed(bytes))
    }
}

impl AsRef<[u8]> for Ciphertext<'_> {
    fn as_ref(&self) -> &[u8] {
        match &self.0 {
            CiphertextBytes::Borrowed(bytes) => bytes,
            CiphertextBytes::Owned(ciphertext) => ciphertext.as_ref(),
        }
    }
}

/// The secret both parties share, wiped on drop.
pub struct SharedSecret(mlkem768::SharedSecret);

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SharedSecret").finish_non_exhaustive()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::low;
    use crate::test::{Expected, wycheproof};

    // The seed and message vectors need crate access, so these live here
    // rather than in `tests/wycheproof.rs`.
    #[derive(Deserialize, Debug)]
    struct KemTest {
        #[serde(rename = "tcId")]
        id: usize,
        #[serde(default, with = "hex::serde")]
        seed: Vec<u8>,
        #[serde(default, with = "hex::serde")]
        ek: Vec<u8>,
        #[serde(default, with = "hex::serde")]
        dk: Vec<u8>,
        #[serde(default, with = "hex::serde")]
        m: Vec<u8>,
        #[serde(default, with = "hex::serde")]
        c: Vec<u8>,
        #[serde(default, rename = "K", with = "hex::serde")]
        k: Vec<u8>,
        result: Expected,
    }

    fn secret_bytes(secret: &SharedSecret) -> Vec<u8> {
        low::ct::into_public(secret.as_ref().to_vec())
    }

    #[test]
    fn wycheproof_keygen() {
        for test in wycheproof::<KemTest>("mlkem_768_keygen_seed_test.json") {
            assert_eq!(test.result, Expected::Valid, "{}", test.id);
            let key = mlkem768::DecapKey::keygen_internal(&test.seed.try_into().unwrap());
            assert_eq!(&low::ct::into_public(key.as_bytes())[..], &test.dk);
            let key = DecapsulationKey(key);
            assert_eq!(key.encapsulation_key().key_bytes(), &test.ek);
        }
    }

    #[test]
    fn wycheproof_encaps() {
        for test in wycheproof::<KemTest>("mlkem_768_encaps_test.json") {
            let m = mlkem768::Message(test.m.try_into().unwrap());
            let result = EncapsulationKey::new(&ML_KEM_768, &test.ek).map(|key| {
                let (secret, ciphertext) = key.key.encaps_internal(m);
                (secret_bytes(&SharedSecret(secret)), ciphertext)
            });
            match (test.result, &result) {
                (Expected::Valid, Ok((secret, ciphertext))) => {
                    assert_eq!(secret, &test.k, "{}", test.id);
                    assert_eq!(&ciphertext.as_ref()[..], &test.c, "{}", test.id);
                }
                (Expected::Invalid, Err(Error::WrongLength | Error::OutOfRange)) => {}
                _ => panic!("{}: expected {:?} got {:?}", test.id, test.result, result),
            }
        }
    }

    #[test]
    fn wycheproof_decaps() {
        for test in wycheproof::<KemTest>("mlkem_768_test.json") {
            // Generation never makes a seed of another length.
            let Ok(seed) = test.seed.as_slice().try_into() else {
                assert_eq!(test.result, Expected::Invalid, "{}", test.id);
                continue;
            };

            let key = DecapsulationKey(mlkem768::DecapKey::keygen_internal(&seed));
            assert_eq!(key.encapsulation_key().key_bytes(), &test.ek, "{}", test.id);
            let result = key
                .decapsulate(Ciphertext::from(&test.c[..]))
                .map(|secret| secret_bytes(&secret));
            match (test.result, &result) {
                (Expected::Valid, Ok(secret)) => assert_eq!(secret, &test.k, "{}", test.id),
                (Expected::Invalid, Err(Error::WrongLength)) => {}
                _ => panic!("{}: expected {:?} got {:?}", test.id, test.result, result),
            }
        }
    }

    // Exporting our decapsulation key needs crate access, so this
    // differential test lives here rather than in `tests/crosschecks.rs`.
    mod crosscheck {
        use aws_lc_rs::kem::{self, ML_KEM_768};
        use proptest::prelude::*;
        use proptest::sample::Index;

        use super::*;

        // Each case generates a key, which is slow under emulation.
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]

            // We decapsulate what aws-lc-rs encapsulates to our key, and so
            // does aws-lc-rs holding our serialized key. With one byte of the
            // ciphertext altered, both give the same implicit-rejection secret.
            #[test]
            fn encapsulated_by_theirs(alter in prop::option::of((any::<Index>(), 1..=255u8))) {
                let ours = DecapsulationKey::generate(&super::ML_KEM_768).unwrap();
                let theirs = kem::DecapsulationKey::new(
                    &ML_KEM_768,
                    &low::ct::into_public(ours.0.as_bytes()),
                )
                .unwrap();
                let (ciphertext, secret) =
                    kem::EncapsulationKey::new(&ML_KEM_768, ours.encapsulation_key().key_bytes())
                        .unwrap()
                        .encapsulate()
                        .unwrap();

                let mut ciphertext = ciphertext.as_ref().to_vec();
                if let Some((index, xor)) = alter {
                    let index = index.index(ciphertext.len());
                    ciphertext[index] ^= xor;
                }
                let theirs_secret = theirs.decapsulate(kem::Ciphertext::from(&ciphertext[..])).unwrap();
                let ours_secret = secret_bytes(&ours.decapsulate(Ciphertext::from(&ciphertext[..])).unwrap());
                prop_assert_eq!(&ours_secret[..], theirs_secret.as_ref());
                prop_assert_eq!(&ours_secret[..] == secret.as_ref(), alter.is_none());
            }
        }
    }
}
