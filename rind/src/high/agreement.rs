// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::fmt;

use crate::error::{Error, KeyFormatError};
use crate::low;
use crate::mid::{p256, p384, x25519};

/// A key agreement algorithm: a curve and its public key encoding.
pub struct Algorithm {
    id: AlgorithmId,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum AlgorithmId {
    X25519,
    EcdhP256,
    EcdhP384,
}

impl fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.id.fmt(f)
    }
}

/// X25519, with 32-byte public keys.
///
/// See [RFC7748](https://datatracker.ietf.org/doc/html/rfc7748).
pub static X25519: Algorithm = Algorithm {
    id: AlgorithmId::X25519,
};

/// ECDH on P-256, with X9.62 uncompressed public keys.
///
/// P-256 is also known as "NISTP256", "prime256v1", or "secp256r1".
pub static ECDH_P256: Algorithm = Algorithm {
    id: AlgorithmId::EcdhP256,
};

/// ECDH on P-384, with X9.62 uncompressed public keys.
///
/// P-384 is also known as "NISTP384", or "secp384r1".
pub static ECDH_P384: Algorithm = Algorithm {
    id: AlgorithmId::EcdhP384,
};

/// A private key used for one key agreement, wiped on drop.
///
/// There is no static private key: no consumer agrees twice with one key.
pub struct EphemeralPrivateKey(Private);

// `repr(u8)` puts `X25519` at tag zero, and every variant's key is plain
// words, so all-bits-zero is a valid value and `Drop` can wipe the tag and
// any unused tail along with the key.
#[repr(u8)]
enum Private {
    X25519(x25519::PrivateKey),
    P256(p256::PrivateKey),
    P384(p384::PrivateKey),
}

impl low::Zeroable for Private {}

impl EphemeralPrivateKey {
    /// Generates a private key for `algorithm` from the system random source.
    ///
    /// Unlike aws-lc-rs, this takes no random source: aws-lc-rs ignores its
    /// own, a leftover of ring's API.
    pub fn generate(algorithm: &'static Algorithm) -> Result<Self, Error> {
        Ok(Self(match algorithm.id {
            AlgorithmId::X25519 => Private::X25519(x25519::PrivateKey::new_random()?),
            AlgorithmId::EcdhP256 => Private::P256(p256::PrivateKey::new_random()?),
            AlgorithmId::EcdhP384 => Private::P384(p384::PrivateKey::new_random()?),
        }))
    }

    /// Computes the public key to send to the peer.
    pub fn compute_public_key(&self) -> PublicKey {
        let mut public = PublicKey {
            bytes: [0; PublicKey::MAX_LEN],
            len: 0,
        };
        let encoded: &[u8] = match &self.0 {
            Private::X25519(key) => &key.public_key().as_bytes(),
            Private::P256(key) => &key.public_key_uncompressed(),
            Private::P384(key) => &key.public_key_uncompressed(),
        };
        public.bytes[..encoded.len()].copy_from_slice(encoded);
        public.len = encoded.len();
        public
    }
}

impl Drop for EphemeralPrivateKey {
    fn drop(&mut self) {
        low::zeroise_value(&mut self.0);
    }
}

impl fmt::Debug for EphemeralPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralPrivateKey")
            .finish_non_exhaustive()
    }
}

/// Our public key: 32 bytes for X25519, or an X9.62 uncompressed point.
#[derive(Clone)]
pub struct PublicKey {
    bytes: [u8; Self::MAX_LEN],
    len: usize,
}

impl PublicKey {
    // P-384's uncompressed point.
    const MAX_LEN: usize = 97;
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey").field(&self.as_ref()).finish()
    }
}

/// A peer's public key, parsed for `algorithm` only at agreement.
#[derive(Clone, Copy, Debug)]
pub struct UnparsedPublicKey<B: AsRef<[u8]>> {
    algorithm: &'static Algorithm,
    bytes: B,
}

impl<B: AsRef<[u8]>> UnparsedPublicKey<B> {
    /// Wraps a peer's encoded public key for `algorithm`.
    pub fn new(algorithm: &'static Algorithm, bytes: B) -> Self {
        Self { algorithm, bytes }
    }
}

/// The secret both parties agree on, wiped on drop.
pub struct SharedSecret(Secret);

enum Secret {
    X25519(x25519::SharedSecret),
    P256(p256::SharedSecret),
    P384(p384::SharedSecret),
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        match &self.0 {
            Secret::X25519(secret) => &secret.0,
            Secret::P256(secret) => &secret.0,
            Secret::P384(secret) => &secret.0,
        }
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SharedSecret").finish_non_exhaustive()
    }
}

/// Agrees on a secret with a peer, consuming our private key.
///
/// The peer's key is refused if it is malformed, off the curve, or for
/// another algorithm than ours, and so is X25519's all-zero output from a
/// small-order point
/// ([RFC7748 section 6.1](https://datatracker.ietf.org/doc/html/rfc7748#section-6.1)).
///
/// Unlike aws-lc-rs, this returns the secret instead of passing it to a
/// key derivation closure; [`SharedSecret`] wipes itself on drop instead.
pub fn agree_ephemeral<B: AsRef<[u8]>>(
    my_private_key: EphemeralPrivateKey,
    peer_public_key: &UnparsedPublicKey<B>,
) -> Result<SharedSecret, Error> {
    let peer = peer_public_key.bytes.as_ref();
    Ok(SharedSecret(
        match (&my_private_key.0, peer_public_key.algorithm.id) {
            (Private::X25519(key), AlgorithmId::X25519) => {
                Secret::X25519(key.diffie_hellman(&x25519::PublicKey::try_from_slice(peer)?)?)
            }
            (Private::P256(key), AlgorithmId::EcdhP256) => {
                Secret::P256(key.diffie_hellman(&p256::PublicKey::from_x962_uncompressed(peer)?)?)
            }
            (Private::P384(key), AlgorithmId::EcdhP384) => {
                Secret::P384(key.diffie_hellman(&p384::PublicKey::from_x962_uncompressed(peer)?)?)
            }
            _ => return Err(KeyFormatError::MismatchedAgreementAlgorithm.into()),
        },
    ))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::test::{Expected, wycheproof};

    #[test]
    fn agrees() {
        for algorithm in [&X25519, &ECDH_P256, &ECDH_P384] {
            let alice = EphemeralPrivateKey::generate(algorithm).unwrap();
            let bob = EphemeralPrivateKey::generate(algorithm).unwrap();
            let alice_public = alice.compute_public_key();
            let bob_public = bob.compute_public_key();

            let alice_secret =
                agree_ephemeral(alice, &UnparsedPublicKey::new(algorithm, &bob_public)).unwrap();
            let bob_secret =
                agree_ephemeral(bob, &UnparsedPublicKey::new(algorithm, &alice_public)).unwrap();
            assert_eq!(
                low::ct::into_public(alice_secret.as_ref().to_vec()),
                low::ct::into_public(bob_secret.as_ref().to_vec()),
            );
        }
    }

    #[test]
    fn refuses_another_algorithms_peer() {
        for (ours, theirs) in [
            (&X25519, &ECDH_P256),
            (&ECDH_P256, &ECDH_P384),
            (&ECDH_P384, &X25519),
        ] {
            let peer = EphemeralPrivateKey::generate(theirs)
                .unwrap()
                .compute_public_key();
            let key = EphemeralPrivateKey::generate(ours).unwrap();
            assert_eq!(
                agree_ephemeral(key, &UnparsedPublicKey::new(theirs, &peer)).err(),
                Some(KeyFormatError::MismatchedAgreementAlgorithm.into())
            );
        }
    }

    #[derive(Deserialize, Debug)]
    struct EcdhTest {
        #[serde(rename = "tcId")]
        id: usize,
        flags: Vec<String>,
        #[serde(with = "hex::serde")]
        public: Vec<u8>,
        #[serde(with = "hex::serde")]
        private: Vec<u8>,
        #[serde(with = "hex::serde")]
        shared: Vec<u8>,
        result: Expected,
    }

    impl EcdhTest {
        fn has_flag(&self, flag: &str) -> bool {
            self.flags.iter().any(|f| f == flag)
        }
    }

    fn check_nist_ecdh(file: &str, agree: impl Fn(&EcdhTest) -> Result<Vec<u8>, Error>) {
        for test in wycheproof::<EcdhTest>(file) {
            let result = agree(&test);
            // Point compression is unsupported.
            if test.has_flag("CompressedPublic") || test.has_flag("CompressedPoint") {
                assert_eq!(result, Err(Error::NotUncompressed), "{}", test.id);
                continue;
            }

            match (test.result, &result) {
                (Expected::Valid, Ok(shared)) => assert_eq!(shared, &test.shared, "{}", test.id),
                (Expected::Invalid, Err(Error::NotOnCurve))
                    if test.has_flag("InvalidCurveAttack") => {}
                (Expected::Invalid, Err(Error::WrongLength))
                    if test.has_flag("InvalidEncoding") => {}
                _ => panic!("{}: expected {:?} got {:?}", test.id, test.result, result),
            }
        }
    }

    #[test]
    fn wycheproof_p256() {
        check_nist_ecdh("ecdh_secp256r1_ecpoint_test.json", |test| {
            let private = p256::StaticPrivateKey::from_bytes(&test.private).unwrap();
            let peer = p256::PublicKey::from_x962_uncompressed(&test.public)?;
            Ok(low::ct::into_public(private.diffie_hellman(&peer)?.0).to_vec())
        });
    }

    #[test]
    fn wycheproof_p384() {
        check_nist_ecdh("ecdh_secp384r1_ecpoint_test.json", |test| {
            let private = p384::StaticPrivateKey::from_bytes(&test.private).unwrap();
            let peer = p384::PublicKey::from_x962_uncompressed(&test.public)?;
            Ok(low::ct::into_public(private.diffie_hellman(&peer)?.0).to_vec())
        });
    }

    #[test]
    fn wycheproof_x25519() {
        for test in wycheproof::<EcdhTest>("x25519_test.json") {
            let private = x25519::StaticPrivateKey::try_from_slice(&test.private).unwrap();
            let result = x25519::PublicKey::try_from_slice(&test.public)
                .and_then(|peer| private.diffie_hellman(&peer))
                .map(|shared| low::ct::into_public(shared.0));
            match (test.result, &result) {
                (Expected::Acceptable, Err(Error::NotOnCurve))
                    if test.has_flag("ZeroSharedSecret") => {}
                (Expected::Valid | Expected::Acceptable, Ok(shared)) => {
                    assert_eq!(&shared[..], &test.shared, "{}", test.id)
                }
                _ => panic!("{}: expected {:?} got {:?}", test.id, test.result, result),
            }
        }
    }

    // A fixed private key needs crate access, so this differential test lives
    // here rather than beside the other curves' in `tests/crosschecks.rs`.
    mod x25519_crosscheck {
        use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
        use proptest::prelude::*;

        use super::*;

        // Any 32 bytes is a private key or a peer's u-coordinate, including
        // coordinates at or above the field prime. The fixed peers have small
        // order, which both sides refuse for the all-zero secret they give.
        fn peer() -> impl Strategy<Value = [u8; 32]> {
            let mut one = [0u8; 32];
            one[0] = 1;
            prop_oneof![
                8 => any::<[u8; 32]>(),
                1 => Just([0u8; 32]),
                1 => Just(one),
            ]
        }

        proptest! {
            #[test]
            fn ecdh(private in any::<[u8; 32]>(), peer in peer()) {
                let ours = x25519::StaticPrivateKey::from_array(&private);
                let theirs = PrivateKey::from_private_key(&X25519, &private).unwrap();
                let theirs_public = theirs.compute_public_key().unwrap();
                prop_assert_eq!(&ours.public_key().as_bytes()[..], theirs_public.as_ref());

                let ours_secret = ours
                    .diffie_hellman(&x25519::PublicKey::from_array(&peer))
                    .map(|secret| low::ct::into_public(secret.0));
                let theirs_secret = agreement::agree(
                    &theirs,
                    UnparsedPublicKey::new(&X25519, peer),
                    (),
                    |secret| Ok(secret.to_vec()),
                );
                match (ours_secret, theirs_secret) {
                    (Ok(ours), Ok(theirs)) => prop_assert_eq!(&ours[..], &theirs[..]),
                    (Err(_), Err(())) => {}
                    (ours, theirs) => prop_assert!(
                        false,
                        "rind gave {:?}, aws-lc-rs {:?}",
                        ours.err(),
                        theirs.err()
                    ),
                }
            }
        }
    }
}
