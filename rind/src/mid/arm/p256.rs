// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! P-256 over HACL*'s `P256`, which exposes whole operations: key
//! validation, Diffie-Hellman, and ECDSA over a caller-supplied nonce.

use core::fmt;

use libcrux_hacl_rs::bignum::bignum256;

use super::util;
use crate::Error;
use crate::low;
use crate::mid::rng::{RandomSource, SystemRandom};

/// A P-256 public key.
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// `x || y`, big-endian.
    xy: [u8; 64],
}

impl PublicKey {
    pub(crate) const BYTES: usize = 65;

    /// Create an P-256 [`PublicKey`] from a byte slice.
    ///
    /// This must be exactly 65 bytes in length, using the X9.62
    /// uncompressed encoding.  An error is returned if a coordinate
    /// is not below the field prime, or the point is not on the curve.
    pub fn from_x962_uncompressed(bytes: &[u8]) -> Result<Self, Error> {
        let _entry = low::Entry::new_public();
        match bytes.first() {
            Some(&0x04) => (),
            Some(_) => return Err(Error::NotUncompressed),
            None => return Err(Error::WrongLength),
        }

        let xy: [u8; 64] = bytes[1..].try_into().map_err(|_| Error::WrongLength)?;
        match libcrux_p256::validate_public_key(&xy) {
            true => Ok(Self { xy }),
            false => Err(Error::NotOnCurve),
        }
    }

    /// Encodes this public key using the X9.62 uncompressed encoding.
    pub fn as_bytes_uncompressed(&self) -> [u8; Self::BYTES] {
        let _entry = low::Entry::new_public();
        uncompressed(&self.xy)
    }

    pub(crate) fn raw_ecdsa_verify(&self, r: &Scalar, s: &Scalar, e: &Scalar) -> Result<(), Error> {
        let e = e.as_bytes();
        match libcrux_p256::ecdsa_verif_without_hash(
            e.len() as u32,
            &e,
            &self.xy,
            &r.as_bytes(),
            &s.as_bytes(),
        ) {
            true => Ok(()),
            false => Err(Error::BadSignature),
        }
    }
}

/// A P-256 ephemeral private key.
///
/// This can be used at most once for the Diffie-Hellman operation,
/// and that is the most common usage pattern for key exchange.
pub(crate) struct PrivateKey {
    scalar: Scalar,
}

impl PrivateKey {
    /// Generate a new random private key using the system RNG.
    pub(crate) fn new_random() -> Result<Self, Error> {
        Self::generate(&mut SystemRandom)
    }

    /// Derive the corresponding public key, and return it in
    /// X9.62 uncompressed encoding.
    pub(crate) fn public_key_uncompressed(&self) -> [u8; PublicKey::BYTES] {
        let _entry = low::Entry::new_secret();
        uncompressed(&self.public_point())
    }

    /// Do the Diffie-Hellman operation.
    ///
    /// `peer` is the peer's public key (and this type means it was
    /// already checked to be on the curve.)
    ///
    /// Returns a [`SharedSecret`].  May return an error in fault conditions.
    pub(crate) fn diffie_hellman(&self, peer: &PublicKey) -> Result<SharedSecret, Error> {
        let _entry = low::Entry::new_secret();
        let d = self.scalar.as_bytes();
        let mut point = [0u8; 64];
        let ok = libcrux_p256::dh_responder(&mut point, &peer.xy, &d);
        let mut secret = SharedSecret([0u8; 32]);
        secret.0.copy_from_slice(&point[..32]);
        low::zeroise(&mut point);
        match ok {
            true => Ok(secret),
            false => Err(Error::NotOnCurve),
        }
    }

    /// `x || y` of the public key.
    fn public_point(&self) -> [u8; 64] {
        let d = self.scalar.as_bytes();
        let mut xy = [0u8; 64];
        let ok = libcrux_p256::dh_initiator(&mut xy, &d);
        match low::ct::into_public(ok) {
            true => low::ct::into_public(xy),
            false => panic!("internal fault"),
        }
    }

    pub(crate) fn generate(rng: &mut dyn RandomSource) -> Result<Self, Error> {
        let _entry = low::Entry::new_secret();
        for _ in 0..64 {
            let mut r = [0u8; Scalar::BYTES];
            rng.fill(&mut r)?;
            low::ct::secret_slice(&r);
            if let Ok(p) = Self::from_bytes(&r) {
                return Ok(p);
            }
        }

        Err(Error::RngFailed)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Scalar::from_bytes_checked(bytes).map(|scalar| Self {
            scalar: low::ct::into_secret(scalar),
        })
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey").finish_non_exhaustive()
    }
}

/// A P-256 static private key.
///
/// This can be used many times for the Diffie-Hellman operation.
/// It can also be serialized and deserialized.
pub struct StaticPrivateKey(PrivateKey);

impl StaticPrivateKey {
    /// Generate a new random private key using the system RNG.
    #[cfg(test)]
    pub(crate) fn new_random() -> Result<Self, Error> {
        PrivateKey::generate(&mut SystemRandom).map(Self)
    }

    /// Decode a private key from `bytes`.
    ///
    /// `bytes` may be larger or smaller than the size of `n`: excess bytes
    /// must be zero.  If given a variable-sized input, this is deemed a
    /// non-secret property.  Prefer to use fixed-sized inputs.
    ///
    /// An error is returned if the magnitude of the value is larger than
    /// `n` (ie, the input is never reduced mod n),  or the value is zero.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let _entry = low::Entry::new_secret();
        PrivateKey::from_bytes(bytes).map(Self)
    }

    /// Return a fixed-length encoding of this private key's value, still secret.
    pub(crate) fn secret_bytes(&self) -> [u8; Scalar::BYTES] {
        self.0.scalar.as_bytes()
    }

    /// Derive the corresponding public key, and return it in
    /// X9.62 uncompressed encoding.
    pub(crate) fn public_key_uncompressed(&self) -> [u8; PublicKey::BYTES] {
        let _entry = low::Entry::new_secret();
        uncompressed(&self.0.public_point())
    }

    /// Do the Diffie-Hellman operation.
    ///
    /// `peer` is the peer's public key (and this type means it was
    /// already checked to be on the curve.)
    ///
    /// Returns a [`SharedSecret`].  May return an error in fault conditions.
    #[cfg(test)]
    pub(crate) fn diffie_hellman(&self, peer: &PublicKey) -> Result<SharedSecret, Error> {
        let _entry = low::Entry::new_secret();
        self.0.diffie_hellman(peer)
    }

    pub(crate) fn generate(rng: &mut dyn RandomSource) -> Result<Self, Error> {
        let _entry = low::Entry::new_secret();
        PrivateKey::generate(rng).map(Self)
    }

    pub(crate) fn public_key_x_scalar(&self) -> Scalar {
        let _entry = low::Entry::new_secret();
        Scalar::from_bytes_reduced(&self.0.public_point()[..32]).unwrap()
    }

    /// Returns `s` for nonce `k`, digest `e`, and `r`, which must be `k`'s
    /// [`Self::public_key_x_scalar`].
    ///
    /// HACL* recomputes `r` from `k` itself, so the passed `r` is unused.
    pub(crate) fn raw_ecdsa_sign(&self, k: &Self, e: &Scalar, _r: &Scalar) -> Scalar {
        let d = self.0.scalar.as_bytes();
        let k = k.0.scalar.as_bytes();
        let e = e.as_bytes();
        let mut sig = [0u8; 64];
        // This fails only for a zero `r` or `s`; the caller already refused a
        // zero `r`, and a zero `s` (probability 2^-256) makes the signature
        // invalid either way.
        let ok = libcrux_p256::ecdsa_sign_p256_without_hash(&mut sig, e.len() as u32, &e, &d, &k);
        let sig = low::ct::into_public(sig);
        match low::ct::into_public(ok) {
            true => Scalar::from_bytes_checked(&sig[32..]).unwrap_or_default(),
            false => Scalar::default(),
        }
    }
}

/// A shared secret output from a P-256 Diffie-Hellman operation.
pub(crate) struct SharedSecret(pub(crate) [u8; 32]);

impl Drop for SharedSecret {
    fn drop(&mut self) {
        low::zeroise(&mut self.0);
    }
}

/// An integer mod the curve order `n`, as little-endian words.
#[derive(Default)]
pub struct Scalar([u64; 4]);

impl Scalar {
    pub(crate) const BYTES: usize = 32;

    /// Create a scalar from the given slice, which can be any size.
    ///
    /// If it is larger than 32 bytes, the leading bytes must be
    /// zero (this is deemed a non-secret property).
    ///
    /// This returns an error if the scalar is zero or larger than
    /// the curve order.
    pub(crate) fn from_bytes_checked(bytes: &[u8]) -> Result<Self, Error> {
        let full = Self(util::big_endian_slice_any_size_to_u64x4(bytes).ok_or(Error::WrongLength)?);
        let in_range = bignum256::lt_mask(&full.0, &CURVE_ORDER) == u64::MAX;
        // Whether a scalar is in range is public: a key or signature is refused
        // on it, and a rejected nonce candidate says nothing of the one accepted.
        match low::ct::into_public(in_range & !full.is_zero()) {
            true => Ok(full),
            false => Err(Error::OutOfRange),
        }
    }

    pub(crate) fn from_bytes_reduced(bytes: &[u8]) -> Result<Self, Error> {
        let mut wide = [0u64; 8];
        wide[..4].copy_from_slice(
            &util::big_endian_slice_any_size_to_u64x4(bytes).ok_or(Error::WrongLength)?,
        );
        let mut r = Self::default();
        // Fails only for an even or unit modulus.
        bignum256::r#mod(&CURVE_ORDER, &wide, &mut r.0);
        Ok(r)
    }

    pub(crate) fn as_bytes(&self) -> [u8; Self::BYTES] {
        util::u64x4_to_big_endian(&self.0)
    }

    /// Private test for zero
    pub(crate) fn is_zero(&self) -> bool {
        low::bignum_eq(&self.0, &[0; 4])
    }
}

impl Drop for Scalar {
    fn drop(&mut self) {
        low::zeroise(&mut self.0);
    }
}

fn uncompressed(xy: &[u8; 64]) -> [u8; PublicKey::BYTES] {
    let mut r = [0u8; PublicKey::BYTES];
    r[0] = 0x04;
    r[1..].copy_from_slice(xy);
    r
}

/// The curve order `n`, as little-endian words.
const CURVE_ORDER: [u64; 4] = [
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
];

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn scalar_range() {
        let n = util::u64x4_to_big_endian(&CURVE_ORDER);
        assert_eq!(
            Scalar::from_bytes_checked(&n).err(),
            Some(Error::OutOfRange)
        );
        assert_eq!(
            Scalar::from_bytes_checked(&[0; 32]).err(),
            Some(Error::OutOfRange)
        );
        let mut n_minus_1 = n;
        n_minus_1[31] -= 1;
        assert!(Scalar::from_bytes_checked(&n_minus_1).is_ok());
    }

    #[test]
    fn scalar_reduction() {
        let n = util::u64x4_to_big_endian(&CURVE_ORDER);
        assert!(Scalar::from_bytes_reduced(&n).unwrap().is_zero());

        let mut n_plus_1 = n;
        n_plus_1[31] += 1;
        assert_eq!(
            Scalar::from_bytes_reduced(&n_plus_1).unwrap().0,
            [1, 0, 0, 0]
        );

        let max = Scalar::from_bytes_reduced(&[0xff; 32]).unwrap();
        assert_eq!(
            max.0,
            [0x0c46_353d_039c_daae, 0x4319_0552_58e8_617b, 0, 0xffff_ffff]
        );
    }

    #[test]
    fn public_key_encoding() {
        let mut bad = [0u8; 65];
        assert_eq!(
            PublicKey::from_x962_uncompressed(&bad).err(),
            Some(Error::NotUncompressed)
        );
        bad[0] = 0x04;
        assert_eq!(
            PublicKey::from_x962_uncompressed(&bad).err(),
            Some(Error::NotOnCurve)
        );
        assert_eq!(
            PublicKey::from_x962_uncompressed(&bad[..64]).err(),
            Some(Error::WrongLength)
        );
        assert_eq!(
            PublicKey::from_x962_uncompressed(&[]).err(),
            Some(Error::WrongLength)
        );

        let key = StaticPrivateKey::new_random().unwrap();
        let encoded = key.public_key_uncompressed();
        let decoded = PublicKey::from_x962_uncompressed(&encoded).unwrap();
        assert_eq!(decoded.as_bytes_uncompressed(), encoded);
    }
}
