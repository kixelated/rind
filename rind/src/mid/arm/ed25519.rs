// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! rfc8032 `PureEd25519` over curve25519-dalek's point and scalar arithmetic.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::{Scalar, clamp_integer};

use crate::error::Error;
use crate::low;
use crate::mid::sha2::Sha512Context;

// Both are plain limbs or bytes, so all zeroes is a value they can hold.
impl low::Zeroable for Scalar {}
impl low::Zeroable for EdwardsPoint {}

pub(crate) struct SigningKey {
    seed: [u8; 32],
    s: Scalar,
    prefix: [u8; 32],
    verifying_key: VerifyingKey,
}

impl SigningKey {
    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        low::ct::secret_slice(seed);

        // Step: rfc8032 5.1.5.1, 5.1.5.2
        // `h := SHA512(seed)`
        // `s := ed25519-clamp(h[0..32])`
        // `prefix := h[32..64]`
        let mut h = ed25519_digest(seed, &[], &[]);
        let (lower, upper) = h.split_at(32);
        // `s` is reduced, but `[s]B` is unchanged since `B` has order `L`.
        let s = Scalar::from_bytes_mod_order(clamp_integer(lower.try_into().unwrap()));
        let prefix = upper.try_into().unwrap();
        // aws-lc wipes the hashed seed.
        low::zeroise(&mut h);

        // Step: rfc8032 5.1.5.3, 5.1.5.4
        let point = EdwardsPoint::mul_base(&s);

        Self {
            seed: *seed,
            s,
            prefix,
            verifying_key: low::ct::into_public(VerifyingKey {
                bytes: point.compress().0,
                point,
            }),
        }
    }

    /// `PureEd25519` signing
    pub(crate) fn sign(&self, msg: &[u8]) -> [u8; 64] {
        // Step: rfc8032 5.1.6.2
        // `r := SHA-512(dom2(F, C) || prefix || msg) mod L`
        let mut r_hash = ed25519_digest(&self.prefix, msg, &[]);
        let mut r = Scalar::from_bytes_mod_order_wide(&r_hash);

        // Step: rfc8032 5.1.6.3
        // `R := [r]B`
        let sig_r = EdwardsPoint::mul_base(&r).compress().0;

        // Step: rfc8032 5.1.6.4
        // `k := SHA512(dom2(F, C) || R || A || PH(msg)) mod L`
        let k = ed25519_digest(&sig_r, &self.verifying_key.bytes, msg);
        let k = Scalar::from_bytes_mod_order_wide(&k);

        // Step: rfc8032 5.1.6.5
        // `S := (k * s + r) mod L`
        let s = k * self.s + r;
        // aws-lc wipes the nonce as a hash and reduced. It wipes the
        // challenge `k` too, but any verifier recomputes that.
        low::zeroise(&mut r_hash);
        low::zeroise_value(&mut r);

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&sig_r);
        sig[32..].copy_from_slice(s.as_bytes());
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
        low::zeroise_value(&mut self.s);
        low::zeroise(&mut self.prefix);
        // clearly not necessary, but makes zeroisation easier to test
        low::zeroise_value(&mut self.verifying_key.point);
        low::zeroise(&mut self.verifying_key.bytes);
    }
}

#[derive(Clone, Debug)]
pub(crate) struct VerifyingKey {
    bytes: [u8; 32],
    point: EdwardsPoint,
}

impl VerifyingKey {
    /// Decodes `bytes`, refusing an encoding that is off the curve or not
    /// canonical, as s2n-bignum's `edwards25519_decode` does on the other
    /// backends.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::WrongLength)?;

        // dalek reduces `y` modulo `p`, and takes a set sign bit on `x = 0`
        // (where `y = ±1`) as `x = 0`, so each point would have a second
        // encoding.
        let mut y = bytes;
        y[31] &= 0x7f;
        let negative_zero = bytes[31] >> 7 == 1 && (y == ONE || y == P_MINUS_ONE);
        if !is_below_p(&y) || negative_zero {
            return Err(Error::NotOnCurve);
        }

        let point = CompressedEdwardsY(bytes)
            .decompress()
            .ok_or(Error::NotOnCurve)?;
        Ok(Self { bytes, point })
    }

    /// `PureEd25519` signature verification
    pub(crate) fn verify(&self, sig: &[u8; 64], msg: &[u8]) -> Result<(), Error> {
        // Step: rfc8032 5.1.7.1 (A' := A is an invariant for `self`)
        let (sig_r, s) = sig.split_at(32);

        // S must be in the range [0, order) to prevent signature malleability.
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s.try_into().unwrap()))
            .ok_or(Error::BadSignature)?;

        // Step: rfc8032 5.1.7.2
        // `k := SHA512(dom2(F, C) || R || A || msg)`
        let k = Scalar::from_bytes_mod_order_wide(&ed25519_digest(sig_r, &self.bytes, msg));

        // Step: rfc8032 5.1.7.3
        // `R := [S]B - [k]A`, compared in its encoding.
        let r = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &-self.point, &s);
        if r.compress().0 == sig_r {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }

    pub(crate) fn as_bytes(&self) -> [u8; 32] {
        self.bytes
    }
}

/// `y = 1`, little-endian.
const ONE: [u8; 32] = {
    let mut one = [0u8; 32];
    one[0] = 1;
    one
};

/// `y = p - 1 = 2^255 - 20`, little-endian.
const P_MINUS_ONE: [u8; 32] = {
    let mut p = [0xffu8; 32];
    p[0] = 0xec;
    p[31] = 0x7f;
    p
};

/// Whether the little-endian `y` is below `p = 2^255 - 19`.
fn is_below_p(y: &[u8; 32]) -> bool {
    y.iter().rev().cmp(P_MINUS_ONE.iter().rev()).is_le()
}

/// This is `H(..) := SHA-512(dom2(phflag, ctx) || ..)` from rfc8032 5.1, with
/// phflag=0 and ctx="".
///
/// `dom2(phflag, ctx)` is therefore empty, so this is simply the concatenation
/// of the arguments.
fn ed25519_digest(x1: &[u8], x2: &[u8], x3: &[u8]) -> [u8; 64] {
    let mut h = Sha512Context::new();
    h.update(x1);
    h.update(x2);
    h.update(x3);
    h.finish()
}
