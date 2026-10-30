// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

pub(crate) use rsa_priv::KeySize;

use crate::Error;
use crate::error::KeyFormatError;
use crate::high::asn1::{self, Type, pkix};
use crate::high::hash::{self, Hash};
use crate::high::{pkcs1, pkcs8};
use crate::low::Entry;
use crate::low::PosInt;
use crate::mid::rng::SystemRandom;
use crate::mid::{rsa_priv, rsa_pub};

/// An RSA verification public key.
///
/// Keys supported by this library have public moduli between
/// 2048- and 8192-bits.
#[derive(Debug)]
pub(crate) struct VerifyingKey(rsa_pub::RsaPublicKey);

impl VerifyingKey {
    /// Decodes an RSA public verification key from PKCS#1 DER format.
    ///
    /// This format is defined in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.1)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub(crate) fn from_pkcs1_der(bytes: &[u8]) -> Result<Self, Error> {
        let _entry = Entry::new_public();
        let decoded = pkix::RSAPublicKey::from_bytes(bytes).map_err(KeyFormatError::Asn1)?;

        if decoded.modulus.is_negative() {
            return Err(Error::OutOfRange);
        }

        let n = PosInt::from_bytes(decoded.modulus.as_ref())?;
        let e = decoded
            .publicExponent
            .as_usize()
            .map_err(KeyFormatError::Asn1)?;
        let e = e.try_into().map_err(|_| Error::OutOfRange)?;

        let pub_key = rsa_pub::RsaPublicKey::new(n, e)?;

        Ok(Self(pub_key))
    }

    /// Encodes this RSA verification key in SubjectPublicKeyInfo DER format.
    ///
    /// The `SubjectPublicKeyInfo.algorithm` identifier is `rsaEncryption`.
    ///
    /// `output` is the output buffer, and the encoding is written to the start
    /// of this buffer.  An error is returned if the encoding is larger than
    /// the supplied buffer.  Otherwise, on success, the range containing the
    /// encoding is returned.
    pub(crate) fn to_spki_der<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let _entry = Entry::new_public();

        let mut pub_key_buffer = [0u8; rsa_pub::MAX_PUBLIC_MODULUS_BYTES + 64];
        let pub_key_buffer = self.to_pkcs1_der(&mut pub_key_buffer)?;

        let spki = pkix::SubjectPublicKeyInfo {
            algorithm: pkix::AlgorithmIdentifier {
                algorithm: asn1::oid::rsaEncryption.clone(),
                parameters: Some(asn1::Any::Null(asn1::Null)),
            },
            subjectPublicKey: asn1::BitString::new(pub_key_buffer),
        };

        let len = spki
            .encode(&mut asn1::Encoder::new(output))
            .map_err(|_| Error::WrongLength)?;
        Ok(&output[..len])
    }

    /// Encodes this RSA verification key to PKCS#1 DER format.
    ///
    /// `output` is the output buffer, and the encoding is written to the start
    /// of this buffer.  An error is returned if the encoding is larger than
    /// the supplied buffer.  Otherwise, on success, the range containing the
    /// encoding is returned.
    pub(crate) fn to_pkcs1_der<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let _entry = Entry::new_public();

        let mut buffer = [0u8; rsa_pub::MAX_PUBLIC_MODULUS_BYTES + 1];
        let public_modulus = self.0.n.to_bytes_asn1(&mut buffer)?;
        let public_exponent = self.0.e.to_be_bytes();

        let pub_key = pkix::RSAPublicKey {
            modulus: asn1::Integer::new(public_modulus),
            publicExponent: asn1::Integer::new(&public_exponent),
        };
        let used = pub_key
            .encode(&mut asn1::Encoder::new(output))
            .map_err(|_| Error::WrongLength)?;
        Ok(&output[..used])
    }

    /// Verifies `signature`, using RSASSA-PKCS1-v1_5 with SHA-256.
    ///
    /// `message` is the (unhashed) signed message.  It is hashed
    /// using SHA-256 by this function.
    ///
    /// [`Error::BadSignature`] is returned if the signature is invalid.
    pub(crate) fn verify_pkcs1_sha256(
        &self,
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), Error> {
        let _entry = Entry::new_public();
        let hash = hash::Sha256::hash(message);
        self._verify_pkcs1(signature, pkcs1::DIGESTINFO_SHA256, hash.as_ref())
    }

    /// Verifies `signature`, using RSASSA-PKCS1-v1_5 with SHA-384.
    ///
    /// `message` is the (unhashed) signed message.  It is hashed
    /// using SHA-384 by this function.
    ///
    /// [`Error::BadSignature`] is returned if the signature is invalid.
    pub(crate) fn verify_pkcs1_sha384(
        &self,
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), Error> {
        let _entry = Entry::new_public();
        let hash = hash::Sha384::hash(message);
        self._verify_pkcs1(signature, pkcs1::DIGESTINFO_SHA384, hash.as_ref())
    }

    /// Verifies `signature`, using RSASSA-PKCS1-v1_5 with SHA-512.
    ///
    /// `message` is the (unhashed) signed message.  It is hashed
    /// using SHA-512 by this function.
    ///
    /// [`Error::BadSignature`] is returned if the signature is invalid.
    pub(crate) fn verify_pkcs1_sha512(
        &self,
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), Error> {
        let _entry = Entry::new_public();
        let hash = hash::Sha512::hash(message);
        self._verify_pkcs1(signature, pkcs1::DIGESTINFO_SHA512, hash.as_ref())
    }

    fn _verify_pkcs1(
        &self,
        signature: &[u8],
        digest_info: &[u8],
        hash: &[u8],
    ) -> Result<(), Error> {
        if signature.len() != self.0.modulus_len_bytes() {
            return Err(Error::BadSignature);
        }
        let c = PosInt::from_bytes(signature).map_err(|_| Error::BadSignature)?;
        let m = self.0.public_op(c).map_err(|_| Error::BadSignature)?;

        let mut m_bytes = [0u8; rsa_pub::MAX_PUBLIC_MODULUS_BYTES];
        let m_bytes = i2osp(&m, &mut m_bytes[..self.0.modulus_len_bytes()])?;

        let mut actual_m = [0u8; rsa_pub::MAX_PUBLIC_MODULUS_BYTES];
        let actual_m = &mut actual_m[..self.0.modulus_len_bytes()];
        pkcs1::encode_pkcs1_sig(actual_m, digest_info, hash);

        match actual_m == m_bytes {
            true => Ok(()),
            false => Err(Error::BadSignature),
        }
    }

    /// Verifies `signature`, using RSASSA-PSS with SHA-256.
    ///
    /// `saltLength` is fixed as 32 bytes; this is the most common
    /// option when used with SHA-256.
    ///
    /// `message` is the (unhashed) signed message.  It is hashed
    /// using SHA-256 by this function.
    ///
    /// [`Error::BadSignature`] is returned if the signature is invalid.
    ///
    /// RSASSA-PSS is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub(crate) fn verify_pss_sha256(&self, signature: &[u8], message: &[u8]) -> Result<(), Error> {
        let _entry = Entry::new_public();
        self._verify_pss::<hash::Sha256>(signature, message)
    }

    /// Verifies `signature`, using RSASSA-PSS with SHA-384.
    ///
    /// `saltLength` is fixed as 48 bytes; this is the most common
    /// option when used with SHA-384.
    ///
    /// `message` is the (unhashed) signed message.  It is hashed
    /// using SHA-384 by this function.
    ///
    /// [`Error::BadSignature`] is returned if the signature is invalid.
    ///
    /// RSASSA-PSS is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub(crate) fn verify_pss_sha384(&self, signature: &[u8], message: &[u8]) -> Result<(), Error> {
        let _entry = Entry::new_public();
        self._verify_pss::<hash::Sha384>(signature, message)
    }

    /// Verifies `signature`, using RSASSA-PSS with SHA-512.
    ///
    /// `saltLength` is fixed as 64 bytes; this is the most common
    /// option when used with SHA-512.
    ///
    /// `message` is the (unhashed) signed message.  It is hashed
    /// using SHA-512 by this function.
    ///
    /// [`Error::BadSignature`] is returned if the signature is invalid.
    ///
    /// RSASSA-PSS is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub(crate) fn verify_pss_sha512(&self, signature: &[u8], message: &[u8]) -> Result<(), Error> {
        let _entry = Entry::new_public();
        self._verify_pss::<hash::Sha512>(signature, message)
    }

    fn _verify_pss<H: Hash>(&self, signature: &[u8], message: &[u8]) -> Result<(), Error> {
        let hash = H::hash(message);

        if signature.len() != self.0.modulus_len_bytes() {
            return Err(Error::BadSignature);
        }
        let c = PosInt::from_bytes(signature).map_err(|_| Error::BadSignature)?;
        let m = self.0.public_op(c).map_err(|_| Error::BadSignature)?;

        // RFC 8017 section 8.1.2: EM is only `ceil(emBits / 8)` octets, one
        // fewer than the modulus when its bit length is one more than a
        // multiple of eight, and `m` must fit them.
        let em_bits = self.0.modulus_len_bits() - 1;
        let mut em = [0u8; rsa_pub::MAX_PUBLIC_MODULUS_BYTES];
        let em = i2osp(&m, &mut em[..em_bits.div_ceil(8)]).map_err(|_| Error::BadSignature)?;

        pkcs1::verify_pss_sig::<H>(em, em_bits, hash.as_ref())
    }
}

/// An RSA signing private key.
///
/// Keys supported by this library have public moduli between
/// 2048- and 8192-bits.  Only two-prime RSA keys are supported.
pub(crate) struct SigningKey(rsa_priv::RsaPrivateKey);

impl SigningKey {
    /// Generates a new RSA signing key.
    ///
    /// `size` is the desired key size.  This library supports a selection of common key sizes.
    ///
    /// Key generation is a slow process, especially for larger key sizes.  As an indication,
    /// an 2048-bit key takes about 30 milliseconds, while an 8192-bit key may take 15 seconds or more.
    /// The time required is non-deterministic, and does not have an upper bound.
    ///
    /// # Warning
    /// Unlike other private key operations in rind, RSA key generation is not side-channel safe.
    /// Avoid generating keys in untrusted multi-tenant or physical environments.
    pub(crate) fn generate(size: KeySize) -> Result<Self, Error> {
        let _entry = Entry::new_secret();
        rsa_priv::RsaPrivateKey::generate(size, &mut SystemRandom, &mut SystemRandom)
            .map(SigningKey)
    }

    /// Decodes an RSA signing key from PKCS#1 DER format.
    ///
    /// This format is defined in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.2)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub(crate) fn from_pkcs1_der(bytes: &[u8]) -> Result<Self, Error> {
        let _entry = Entry::new_secret();
        let decoded = pkix::RSAPrivateKey::from_bytes(bytes).map_err(KeyFormatError::Asn1)?;

        if !matches!(decoded.version, pkix::Version::two_prime) {
            return Err(Error::OutOfRange);
        }

        if decoded.modulus.is_negative() {
            return Err(Error::OutOfRange);
        }

        let n = PosInt::from_bytes(decoded.modulus.as_ref())?;
        let e = decoded
            .publicExponent
            .as_usize()
            .map_err(KeyFormatError::Asn1)?;
        let e = e.try_into().map_err(|_| Error::OutOfRange)?;

        let p = PosInt::from_bytes(decoded.prime1.as_ref())?;
        let q = PosInt::from_bytes(decoded.prime2.as_ref())?;
        let d = PosInt::from_bytes(decoded.privateExponent.as_ref())?;
        let dp = PosInt::from_bytes(decoded.exponent1.as_ref())?;
        let dq = PosInt::from_bytes(decoded.exponent2.as_ref())?;
        let iqmp = PosInt::from_bytes(decoded.coefficient.as_ref())?;

        let priv_key = rsa_priv::RsaPrivateKey::new(p, q, d, dp, dq, iqmp, n, e)?;
        Ok(Self(priv_key))
    }

    /// Encodes an RSA signing key to PKCS#1 DER format.
    ///
    /// `output` is the output buffer, and the encoding is written to the start
    /// of this buffer.  An error is returned if the encoding is larger than
    /// the supplied buffer.  Otherwise, on success, the range containing the
    /// encoding is returned.
    pub(crate) fn to_pkcs1_der<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let _entry = Entry::new_secret();

        let mut buf = rsa_priv::RsaComponentsBuffer::default();
        let components = self.0.encode_components(&mut buf)?;

        let used = pkix::RSAPrivateKey {
            version: pkix::Version::two_prime,
            modulus: asn1::Integer::new(components.public_modulus),
            publicExponent: asn1::Integer::new(components.public_exponent),
            prime1: asn1::Integer::new(components.p),
            prime2: asn1::Integer::new(components.q),
            privateExponent: asn1::Integer::new(components.d),
            exponent1: asn1::Integer::new(components.dp),
            exponent2: asn1::Integer::new(components.dq),
            coefficient: asn1::Integer::new(components.iqmp),
        }
        .encode(&mut asn1::Encoder::new(output))
        .map_err(|_| Error::WrongLength)?;

        output.get(..used).ok_or(Error::WrongLength)
    }

    // this is an over-estimate
    const MAX_PKCS1_BUFFER_LEN: usize = rsa_priv::RsaComponentsBuffer::LEN + 128;

    /// Encodes an RSA signing key to PKCS#8 DER format.
    ///
    /// `output` is the output buffer, and the encoding is written to the start
    /// of this buffer.  An error is returned if the encoding is larger than
    /// the supplied buffer.  Otherwise, on success, the range containing the
    /// encoding is returned.
    pub(crate) fn to_pkcs8_der<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let _entry = Entry::new_secret();

        let mut pkcs1_buffer = [0u8; Self::MAX_PKCS1_BUFFER_LEN];

        pkcs8::Key::construct(
            self.to_pkcs1_der(&mut pkcs1_buffer)?,
            None,
            asn1::oid::rsaEncryption.clone(),
            Some(asn1::Any::Null(asn1::Null)),
        )
        .encode(output)
    }

    /// Decodes an RSA signing key from PKCS#8 DER format.
    ///
    /// This format is defined in
    /// [RFC5208](https://datatracker.ietf.org/doc/html/rfc5208#section-5)
    /// (and earlier standards, including the original PKCS#8 standard).
    ///
    /// `privateKeyAlgorithm` inside this encoding must be `rsaEncryption`.
    pub(crate) fn from_pkcs8_der(bytes: &[u8]) -> Result<Self, Error> {
        let _entry = Entry::new_secret();
        pkcs8::Key::decode(
            bytes,
            &asn1::oid::rsaEncryption,
            Some(asn1::Any::Null(asn1::Null)),
        )
        .and_then(|k| Self::from_pkcs1_der(k.private_key()))
    }

    /// Returns the matching public key.
    pub(crate) fn public_key(&self) -> VerifyingKey {
        let _entry = Entry::new_public();
        VerifyingKey(self.0.public_key())
    }

    /// Returns the public modulus length, in bytes.
    pub(crate) fn modulus_len_bytes(&self) -> usize {
        let _entry = Entry::new_public();
        self.0.public_key().modulus_len_bytes()
    }

    /// Signs `message`, using RSASSA-PKCS1-v1_5 with SHA-256.
    ///
    /// The signature is written to the front of `signature`, is
    /// precisely [`Self::modulus_len_bytes()`] in length, and
    /// then the written-to slice is returned.
    ///
    /// RSASSA-PKCS1-v1_5 is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.2)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub(crate) fn sign_pkcs1_sha256<'a>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        let _entry = Entry::new_secret();
        let hash = hash::Sha256::hash(message);
        self._sign_pkcs1(signature, pkcs1::DIGESTINFO_SHA256, hash.as_ref())
    }

    /// Signs `message`, using RSASSA-PKCS1-v1_5 with SHA-384.
    ///
    /// The signature is written to the front of `signature`, is
    /// precisely [`Self::modulus_len_bytes()`] in length, and
    /// then the written-to slice is returned.
    ///
    /// RSASSA-PKCS1-v1_5 is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.2)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub(crate) fn sign_pkcs1_sha384<'a>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        let _entry = Entry::new_secret();
        let hash = hash::Sha384::hash(message);
        self._sign_pkcs1(signature, pkcs1::DIGESTINFO_SHA384, hash.as_ref())
    }

    /// Signs `message`, using RSASSA-PKCS1-v1_5 with SHA-512.
    ///
    /// The signature is written to the front of `signature`, is
    /// precisely [`Self::modulus_len_bytes()`] in length, and
    /// then the written-to slice is returned.
    ///
    /// RSASSA-PKCS1-v1_5 is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.2)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub(crate) fn sign_pkcs1_sha512<'a>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        let _entry = Entry::new_secret();
        let hash = hash::Sha512::hash(message);
        self._sign_pkcs1(signature, pkcs1::DIGESTINFO_SHA512, hash.as_ref())
    }

    /// Signs `message`, using RSASSA-PSS with SHA-256.
    ///
    /// `saltLength` is fixed as 32 bytes; this is the most common
    /// option when used with SHA-256.
    ///
    /// The signature is written to the front of `signature`, is
    /// precisely [`Self::modulus_len_bytes()`] in length, and
    /// then the written-to slice is returned.
    ///
    /// RSASSA-PSS is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub(crate) fn sign_pss_sha256<'a>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        let _entry = Entry::new_secret();
        self._sign_pss::<hash::Sha256>(signature, message)
    }

    /// Signs `message`, using RSASSA-PSS with SHA-384.
    ///
    /// `saltLength` is fixed as 48 bytes; this is the most common
    /// option when used with SHA-384.
    ///
    /// The signature is written to the front of `signature`, is
    /// precisely [`Self::modulus_len_bytes()`] in length, and
    /// then the written-to slice is returned.
    ///
    /// RSASSA-PSS is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub(crate) fn sign_pss_sha384<'a>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        let _entry = Entry::new_secret();
        self._sign_pss::<hash::Sha384>(signature, message)
    }

    /// Signs `message`, using RSASSA-PSS with SHA-512.
    ///
    /// `saltLength` is fixed as 64 bytes; this is the most common
    /// option when used with SHA-512.
    ///
    /// The signature is written to the front of `signature`, is
    /// precisely [`Self::modulus_len_bytes()`] in length, and
    /// then the written-to slice is returned.
    ///
    /// RSASSA-PSS is described in
    /// [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1)
    /// (and earlier standards, including the original PKCS#1 standard).
    pub(crate) fn sign_pss_sha512<'a>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        let _entry = Entry::new_secret();
        self._sign_pss::<hash::Sha512>(signature, message)
    }

    fn _sign_pkcs1<'a>(
        &self,
        signature: &'a mut [u8],
        digest_info: &[u8],
        hash: &[u8],
    ) -> Result<&'a [u8], Error> {
        if signature.len() < self.0.modulus_len_bytes() {
            return Err(Error::OutOfRange);
        }

        let mut m = [0u8; rsa_pub::MAX_PUBLIC_MODULUS_BYTES];
        let m = &mut m[..self.0.modulus_len_bytes()];
        pkcs1::encode_pkcs1_sig(m, digest_info, hash);

        let m = PosInt::from_bytes(m)?;
        let c = self.0.private_op(&m).map_err(|_| Error::BadSignature)?;
        self.to_signature(&c, signature)
    }

    fn _sign_pss<'a, H: Hash>(
        &self,
        signature: &'a mut [u8],
        message: &[u8],
    ) -> Result<&'a [u8], Error> {
        if signature.len() < self.0.modulus_len_bytes() {
            return Err(Error::OutOfRange);
        }

        let hash = H::hash(message);

        // RFC 8017 section 8.1.1: EM is only `ceil(emBits / 8)` octets, one
        // fewer than the modulus when its bit length is one more than a
        // multiple of eight.
        let em_bits = self.0.modulus_len_bits() - 1;
        let mut em = [0u8; rsa_pub::MAX_PUBLIC_MODULUS_BYTES];
        let em = &mut em[..em_bits.div_ceil(8)];

        pkcs1::encode_pss_sig::<H>(em, em_bits, &mut SystemRandom, hash.as_ref())?;
        let m = PosInt::from_bytes(em)?;
        let c = self.0.private_op(&m).map_err(|_| Error::BadSignature)?;
        self.to_signature(&c, signature)
    }

    /// Writes `c` to the front of `signature` in exactly the modulus length.
    fn to_signature<'a, const N: usize>(
        &self,
        c: &PosInt<N>,
        signature: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let signature = signature
            .get_mut(..self.0.modulus_len_bytes())
            .ok_or(Error::OutOfRange)?;
        Ok(i2osp(c, signature)?)
    }
}

/// This is I2OSP: writes `x` to all of `out`, big-endian, however many of its
/// leading bytes are zero, and refuses an `x` that does not fit.
fn i2osp<'a, const N: usize>(x: &PosInt<N>, out: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
    let mut bytes = [0u8; rsa_pub::MAX_PUBLIC_MODULUS_BYTES];
    let bytes = x.to_bytes(&mut bytes)?;
    let (excess, bytes) = bytes.split_at(bytes.len().saturating_sub(out.len()));
    if excess.iter().any(|b| *b != 0) {
        return Err(Error::OutOfRange);
    }

    let (zeroes, value) = out.split_at_mut(out.len() - bytes.len());
    zeroes.fill(0);
    value.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::high::hmac_drbg::HmacDrbg;
    use crate::mid::rng::SliceRandomSource;

    fn check_all_algs(buf: &mut [u8], private: &SigningKey, public: &VerifyingKey) {
        let sig = private.sign_pkcs1_sha256(buf, b"hello").unwrap();
        public.verify_pkcs1_sha256(sig, b"hello").unwrap();

        let sig = private.sign_pkcs1_sha384(buf, b"hello").unwrap();
        public.verify_pkcs1_sha384(sig, b"hello").unwrap();

        let sig = private.sign_pkcs1_sha512(buf, b"hello").unwrap();
        public.verify_pkcs1_sha512(sig, b"hello").unwrap();

        let sig = private.sign_pss_sha256(buf, b"hello").unwrap();
        public.verify_pss_sha256(sig, b"hello").unwrap();

        let sig = private.sign_pss_sha384(buf, b"hello").unwrap();
        public.verify_pss_sha384(sig, b"hello").unwrap();

        let sig = private.sign_pss_sha512(buf, b"hello").unwrap();
        public.verify_pss_sha512(sig, b"hello").unwrap();
    }

    #[test]
    fn pairwise_rsa2048_sign_verify() {
        let private_key = SigningKey::from_pkcs1_der(include_bytes!("rsa/rsa2048.der")).unwrap();

        check_all_algs(&mut [0u8; 256], &private_key, &private_key.public_key());
    }

    #[test]
    fn verify_rejects_signature_not_modulus_length() {
        // RFC 8017 requires a signature of exactly k octets.  A zero byte
        // added to or removed from the front keeps its integer value, so
        // only the length check rejects these.
        type Sign = fn(&SigningKey, &mut [u8], &[u8]) -> Result<(), Error>;
        type Verify = fn(&VerifyingKey, &[u8], &[u8]) -> Result<(), Error>;
        let schemes: [(Sign, Verify); 2] = [
            (
                |k, s, m| k.sign_pkcs1_sha256(s, m).map(|_| ()),
                VerifyingKey::verify_pkcs1_sha256,
            ),
            (
                |k, s, m| k.sign_pss_sha256(s, m).map(|_| ()),
                VerifyingKey::verify_pss_sha256,
            ),
        ];

        let private_key = SigningKey::from_pkcs1_der(include_bytes!("rsa/rsa2048.der")).unwrap();
        let public_key = private_key.public_key();

        for (sign, verify) in schemes {
            let mut signature = [0u8; 257];
            for i in 0u32.. {
                let message = i.to_be_bytes();
                sign(&private_key, &mut signature[1..], &message).unwrap();
                assert_eq!(
                    verify(&public_key, &signature, &message),
                    Err(Error::BadSignature)
                );

                // About one signature in 256 starts with a zero byte.
                if signature[1] == 0 {
                    verify(&public_key, &signature[1..], &message).unwrap();
                    assert_eq!(
                        verify(&public_key, &signature[2..], &message),
                        Err(Error::BadSignature)
                    );
                    break;
                }
            }
        }
    }

    #[test]
    fn pairwise_rsa2048_sign_verify_pkcs8() {
        let private_key =
            SigningKey::from_pkcs8_der(include_bytes!("rsa/rsa2048.pkcs8.der")).unwrap();

        check_all_algs(&mut [0u8; 256], &private_key, &private_key.public_key());
    }

    #[test]
    fn pairwise_rsa3072_sign_verify() {
        let private_key = SigningKey::from_pkcs1_der(include_bytes!("rsa/rsa3072.der")).unwrap();

        check_all_algs(&mut [0u8; 384], &private_key, &private_key.public_key());
    }

    #[test]
    fn pairwise_rsa4096_sign_verify() {
        let private_key = SigningKey::from_pkcs1_der(include_bytes!("rsa/rsa4096.der")).unwrap();

        check_all_algs(&mut [0u8; 512], &private_key, &private_key.public_key());
    }

    #[test]
    fn pairwise_rsa6144_sign_verify() {
        let private_key = SigningKey::from_pkcs1_der(include_bytes!("rsa/rsa6144.der")).unwrap();

        check_all_algs(&mut [0u8; 768], &private_key, &private_key.public_key());
    }

    #[test]
    fn pairwise_rsa8192_sign_verify() {
        let private_key = SigningKey::from_pkcs1_der(include_bytes!("rsa/rsa8192.der")).unwrap();

        check_all_algs(&mut [0u8; 1024], &private_key, &private_key.public_key());
    }

    /// Moduli that are not a whole number of words: 2049 bits makes PSS's
    /// encoded message a byte shorter than the modulus, 2050 bits masks seven
    /// of its top bits, and 2056 bits is a whole number of bytes.
    const ODD_SIZE_KEYS: [&[u8]; 3] = [
        include_bytes!("rsa/rsa2049.pkcs8.der"),
        include_bytes!("rsa/rsa2050.pkcs8.der"),
        include_bytes!("rsa/rsa2056.pkcs8.der"),
    ];

    #[test]
    fn pairwise_odd_size_sign_verify() {
        for der in ODD_SIZE_KEYS {
            let private_key = SigningKey::from_pkcs8_der(der).unwrap();

            check_all_algs(&mut [0u8; 257], &private_key, &private_key.public_key());
        }
    }

    #[test]
    fn pairwise_key_formatting() {
        check_pkcs1(include_bytes!("rsa/rsa2048.der"));
        check_pkcs1(include_bytes!("rsa/rsa3072.der"));
        check_pkcs1(include_bytes!("rsa/rsa4096.der"));
        check_pkcs1(include_bytes!("rsa/rsa6144.der"));
        check_pkcs1(include_bytes!("rsa/rsa8192.der"));

        check_pkcs8(include_bytes!("rsa/rsa2048.pkcs8.der"));
        check_pkcs8(include_bytes!("rsa/rsa3072.pkcs8.der"));
        check_pkcs8(include_bytes!("rsa/rsa4096.pkcs8.der"));
        check_pkcs8(include_bytes!("rsa/rsa6144.pkcs8.der"));
        check_pkcs8(include_bytes!("rsa/rsa8192.pkcs8.der"));
        for der in ODD_SIZE_KEYS {
            check_pkcs8(der);
        }
    }

    fn check_pkcs1(pkcs1_der: &[u8]) {
        let decoded = SigningKey::from_pkcs1_der(pkcs1_der).unwrap();
        let mut buffer = [0u8; SigningKey::MAX_PKCS1_BUFFER_LEN];
        let encoded = decoded.to_pkcs1_der(&mut buffer).unwrap();
        assert_eq!(encoded, pkcs1_der);
        assert_eq!(
            decoded.to_pkcs1_der(&mut buffer[..pkcs1_der.len() - 1]),
            Err(Error::WrongLength)
        );
        let public_key = decoded.public_key();
        assert_eq!(
            public_key.to_pkcs1_der(&mut [0u8; 8]),
            Err(Error::WrongLength)
        );
        assert_eq!(
            public_key.to_spki_der(&mut [0u8; 8]),
            Err(Error::WrongLength)
        );
    }

    fn check_pkcs8(pkcs8_der: &[u8]) {
        let decoded = SigningKey::from_pkcs8_der(pkcs8_der).unwrap();
        let mut buffer = [0u8; SigningKey::MAX_PKCS1_BUFFER_LEN];
        let encoded = decoded.to_pkcs8_der(&mut buffer).unwrap();
        assert_eq!(encoded, pkcs8_der);
        assert_eq!(
            decoded.to_pkcs8_der(&mut buffer[..pkcs8_der.len() - 1]),
            Err(Error::WrongLength)
        );
    }

    /// Every backend makes the same decisions from the same random input,
    /// so generates the same key.
    #[test]
    fn key_generation_known_answer() {
        let candidates = include_str!("../testdata/rsa.bench.2048.txt")
            .split_whitespace()
            .flat_map(|line| hex::decode(line).unwrap())
            .collect::<Vec<_>>();
        let key = SigningKey(
            rsa_priv::RsaPrivateKey::generate(
                KeySize::Rsa2048,
                &mut SliceRandomSource(&candidates),
                &mut HmacDrbg::<hash::Sha256>::new(b"", b"", b""),
            )
            .unwrap(),
        );
        let mut buffer = [0u8; SigningKey::MAX_PKCS1_BUFFER_LEN];
        let der = key.to_pkcs1_der(&mut buffer).unwrap();
        assert_eq!(
            hex::encode(hash::Sha256::hash(der)),
            "45cd51509b4deac86be0cb60faa945339c4526cce2faa489212c6b9b853b121d"
        );
    }

    #[test]
    fn key_generation_smoke_test() {
        let mut sizes = vec![2048, 3072];

        if std::env::var_os("SLOW_TESTS").is_some() {
            sizes.extend_from_slice(&[4096, 6144, 8192]);
        }

        for size in sizes {
            println!("generating {size:?}...");
            let start = std::time::Instant::now();
            let key = SigningKey::generate(KeySize::try_from(size).unwrap()).unwrap();
            println!("generated (took {}ms)", start.elapsed().as_millis());
            check_all_algs(&mut [0u8; 1024], &key, &key.public_key());
        }
    }
}
