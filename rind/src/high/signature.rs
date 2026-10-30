// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::fmt;

use super::curve::{Curve, MAX_SCALAR_LEN, MAX_UNCOMPRESSED_PUBLIC_KEY_LEN, P256, P384};
use super::ecdsa;
use super::ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};
use super::hash::{Sha256, Sha384, Sha512};
use super::rsa;
use crate::error::{Error, KeyFormatError};
use crate::low::{self, Zeroable};
pub use crate::mid::rsa_priv::KeySize;
use crate::mid::rsa_pub::MAX_PUBLIC_MODULUS_BYTES;

/// The hash a signature algorithm applies to the message.
///
/// No variant is SHA-1, so SHA-1 never reaches a signature.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
enum HashId {
    Sha256,
    Sha384,
    Sha512,
}

/// Runs `$body` with `$H` naming the hash type for `$hash`.
macro_rules! with_hash {
    ($hash:expr, |$H:ident| $body:expr) => {
        match $hash {
            HashId::Sha256 => {
                type $H = Sha256;
                $body
            }
            HashId::Sha384 => {
                type $H = Sha384;
                $body
            }
            HashId::Sha512 => {
                type $H = Sha512;
                $body
            }
        }
    };
}

mod sealed {
    use crate::Error;

    pub trait Sealed {
        fn parse(&self, public_key: &[u8]) -> Result<Key, Error>;
    }

    /// A parsed key, opaque so the sealed trait names no crate-private type.
    pub struct Key(pub(super) super::Parsed);
}

/// A signature verification algorithm, for [`UnparsedPublicKey`] and [`ParsedPublicKey`].
pub trait VerificationAlgorithm: fmt::Debug + Sync + sealed::Sealed {}

/// A peer's public key, parsed for `algorithm` only at verification.
#[derive(Clone, Copy, Debug)]
pub struct UnparsedPublicKey<B: AsRef<[u8]>> {
    algorithm: &'static dyn VerificationAlgorithm,
    bytes: B,
}

impl<B: AsRef<[u8]>> UnparsedPublicKey<B> {
    /// Wraps a peer's encoded public key for `algorithm`.
    ///
    /// ECDSA keys are X9.62 uncompressed points, RSA keys are PKCS#1
    /// `RSAPublicKey` DER, and Ed25519 keys are their 32 bytes. Unlike
    /// aws-lc-rs, a compressed ECDSA point is refused: no consumer sends one.
    pub fn new(algorithm: &'static dyn VerificationAlgorithm, bytes: B) -> Self {
        Self { algorithm, bytes }
    }

    /// Verifies `signature` over `message`, refusing a malformed key or signature.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        ParsedPublicKey::new(self.algorithm, self.bytes.as_ref())?.verify(message, signature)
    }
}

/// A peer's public key, parsed for `algorithm` once, so a malformed key is
/// refused before any signature arrives.
///
/// On 32-bit ARM, whose Ed25519 backend decodes a point only when verifying,
/// an Ed25519 key off the curve is refused by [`Self::verify`] instead.
pub struct ParsedPublicKey {
    algorithm: &'static dyn VerificationAlgorithm,
    key: Parsed,
}

#[allow(clippy::large_enum_variant)]
enum Parsed {
    EcdsaP256(ecdsa::VerifyingKey<P256>, Ecdsa),
    EcdsaP384(ecdsa::VerifyingKey<P384>, Ecdsa),
    Rsa(rsa::VerifyingKey, RsaScheme),
    Ed25519(Ed25519VerifyingKey),
}

impl ParsedPublicKey {
    /// Parses a peer's encoded public key, as [`UnparsedPublicKey::new`] takes it, for `algorithm`.
    pub fn new(
        algorithm: &'static dyn VerificationAlgorithm,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        Ok(Self {
            algorithm,
            key: algorithm.parse(bytes.as_ref())?.0,
        })
    }

    /// Verifies `signature` over `message`, refusing a malformed signature.
    ///
    /// aws-lc-rs names this `verify_sig`; it matches
    /// [`UnparsedPublicKey::verify`] here.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        match &self.key {
            Parsed::EcdsaP256(key, algorithm) => algorithm.verify(key, message, signature),
            Parsed::EcdsaP384(key, algorithm) => algorithm.verify(key, message, signature),
            Parsed::Rsa(key, scheme) => scheme.verify(key, message, signature),
            Parsed::Ed25519(key) => key.verify(signature, message),
        }
    }
}

impl fmt::Debug for ParsedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedPublicKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// A key pair, which reveals its public key.
pub trait KeyPair {
    /// The public key's encoding, as [`UnparsedPublicKey`] takes it.
    type PublicKey: AsRef<[u8]>;

    /// Returns the public key.
    fn public_key(&self) -> &Self::PublicKey;
}

/// A signature from an ECDSA or Ed25519 key pair.
#[derive(Clone, Copy)]
pub struct Signature {
    bytes: [u8; Self::MAX_LEN],
    len: usize,
}

impl Signature {
    // A DER `SEQUENCE` of two P-384 `INTEGER`s, each with a sign byte.
    const MAX_LEN: usize = 2 + 2 * (2 + MAX_SCALAR_LEN + 1);

    fn new() -> Self {
        Self {
            bytes: [0; Self::MAX_LEN],
            len: 0,
        }
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signature").field(&self.as_ref()).finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
enum CurveId {
    P256,
    P384,
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
enum EcdsaEncoding {
    /// A DER `Ecdsa-Sig-Value`, as X.509 and TLS use.
    Asn1,
    /// `r || s`, each the curve's scalar length, as JWS uses.
    Fixed,
}

/// A curve, a hash, and a signature encoding.
#[derive(Clone, Copy, Debug)]
struct Ecdsa {
    curve: CurveId,
    hash: HashId,
    encoding: EcdsaEncoding,
}

impl Ecdsa {
    fn verify<C: Curve>(
        self,
        key: &ecdsa::VerifyingKey<C>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        with_hash!(self.hash, |H| match self.encoding {
            EcdsaEncoding::Asn1 => key.verify_asn1::<H>(message, signature),
            EcdsaEncoding::Fixed => key.verify::<H>(message, signature),
        })
    }
}

/// An ECDSA verification algorithm: a curve, a hash, and a signature encoding.
#[derive(Debug)]
pub struct EcdsaVerificationAlgorithm(Ecdsa);

impl sealed::Sealed for EcdsaVerificationAlgorithm {
    fn parse(&self, public_key: &[u8]) -> Result<sealed::Key, Error> {
        Ok(sealed::Key(match self.0.curve {
            CurveId::P256 => Parsed::EcdsaP256(
                ecdsa::VerifyingKey::from_x962_uncompressed(public_key)?,
                self.0,
            ),
            CurveId::P384 => Parsed::EcdsaP384(
                ecdsa::VerifyingKey::from_x962_uncompressed(public_key)?,
                self.0,
            ),
        }))
    }
}

impl VerificationAlgorithm for EcdsaVerificationAlgorithm {}

/// ECDSA on P-256 with SHA-256, ASN.1 signatures.
pub static ECDSA_P256_SHA256_ASN1: EcdsaVerificationAlgorithm =
    ecdsa_algorithm(CurveId::P256, HashId::Sha256, EcdsaEncoding::Asn1);

/// ECDSA on P-256 with SHA-384, ASN.1 signatures.
pub static ECDSA_P256_SHA384_ASN1: EcdsaVerificationAlgorithm =
    ecdsa_algorithm(CurveId::P256, HashId::Sha384, EcdsaEncoding::Asn1);

/// ECDSA on P-256 with SHA-512, ASN.1 signatures.
pub static ECDSA_P256_SHA512_ASN1: EcdsaVerificationAlgorithm =
    ecdsa_algorithm(CurveId::P256, HashId::Sha512, EcdsaEncoding::Asn1);

/// ECDSA on P-384 with SHA-256, ASN.1 signatures.
pub static ECDSA_P384_SHA256_ASN1: EcdsaVerificationAlgorithm =
    ecdsa_algorithm(CurveId::P384, HashId::Sha256, EcdsaEncoding::Asn1);

/// ECDSA on P-384 with SHA-384, ASN.1 signatures.
pub static ECDSA_P384_SHA384_ASN1: EcdsaVerificationAlgorithm =
    ecdsa_algorithm(CurveId::P384, HashId::Sha384, EcdsaEncoding::Asn1);

/// ECDSA on P-384 with SHA-512, ASN.1 signatures.
pub static ECDSA_P384_SHA512_ASN1: EcdsaVerificationAlgorithm =
    ecdsa_algorithm(CurveId::P384, HashId::Sha512, EcdsaEncoding::Asn1);

/// ECDSA on P-256 with SHA-256, fixed-length `r || s` signatures (JWS's ES256).
pub static ECDSA_P256_SHA256_FIXED: EcdsaVerificationAlgorithm =
    ecdsa_algorithm(CurveId::P256, HashId::Sha256, EcdsaEncoding::Fixed);

/// ECDSA on P-384 with SHA-384, fixed-length `r || s` signatures (JWS's ES384).
pub static ECDSA_P384_SHA384_FIXED: EcdsaVerificationAlgorithm =
    ecdsa_algorithm(CurveId::P384, HashId::Sha384, EcdsaEncoding::Fixed);

const fn ecdsa_algorithm(
    curve: CurveId,
    hash: HashId,
    encoding: EcdsaEncoding,
) -> EcdsaVerificationAlgorithm {
    EcdsaVerificationAlgorithm(Ecdsa {
        curve,
        hash,
        encoding,
    })
}

/// An ECDSA signing algorithm, which an [`EcdsaKeyPair`] is bound to.
#[derive(Debug)]
pub struct EcdsaSigningAlgorithm(Ecdsa);

/// Signs as [`ECDSA_P256_SHA256_ASN1`] verifies.
pub static ECDSA_P256_SHA256_ASN1_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(ECDSA_P256_SHA256_ASN1.0);

/// Signs as [`ECDSA_P384_SHA384_ASN1`] verifies.
pub static ECDSA_P384_SHA384_ASN1_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(ECDSA_P384_SHA384_ASN1.0);

/// Signs as [`ECDSA_P256_SHA256_FIXED`] verifies.
pub static ECDSA_P256_SHA256_FIXED_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(ECDSA_P256_SHA256_FIXED.0);

/// Signs as [`ECDSA_P384_SHA384_FIXED`] verifies.
pub static ECDSA_P384_SHA384_FIXED_SIGNING: EcdsaSigningAlgorithm =
    EcdsaSigningAlgorithm(ECDSA_P384_SHA384_FIXED.0);

/// An ECDSA private key and its public key, bound to one signing algorithm.
pub struct EcdsaKeyPair {
    key: EcdsaKey,
    algorithm: Ecdsa,
    public_key: EcdsaPublicKey,
}

// `repr(u8)` puts `P256` at tag zero, so all-bits-zero is a valid value.
#[repr(u8)]
enum EcdsaKey {
    P256(ecdsa::SigningKey<P256>),
    P384(ecdsa::SigningKey<P384>),
}

/// Loads a key on `$curve` with `SigningKey::$load`.
macro_rules! load_ecdsa {
    ($curve:expr, $load:ident($($arg:expr),*)) => {
        match $curve {
            CurveId::P256 => EcdsaKey::P256(ecdsa::SigningKey::$load($($arg),*)?),
            CurveId::P384 => EcdsaKey::P384(ecdsa::SigningKey::$load($($arg),*)?),
        }
    };
}

/// Runs `$body` with `$key` bound to whichever curve's key `$pair` holds.
macro_rules! on_ecdsa {
    ($pair:expr, |$key:ident| $body:expr) => {
        match &$pair.key {
            EcdsaKey::P256($key) => $body,
            EcdsaKey::P384($key) => $body,
        }
    };
}

impl EcdsaKeyPair {
    /// Generates a key pair for `algorithm` from the system random source.
    pub fn generate(algorithm: &'static EcdsaSigningAlgorithm) -> Result<Self, Error> {
        Self::new(algorithm, load_ecdsa!(algorithm.0.curve, generate()))
    }

    /// Loads a PKCS#8 `ECPrivateKey` on `algorithm`'s curve.
    pub fn from_pkcs8(
        algorithm: &'static EcdsaSigningAlgorithm,
        pkcs8: &[u8],
    ) -> Result<Self, Error> {
        Self::new(
            algorithm,
            load_ecdsa!(algorithm.0.curve, from_pkcs8_der(pkcs8)),
        )
    }

    /// Loads a SEC1 (RFC 5915) `ECPrivateKey` on `algorithm`'s curve.
    ///
    /// Unlike aws-lc-rs, this refuses PKCS#8, which [`Self::from_pkcs8`] takes:
    /// a caller always knows which of the two it holds.
    pub fn from_private_key_der(
        algorithm: &'static EcdsaSigningAlgorithm,
        private_key: &[u8],
    ) -> Result<Self, Error> {
        Self::new(
            algorithm,
            load_ecdsa!(algorithm.0.curve, from_sec1_der(private_key)),
        )
    }

    /// Loads a fixed-length big-endian private scalar, refused unless
    /// `public_key`, an X9.62 uncompressed point, is its public key.
    ///
    /// This suits a JWK's `d` and `x`/`y`; prefer [`Self::from_pkcs8`] for
    /// stored keys.
    pub fn from_private_key_and_public_key(
        algorithm: &'static EcdsaSigningAlgorithm,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, Error> {
        Self::new(
            algorithm,
            load_ecdsa!(
                algorithm.0.curve,
                from_private_key_and_public_key(private_key, public_key)
            ),
        )
    }

    fn new(algorithm: &'static EcdsaSigningAlgorithm, key: EcdsaKey) -> Result<Self, Error> {
        let mut pair = Self {
            key,
            algorithm: algorithm.0,
            public_key: EcdsaPublicKey {
                bytes: [0; MAX_UNCOMPRESSED_PUBLIC_KEY_LEN],
                len: 0,
            },
        };
        pair.public_key.len = on_ecdsa!(pair, |key| key
            .public_key_uncompressed(&mut pair.public_key.bytes))?
        .len();
        Ok(pair)
    }

    /// Signs `message` with a fresh nonce.
    ///
    /// Unlike aws-lc-rs, this takes no random source: aws-lc-rs ignores its
    /// own, a leftover of ring's API.
    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        let mut signature = Signature::new();
        let output = &mut signature.bytes;
        signature.len = on_ecdsa!(self, |key| with_hash!(self.algorithm.hash, |H| {
            match self.algorithm.encoding {
                EcdsaEncoding::Asn1 => key.sign_asn1::<H>(message, output),
                EcdsaEncoding::Fixed => key.sign::<H>(message, output),
            }
        }))?
        .len();
        Ok(signature)
    }

    /// Writes the private key as PKCS#8 to the start of `output`, returning
    /// the written span.
    ///
    /// Unlike aws-lc-rs, this and the other encodings write into the
    /// caller's buffer rather than an allocated `Document`, since rind does
    /// not allocate.
    pub fn to_pkcs8_der<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        on_ecdsa!(self, |key| key.to_pkcs8_der(output))
    }

    /// Writes the public key as a `SubjectPublicKeyInfo` to the start of
    /// `output`, returning the written span.
    pub fn to_spki_der<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        on_ecdsa!(self, |key| key.to_spki_der(output))
    }

    /// Writes the private scalar, big-endian and fixed-length, to the start
    /// of `output`, returning the written span.
    ///
    /// This is what [`Self::from_private_key_and_public_key`] loads, and a
    /// JWK's `d`. aws-lc-rs spells it `private_key().as_be_bytes()`.
    pub fn to_private_key_be<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        on_ecdsa!(self, |key| key.to_private_key_be(output))
    }
}

impl KeyPair for EcdsaKeyPair {
    type PublicKey = EcdsaPublicKey;

    fn public_key(&self) -> &EcdsaPublicKey {
        &self.public_key
    }
}

impl fmt::Debug for EcdsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaKeyPair")
            .field("algorithm", &self.algorithm)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

// Every field is plain words or a `repr(u8)` enum with a variant at zero.
impl Zeroable for EcdsaKeyPair {}

impl Drop for EcdsaKeyPair {
    fn drop(&mut self) {
        // The key wipes its own scalar. Wiping the rest, which is not secret,
        // lets `tests/zeroing.rs` check every byte.
        low::zeroise_value(self);
    }
}

/// An ECDSA public key, as an X9.62 uncompressed point.
#[derive(Clone)]
pub struct EcdsaPublicKey {
    bytes: [u8; MAX_UNCOMPRESSED_PUBLIC_KEY_LEN],
    len: usize,
}

impl AsRef<[u8]> for EcdsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl fmt::Debug for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EcdsaPublicKey")
            .field(&self.as_ref())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum RsaPadding {
    /// RSASSA-PKCS1-v1_5.
    Pkcs1,
    /// RSASSA-PSS, with MGF1 on the same hash and a salt of the hash's length.
    Pss,
}

#[derive(Clone, Copy, Debug)]
struct RsaScheme {
    padding: RsaPadding,
    hash: HashId,
}

impl RsaScheme {
    fn sign(self, key: &rsa::SigningKey, message: &[u8], out: &mut [u8]) -> Result<(), Error> {
        match (self.padding, self.hash) {
            (RsaPadding::Pkcs1, HashId::Sha256) => key.sign_pkcs1_sha256(out, message),
            (RsaPadding::Pkcs1, HashId::Sha384) => key.sign_pkcs1_sha384(out, message),
            (RsaPadding::Pkcs1, HashId::Sha512) => key.sign_pkcs1_sha512(out, message),
            (RsaPadding::Pss, HashId::Sha256) => key.sign_pss_sha256(out, message),
            (RsaPadding::Pss, HashId::Sha384) => key.sign_pss_sha384(out, message),
            (RsaPadding::Pss, HashId::Sha512) => key.sign_pss_sha512(out, message),
        }
        .map(|_| ())
    }

    fn verify(
        self,
        key: &rsa::VerifyingKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        match (self.padding, self.hash) {
            (RsaPadding::Pkcs1, HashId::Sha256) => key.verify_pkcs1_sha256(signature, message),
            (RsaPadding::Pkcs1, HashId::Sha384) => key.verify_pkcs1_sha384(signature, message),
            (RsaPadding::Pkcs1, HashId::Sha512) => key.verify_pkcs1_sha512(signature, message),
            (RsaPadding::Pss, HashId::Sha256) => key.verify_pss_sha256(signature, message),
            (RsaPadding::Pss, HashId::Sha384) => key.verify_pss_sha384(signature, message),
            (RsaPadding::Pss, HashId::Sha512) => key.verify_pss_sha512(signature, message),
        }
    }
}

/// An RSA verification algorithm, for moduli of 2048 to 8192 bits.
#[derive(Debug)]
pub struct RsaParameters(RsaScheme);

impl sealed::Sealed for RsaParameters {
    fn parse(&self, public_key: &[u8]) -> Result<sealed::Key, Error> {
        let key = rsa::VerifyingKey::from_pkcs1_der(public_key)?;
        Ok(sealed::Key(Parsed::Rsa(key, self.0)))
    }
}

impl VerificationAlgorithm for RsaParameters {}

/// RSASSA-PKCS1-v1_5 with SHA-256.
pub static RSA_PKCS1_2048_8192_SHA256: RsaParameters = RsaParameters(PKCS1_SHA256);

/// RSASSA-PKCS1-v1_5 with SHA-384.
pub static RSA_PKCS1_2048_8192_SHA384: RsaParameters = RsaParameters(PKCS1_SHA384);

/// RSASSA-PKCS1-v1_5 with SHA-512.
pub static RSA_PKCS1_2048_8192_SHA512: RsaParameters = RsaParameters(PKCS1_SHA512);

/// RSASSA-PSS with SHA-256, MGF1-SHA-256, and a 32-byte salt.
pub static RSA_PSS_2048_8192_SHA256: RsaParameters = RsaParameters(PSS_SHA256);

/// RSASSA-PSS with SHA-384, MGF1-SHA-384, and a 48-byte salt.
pub static RSA_PSS_2048_8192_SHA384: RsaParameters = RsaParameters(PSS_SHA384);

/// RSASSA-PSS with SHA-512, MGF1-SHA-512, and a 64-byte salt.
pub static RSA_PSS_2048_8192_SHA512: RsaParameters = RsaParameters(PSS_SHA512);

/// An RSA signature padding and hash, for [`RsaKeyPair::sign`].
#[derive(Debug)]
pub struct RsaSignatureEncoding(RsaScheme);

/// Signs as [`RSA_PKCS1_2048_8192_SHA256`] verifies.
pub static RSA_PKCS1_SHA256: RsaSignatureEncoding = RsaSignatureEncoding(PKCS1_SHA256);

/// Signs as [`RSA_PKCS1_2048_8192_SHA384`] verifies.
pub static RSA_PKCS1_SHA384: RsaSignatureEncoding = RsaSignatureEncoding(PKCS1_SHA384);

/// Signs as [`RSA_PKCS1_2048_8192_SHA512`] verifies.
pub static RSA_PKCS1_SHA512: RsaSignatureEncoding = RsaSignatureEncoding(PKCS1_SHA512);

/// Signs as [`RSA_PSS_2048_8192_SHA256`] verifies.
pub static RSA_PSS_SHA256: RsaSignatureEncoding = RsaSignatureEncoding(PSS_SHA256);

/// Signs as [`RSA_PSS_2048_8192_SHA384`] verifies.
pub static RSA_PSS_SHA384: RsaSignatureEncoding = RsaSignatureEncoding(PSS_SHA384);

/// Signs as [`RSA_PSS_2048_8192_SHA512`] verifies.
pub static RSA_PSS_SHA512: RsaSignatureEncoding = RsaSignatureEncoding(PSS_SHA512);

const PKCS1_SHA256: RsaScheme = RsaScheme {
    padding: RsaPadding::Pkcs1,
    hash: HashId::Sha256,
};
const PKCS1_SHA384: RsaScheme = RsaScheme {
    padding: RsaPadding::Pkcs1,
    hash: HashId::Sha384,
};
const PKCS1_SHA512: RsaScheme = RsaScheme {
    padding: RsaPadding::Pkcs1,
    hash: HashId::Sha512,
};
const PSS_SHA256: RsaScheme = RsaScheme {
    padding: RsaPadding::Pss,
    hash: HashId::Sha256,
};
const PSS_SHA384: RsaScheme = RsaScheme {
    padding: RsaPadding::Pss,
    hash: HashId::Sha384,
};
const PSS_SHA512: RsaScheme = RsaScheme {
    padding: RsaPadding::Pss,
    hash: HashId::Sha512,
};

/// A two-prime RSA private key, with a modulus of 2048 to 8192 bits, and its public key.
pub struct RsaKeyPair {
    key: rsa::SigningKey,
    public_key: RsaSubjectPublicKey,
}

impl RsaKeyPair {
    /// Generates a key pair of `size` from the system random source.
    ///
    /// This is slow: about 30 milliseconds for 2048 bits, and 15 seconds or
    /// more for 8192 bits, with no upper bound. It is also not side-channel
    /// safe, so avoid it in untrusted multi-tenant or physical environments.
    pub fn generate(size: KeySize) -> Result<Self, Error> {
        Self::new(rsa::SigningKey::generate(size)?)
    }

    /// Loads a PKCS#8 `rsaEncryption` private key.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, Error> {
        Self::new(rsa::SigningKey::from_pkcs8_der(pkcs8)?)
    }

    /// Loads a PKCS#1 `RSAPrivateKey`.
    pub fn from_der(pkcs1: &[u8]) -> Result<Self, Error> {
        Self::new(rsa::SigningKey::from_pkcs1_der(pkcs1)?)
    }

    fn new(key: rsa::SigningKey) -> Result<Self, Error> {
        let mut public_key = RsaSubjectPublicKey {
            bytes: [0; RsaSubjectPublicKey::MAX_LEN],
            len: 0,
        };
        public_key.len = key.public_key().to_pkcs1_der(&mut public_key.bytes)?.len();
        Ok(Self { key, public_key })
    }

    /// Returns the modulus length in bytes, which every signature has.
    pub fn public_modulus_len(&self) -> usize {
        self.key.modulus_len_bytes()
    }

    /// Signs `message` with `padding` into `signature`, which must be
    /// [`Self::public_modulus_len`] bytes.
    ///
    /// Unlike aws-lc-rs, this takes no random source, which aws-lc-rs
    /// ignores, and refuses a `signature` of the wrong length rather than
    /// panicking.
    pub fn sign(
        &self,
        padding: &'static RsaSignatureEncoding,
        message: &[u8],
        signature: &mut [u8],
    ) -> Result<(), Error> {
        if signature.len() != self.public_modulus_len() {
            return Err(Error::WrongLength);
        }
        padding.0.sign(&self.key, message, signature)
    }

    /// Writes the private key as PKCS#8 to the start of `output`, returning
    /// the written span.
    ///
    /// Unlike aws-lc-rs, this and the other encodings write into the
    /// caller's buffer rather than an allocated `Document`, since rind does
    /// not allocate.
    pub fn to_pkcs8_der<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        self.key.to_pkcs8_der(output)
    }

    /// Writes the public key as a `SubjectPublicKeyInfo` to the start of
    /// `output`, returning the written span.
    pub fn to_spki_der<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        self.key.public_key().to_spki_der(output)
    }
}

impl KeyPair for RsaKeyPair {
    type PublicKey = RsaSubjectPublicKey;

    fn public_key(&self) -> &RsaSubjectPublicKey {
        &self.public_key
    }
}

impl fmt::Debug for RsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaKeyPair")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl Drop for RsaKeyPair {
    fn drop(&mut self) {
        // Not secret, but wiping it lets `tests/zeroing.rs` check every byte.
        low::zeroise_value(&mut self.public_key);
    }
}

/// An RSA public key, as a PKCS#1 `RSAPublicKey`.
// Aligned like the private key's words, so on 32-bit targets the key pair's
// padding falls inside this value, which `RsaKeyPair`'s drop wipes whole,
// rather than after it, where `tests/zeroing.rs` finds stale bytes.
#[derive(Clone)]
#[repr(align(8))]
pub struct RsaSubjectPublicKey {
    bytes: [u8; Self::MAX_LEN],
    len: usize,
}

impl RsaSubjectPublicKey {
    // The modulus and its DER framing, with room for the exponent.
    const MAX_LEN: usize = MAX_PUBLIC_MODULUS_BYTES + 64;
}

impl Zeroable for RsaSubjectPublicKey {}

impl AsRef<[u8]> for RsaSubjectPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl fmt::Debug for RsaSubjectPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RsaSubjectPublicKey")
            .field(&self.as_ref())
            .finish()
    }
}

/// Ed25519 verification, the only EdDSA variant rind supports.
#[derive(Debug)]
pub struct EdDSAParameters;

impl sealed::Sealed for EdDSAParameters {
    fn parse(&self, public_key: &[u8]) -> Result<sealed::Key, Error> {
        let key = Ed25519VerifyingKey::from_bytes(public_key)?;
        Ok(sealed::Key(Parsed::Ed25519(key)))
    }
}

impl VerificationAlgorithm for EdDSAParameters {}

/// Ed25519, with 32-byte public keys and 64-byte signatures.
///
/// See [RFC8032](https://datatracker.ietf.org/doc/html/rfc8032).
pub static ED25519: EdDSAParameters = EdDSAParameters;

/// An Ed25519 private key and its public key.
pub struct Ed25519KeyPair {
    key: Ed25519SigningKey,
    public_key: Ed25519PublicKey,
}

impl Ed25519KeyPair {
    /// Generates a key pair from the system random source.
    pub fn generate() -> Result<Self, Error> {
        Ok(Self::new(Ed25519SigningKey::generate()?))
    }

    /// Loads a PKCS#8 Ed25519 key, refused if it carries a public key
    /// (v2, RFC 5958) that does not match.
    ///
    /// Unlike aws-lc-rs, this also takes PKCS#8 v1, which carries no public
    /// key, as aws-lc-rs's `from_pkcs8_maybe_unchecked` does: common tools
    /// write v1, and such a key is no less valid.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, Error> {
        Ok(Self::new(Ed25519SigningKey::from_pkcs8_der(pkcs8)?))
    }

    /// Loads a 32-byte seed, refused unless `public_key` is its public key.
    ///
    /// This suits a JWK's `d` and `x`.
    pub fn from_seed_and_public_key(seed: &[u8], public_key: &[u8]) -> Result<Self, Error> {
        let pair = Self::new(Ed25519SigningKey::from_bytes(seed)?);
        match pair.public_key.as_ref() == public_key {
            true => Ok(pair),
            false => Err(KeyFormatError::MismatchedPublicKey.into()),
        }
    }

    fn new(key: Ed25519SigningKey) -> Self {
        let public_key = Ed25519PublicKey(key.public_key().as_bytes());
        Self { key, public_key }
    }

    /// Returns the 32-byte seed this key pair was derived from.
    ///
    /// Unlike aws-lc-rs, this cannot fail, so returns the bytes rather than
    /// a `Result` of a wrapper.
    pub fn seed(&self) -> [u8; 32] {
        self.key.as_seed()
    }

    /// Signs `message`.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut signature = Signature::new();
        let bytes = self.key.sign(message);
        signature.bytes[..bytes.len()].copy_from_slice(&bytes);
        signature.len = bytes.len();
        signature
    }

    /// Writes the key pair as PKCS#8 v2 (RFC 5958) to the start of `output`,
    /// returning the written span.
    ///
    /// Unlike aws-lc-rs, this and [`Self::to_spki_der`] write into the
    /// caller's buffer rather than an allocated `Document`, since rind does
    /// not allocate.
    pub fn to_pkcs8_der<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        self.key.to_pkcs8_der(output)
    }

    /// Writes the public key as a `SubjectPublicKeyInfo` to the start of
    /// `output`, returning the written span.
    pub fn to_spki_der<'a>(&self, output: &'a mut [u8]) -> Result<&'a [u8], Error> {
        self.key.public_key().to_spki_der(output)
    }
}

impl KeyPair for Ed25519KeyPair {
    type PublicKey = Ed25519PublicKey;

    fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }
}

impl fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl Drop for Ed25519KeyPair {
    fn drop(&mut self) {
        // Not secret, but wiping it lets `tests/zeroing.rs` check every byte.
        low::zeroise(&mut self.public_key.0);
    }
}

/// An Ed25519 public key, as its 32 bytes.
#[derive(Clone)]
pub struct Ed25519PublicKey([u8; 32]);

impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ed25519PublicKey").field(&self.0).finish()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const ECDSA_SIGNING: [&EcdsaSigningAlgorithm; 4] = [
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &ECDSA_P384_SHA384_ASN1_SIGNING,
        &ECDSA_P384_SHA384_FIXED_SIGNING,
    ];

    fn rejected(result: Result<impl fmt::Debug, Error>) -> Error {
        result.expect_err("accepted")
    }

    #[test]
    fn ecdsa_verifies_only_under_its_algorithm() {
        let verification = [
            &ECDSA_P256_SHA256_ASN1,
            &ECDSA_P256_SHA256_FIXED,
            &ECDSA_P384_SHA384_ASN1,
            &ECDSA_P384_SHA384_FIXED,
        ];
        for (i, signing) in ECDSA_SIGNING.into_iter().enumerate() {
            let pair = EcdsaKeyPair::generate(signing).unwrap();
            let signature = pair.sign(b"message").unwrap();
            for (j, algorithm) in verification.into_iter().enumerate() {
                let result = UnparsedPublicKey::new(algorithm, pair.public_key())
                    .verify(b"message", signature.as_ref());
                assert_eq!(result.is_ok(), i == j, "{signing:?} {algorithm:?}");
            }
            assert_eq!(
                UnparsedPublicKey::new(verification[i], pair.public_key())
                    .verify(b"other", signature.as_ref()),
                Err(Error::BadSignature)
            );
        }
    }

    #[test]
    fn parsed_public_key_refuses_malformed_keys() {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
        let point = pair.public_key().as_ref();
        let signature = pair.sign(b"message").unwrap();
        let key = ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point).unwrap();
        key.verify(b"message", signature.as_ref()).unwrap();
        assert_eq!(
            key.verify(b"other", signature.as_ref()),
            Err(Error::BadSignature)
        );

        let malformed: [(&'static dyn VerificationAlgorithm, &[u8]); 4] = [
            (&ECDSA_P256_SHA256_ASN1, &point[1..]),
            (&ECDSA_P384_SHA384_ASN1, point),
            (&ED25519, &point[..31]),
            (&RSA_PKCS1_2048_8192_SHA256, point),
        ];
        for (algorithm, bytes) in malformed {
            assert!(
                ParsedPublicKey::new(algorithm, bytes).is_err(),
                "{algorithm:?}"
            );
        }

        // An Ed25519 encoding of the right length but off the curve.
        let off_curve = ParsedPublicKey::new(&ED25519, [0xff; 32]);
        #[cfg(not(target_arch = "arm"))]
        assert_eq!(off_curve.err(), Some(Error::NotOnCurve));
        #[cfg(target_arch = "arm")]
        assert_eq!(
            off_curve.unwrap().verify(b"", &[0; 64]),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn ecdsa_private_key_round_trips() {
        for signing in ECDSA_SIGNING {
            let pair = EcdsaKeyPair::generate(signing).unwrap();
            let len = match signing.0.curve {
                CurveId::P256 => 32,
                CurveId::P384 => 48,
            };
            let mut buffer = [0u8; MAX_SCALAR_LEN];
            assert_eq!(
                pair.to_private_key_be(&mut buffer[..len - 1]),
                Err(Error::WrongLength)
            );
            let scalar = pair.to_private_key_be(&mut buffer).unwrap();
            assert_eq!(scalar.len(), len);

            let public = pair.public_key().as_ref();
            let reloaded =
                EcdsaKeyPair::from_private_key_and_public_key(signing, scalar, public).unwrap();
            assert_eq!(reloaded.public_key().as_ref(), public);

            // The scalar must be exactly the curve's length, even with a zero
            // byte added or removed.
            let padded = [&[0][..], scalar].concat();
            assert_eq!(
                rejected(EcdsaKeyPair::from_private_key_and_public_key(
                    signing, &padded, public
                )),
                Error::WrongLength
            );
            assert_eq!(
                rejected(EcdsaKeyPair::from_private_key_and_public_key(
                    signing,
                    &scalar[1..],
                    public
                )),
                Error::WrongLength
            );

            // Zero and anything at or above the order are refused.
            let zero = [0u8; MAX_SCALAR_LEN];
            assert_eq!(
                rejected(EcdsaKeyPair::from_private_key_and_public_key(
                    signing,
                    &zero[..len],
                    public
                )),
                Error::OutOfRange
            );
            let ones = [0xffu8; MAX_SCALAR_LEN];
            assert_eq!(
                rejected(EcdsaKeyPair::from_private_key_and_public_key(
                    signing,
                    &ones[..len],
                    public
                )),
                Error::OutOfRange
            );

            // Another key's point, or the point truncated, is refused.
            let other = EcdsaKeyPair::generate(signing).unwrap();
            for public in [other.public_key().as_ref(), &public[..public.len() - 1]] {
                assert_eq!(
                    rejected(EcdsaKeyPair::from_private_key_and_public_key(
                        signing, scalar, public
                    )),
                    KeyFormatError::MismatchedPublicKey.into()
                );
            }
        }
    }

    #[test]
    fn ecdsa_key_is_bound_to_its_curve() {
        let p256 = include_bytes!("ecdsa/secp256r1.pkcs8.der");
        let p384 = include_bytes!("ecdsa/secp384r1.pkcs8.der");
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, p256).unwrap();
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, p384).unwrap();
        assert!(EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, p384).is_err());
        assert!(EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, p256).is_err());

        let p256 = include_bytes!("ecdsa/secp256r1.der");
        let p384 = include_bytes!("ecdsa/secp384r1.der");
        EcdsaKeyPair::from_private_key_der(&ECDSA_P256_SHA256_ASN1_SIGNING, p256).unwrap();
        assert!(EcdsaKeyPair::from_private_key_der(&ECDSA_P256_SHA256_ASN1_SIGNING, p384).is_err());

        // A P-384 point is the wrong length for a P-256 key.
        let pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P384_SHA384_ASN1_SIGNING,
            include_bytes!("ecdsa/secp384r1.pkcs8.der"),
        )
        .unwrap();
        let signature = pair.sign(b"message").unwrap();
        assert_eq!(
            UnparsedPublicKey::new(&ECDSA_P256_SHA384_ASN1, pair.public_key())
                .verify(b"message", signature.as_ref()),
            Err(Error::WrongLength)
        );
    }

    #[test]
    fn rsa_sign_needs_modulus_length() {
        let pair = RsaKeyPair::from_der(include_bytes!("rsa/rsa2048.der")).unwrap();
        let len = pair.public_modulus_len();
        assert_eq!(len, 256);
        for wrong in [len - 1, len + 1] {
            let mut signature = vec![0u8; wrong];
            assert_eq!(
                pair.sign(&RSA_PSS_SHA256, b"message", &mut signature),
                Err(Error::WrongLength)
            );
        }

        let mut signature = vec![0u8; len];
        pair.sign(&RSA_PSS_SHA256, b"message", &mut signature)
            .unwrap();
        let public_key = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, pair.public_key());
        public_key.verify(b"message", &signature).unwrap();
        assert_eq!(
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pair.public_key())
                .verify(b"message", &signature),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn ed25519_seed_and_public_key() {
        let pair = Ed25519KeyPair::generate().unwrap();
        let seed = pair.seed();
        let public = pair.public_key().as_ref();
        let reloaded = Ed25519KeyPair::from_seed_and_public_key(&seed, public).unwrap();
        assert_eq!(reloaded.public_key().as_ref(), public);
        assert_eq!(
            reloaded.sign(b"message").as_ref(),
            pair.sign(b"message").as_ref()
        );

        let other = Ed25519KeyPair::generate().unwrap();
        for public in [other.public_key().as_ref(), &public[..31]] {
            assert_eq!(
                rejected(Ed25519KeyPair::from_seed_and_public_key(&seed, public)),
                KeyFormatError::MismatchedPublicKey.into()
            );
        }
        for seed in [&seed[..31], &[seed.as_slice(), &[0]].concat()] {
            assert_eq!(
                rejected(Ed25519KeyPair::from_seed_and_public_key(seed, public)),
                Error::WrongLength
            );
        }
    }
}
