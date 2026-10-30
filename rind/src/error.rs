// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

/// All errors that may happen in this crate.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    /// Some slice was the wrong length.
    WrongLength,

    /// An compressed elliptic curve point encoding was encountered.
    NotUncompressed,

    /// A public key was invalid.
    NotOnCurve,

    /// A value was too small or large.
    OutOfRange,

    /// A random number generator returned an error or fixed values.
    RngFailed,

    /// Presented signature is invalid.
    BadSignature,

    /// Presented AEAD tag/aad/ciphertext/nonce was wrong
    DecryptFailed,

    /// A key encoding was malformed or did not match the expected algorithm.
    KeyRejected(KeyRejected),
}

/// Why a key encoding was rejected, which its `Display` describes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KeyRejected(KeyFormatError);

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum KeyFormatError {
    Asn1(crate::high::asn1::Error),
    MismatchedAgreementAlgorithm,
    UnsupportedPkcs8Version,
    MismatchedPkcs8Algorithm,
    MismatchedPkcs8Parameters,
    MismatchedPkcs8PublicKey,
    MismatchedSec1Curve,
    MismatchedSec1PublicKey,
    MismatchedSpkiAlgorithm,
}

impl From<KeyFormatError> for Error {
    fn from(kfe: KeyFormatError) -> Self {
        Self::KeyRejected(KeyRejected(kfe))
    }
}

impl core::fmt::Display for KeyRejected {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            KeyFormatError::Asn1(e) => write!(f, "an ASN.1 decoding error: {e}"),
            KeyFormatError::MismatchedAgreementAlgorithm => {
                write!(f, "mismatched key agreement algorithm")
            }
            KeyFormatError::UnsupportedPkcs8Version => write!(f, "unsupported PKCS#8 version"),
            KeyFormatError::MismatchedPkcs8Algorithm => write!(f, "mismatched PKCS#8 algorithm"),
            KeyFormatError::MismatchedPkcs8Parameters => {
                write!(f, "mismatched PKCS#8 parameters")
            }
            KeyFormatError::MismatchedPkcs8PublicKey => write!(f, "mismatched PKCS#8 public key"),
            KeyFormatError::MismatchedSec1Curve => write!(f, "mismatched SEC1 curve"),
            KeyFormatError::MismatchedSec1PublicKey => write!(f, "mismatched SEC1 public key"),
            KeyFormatError::MismatchedSpkiAlgorithm => write!(f, "mismatched SPKI algorithm"),
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength => write!(f, "some slice was the wrong length"),
            Self::NotUncompressed => write!(
                f,
                "a compressed elliptic curve point encoding was encountered"
            ),
            Self::NotOnCurve => write!(f, "a public key was invalid"),
            Self::OutOfRange => write!(f, "a value was too small or large"),
            Self::RngFailed => write!(
                f,
                "a random number generator returned an error or fixed values"
            ),
            Self::BadSignature => write!(f, "presented signature is invalid"),
            Self::DecryptFailed => write!(f, "presented AEAD tag/aad/ciphertext/nonce was wrong"),
            Self::KeyRejected(e) => write!(f, "a key was rejected: {e}"),
        }
    }
}

impl core::error::Error for KeyRejected {}
impl core::error::Error for Error {}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", Error::WrongLength),
            "some slice was the wrong length"
        );
        assert_eq!(
            format!("{}", Error::NotUncompressed),
            "a compressed elliptic curve point encoding was encountered"
        );
        assert_eq!(format!("{}", Error::NotOnCurve), "a public key was invalid");
        assert_eq!(
            format!("{}", Error::OutOfRange),
            "a value was too small or large"
        );
        assert_eq!(
            format!("{}", Error::RngFailed),
            "a random number generator returned an error or fixed values"
        );
        assert_eq!(
            format!("{}", Error::BadSignature),
            "presented signature is invalid"
        );
        assert_eq!(
            format!("{}", Error::DecryptFailed),
            "presented AEAD tag/aad/ciphertext/nonce was wrong"
        );
        assert_eq!(
            format!(
                "{}",
                Error::from(KeyFormatError::Asn1(
                    crate::high::asn1::Error::UnexpectedTag
                ))
            ),
            "a key was rejected: an ASN.1 decoding error: unexpected tag"
        );
        assert_eq!(
            format!("{}", Error::from(KeyFormatError::UnsupportedPkcs8Version)),
            "a key was rejected: unsupported PKCS#8 version"
        );
    }

    #[test]
    fn test_keyrejected_display() {
        let display = |kfe| format!("{}", KeyRejected(kfe));
        assert_eq!(
            display(KeyFormatError::MismatchedAgreementAlgorithm),
            "mismatched key agreement algorithm"
        );
        assert_eq!(
            display(KeyFormatError::UnsupportedPkcs8Version),
            "unsupported PKCS#8 version"
        );
        assert_eq!(
            display(KeyFormatError::MismatchedPkcs8Algorithm),
            "mismatched PKCS#8 algorithm"
        );
        assert_eq!(
            display(KeyFormatError::MismatchedPkcs8Parameters),
            "mismatched PKCS#8 parameters"
        );
        assert_eq!(
            display(KeyFormatError::MismatchedPkcs8PublicKey),
            "mismatched PKCS#8 public key"
        );
        assert_eq!(
            display(KeyFormatError::MismatchedSec1Curve),
            "mismatched SEC1 curve"
        );
        assert_eq!(
            display(KeyFormatError::MismatchedSec1PublicKey),
            "mismatched SEC1 public key"
        );
        assert_eq!(
            display(KeyFormatError::MismatchedSpkiAlgorithm),
            "mismatched SPKI algorithm"
        );
    }
}
