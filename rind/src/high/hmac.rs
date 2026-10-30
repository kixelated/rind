// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! HMAC (Hash Message Authentication Code).
//!
//! HMAC is standardized in [FIPS 198](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf).

use super::digest::{self, Digest, Id};
use super::hash::{Hash, HashContext, LegacySha1, Sha256, Sha384, Sha512};
use crate::Error;
use crate::low::{Zeroable, zeroise, zeroise_value};

/// An in-progress HMAC computation, using hash function `H`.
pub(crate) struct Hmac<H: Hash> {
    inner: H::Context,
    outer: H::Context,
}

// Not derived: that would also require `H: Clone`, which code generic over `H: Hash` cannot assume.
impl<H: Hash> Clone for Hmac<H> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            outer: self.outer.clone(),
        }
    }
}

impl<H: Hash> Hmac<H> {
    /// Create a new [`Hmac<H>`] using the given key material.
    pub(crate) fn new(key: impl AsRef<[u8]>) -> Self {
        let mut key_block = H::zeroed_block();

        let key = key.as_ref();
        // shorten long keys
        if key.len() > key_block.len() {
            let h_key = H::hash(key);
            key_block[..h_key.as_ref().len()].copy_from_slice(h_key.as_ref());
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        // compute inner
        for byte in key_block.iter_mut() {
            *byte ^= 0x36;
        }
        let mut inner = H::new();
        inner.update(&key_block);

        // and outer
        for byte in key_block.iter_mut() {
            *byte ^= 0x5c ^ 0x36;
        }
        let mut outer = H::new();
        outer.update(&key_block);

        zeroise(&mut key_block);
        Self { inner, outer }
    }

    /// Add data to be signed.
    pub(crate) fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.inner.update(bytes.as_ref());
    }

    /// Complete the HMAC signing operation, consuming it.
    ///
    /// The HMAC output (sometimes called a "signature", or "tag") is returned.
    pub(crate) fn finish(mut self) -> Digest {
        let mut inner_output = self.inner.finish();
        self.outer.update(inner_output.as_ref());
        zeroise(inner_output.as_mut());
        self.outer.finish()
    }
}

/// An HMAC algorithm, chosen by one of this module's constants.
#[derive(Clone, Copy, Debug)]
pub struct Algorithm(&'static digest::Algorithm);

impl Algorithm {
    /// The length of this algorithm's tag, in bytes.
    pub fn tag_len(&self) -> usize {
        self.0.output_len()
    }
}

/// HMAC-SHA1, for legacy protocols only.
///
/// HMAC does not rely on SHA-1's broken collision resistance, and STUN
/// (RFC 8489) and SRTP (RFC 3711) still require it.
pub static HMAC_SHA1_FOR_LEGACY_USE_ONLY: Algorithm = Algorithm(&digest::SHA1_FOR_LEGACY_USE_ONLY);

/// HMAC-SHA256.
pub static HMAC_SHA256: Algorithm = Algorithm(&digest::SHA256);

/// HMAC-SHA384.
pub static HMAC_SHA384: Algorithm = Algorithm(&digest::SHA384);

/// HMAC-SHA512.
pub static HMAC_SHA512: Algorithm = Algorithm(&digest::SHA512);

/// An HMAC key, keyed once and reused for every message; wiped on drop.
#[derive(Clone)]
pub struct Key(pub(super) Keyed);

impl Key {
    /// Keys `algorithm` with `key_value`, which may be any length.
    pub fn new(algorithm: Algorithm, key_value: &[u8]) -> Self {
        Self(match algorithm.0.id {
            Id::Sha1 => Keyed::Sha1(Hmac::new(key_value)),
            Id::Sha256 => Keyed::Sha256(Hmac::new(key_value)),
            Id::Sha384 => Keyed::Sha384(Hmac::new(key_value)),
            Id::Sha512 => Keyed::Sha512(Hmac::new(key_value)),
        })
    }

    /// The algorithm this key was made for.
    pub fn algorithm(&self) -> Algorithm {
        match self.0 {
            Keyed::Sha1(_) => HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Keyed::Sha256(_) => HMAC_SHA256,
            Keyed::Sha384(_) => HMAC_SHA384,
            Keyed::Sha512(_) => HMAC_SHA512,
        }
    }
}

/// An in-progress tag computation, for a message given in pieces.
///
/// A clone forks the computation, so messages sharing a prefix process it once.
#[derive(Clone)]
pub struct Context(Keyed);

impl Context {
    /// Starts a tag computation under `key`.
    pub fn with_key(key: &Key) -> Self {
        Self(key.0.clone())
    }

    /// Adds `data` to the message.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Returns the tag of the message.
    pub fn sign(self) -> Tag {
        Tag(self.0.sign(&[]))
    }
}

/// Returns the tag of `data` under `key`.
pub fn sign(key: &Key, data: &[u8]) -> Tag {
    Tag(key.0.sign(data))
}

/// Checks in constant time that `tag` is the whole tag of `data` under `key`.
///
/// Fails with [`Error::BadSignature`] otherwise, including for a truncated tag.
pub fn verify(key: &Key, data: &[u8], tag: &[u8]) -> Result<(), Error> {
    match key.0.sign(data).ct_equal(tag) {
        true => Ok(()),
        false => Err(Error::BadSignature),
    }
}

/// An HMAC tag.
#[derive(Clone, Debug)]
pub struct Tag(Digest);

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

// All-zero is the `Sha1` variant with all-zero hash contexts, which
// `Zeroable` allows: every field is a plain integer or byte array.
#[derive(Clone)]
#[repr(u8)]
pub(super) enum Keyed {
    Sha1(Hmac<LegacySha1>),
    Sha256(Hmac<Sha256>),
    Sha384(Hmac<Sha384>),
    Sha512(Hmac<Sha512>),
}

impl Keyed {
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha1(hmac) => hmac.update(data),
            Self::Sha256(hmac) => hmac.update(data),
            Self::Sha384(hmac) => hmac.update(data),
            Self::Sha512(hmac) => hmac.update(data),
        }
    }

    // Finishes a copy: `Drop` forbids moving the hash contexts out of `self`.
    fn sign(&self, data: &[u8]) -> Digest {
        fn sign<H: Hash>(hmac: &Hmac<H>, data: &[u8]) -> Digest {
            let mut hmac = hmac.clone();
            hmac.update(data);
            hmac.finish()
        }

        match self {
            Self::Sha1(hmac) => sign(hmac, data),
            Self::Sha256(hmac) => sign(hmac, data),
            Self::Sha384(hmac) => sign(hmac, data),
            Self::Sha512(hmac) => sign(hmac, data),
        }
    }
}

impl Drop for Keyed {
    fn drop(&mut self) {
        // Wipes the discriminant and the space a smaller variant leaves unused,
        // not only the variant's own hash contexts.
        zeroise_value(self);
    }
}

impl Zeroable for Keyed {}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::test::*;

    #[test]
    fn smoke() {
        let key = Key::new(HMAC_SHA256, b"hello");
        assert_eq!(sign(&key, b"world").as_ref(),
                   b"\xf1\xac\x97\x02\xeb\x5f\xaf\x23\xca\x29\x1a\x4d\xc4\x6d\xed\xde\xee\x2a\x78\xcc\xda\xf0\xa4\x12\xbe\xd7\x71\x4c\xff\xfb\x1c\xc4");

        let key = Key::new(HMAC_SHA384, b"hello");
        assert_eq!(sign(&key, b"world").as_ref(),
                   b"\x80\xd0\x36\xd9\x97\x4e\x6f\x71\xce\xab\xe4\x93\xee\x89\x7d\x00\x23\x5e\xdc\xc4\xc7\x2e\x04\x6d\xdf\xc8\xbf\x68\xe8\x6a\x47\x7d\x63\xb9\xf7\xd2\x6a\xd5\xb9\x90\xaa\xe6\xac\x17\xdb\x57\xdd\xcf");

        let key = Key::new(HMAC_SHA512, b"hello");
        assert_eq!(sign(&key, b"world").as_ref(),
                   b"\x66\x68\xed\x2f\x7d\x01\x6c\x5f\x12\xd7\x80\x8f\xc4\xf2\xd1\xdc\x48\x51\x62\x2d\x7f\x15\x61\x6d\xe9\x47\xa8\x23\xb3\xee\x67\xd7\x61\xb9\x53\xf0\x95\x60\xda\x30\x1f\x83\x29\x02\x02\r\xd1\xc6\x4f\x49\x6d\xf3\x7e\xb7\xac\x4f\xd2\xfe\xee\xb6\x7d\x77\xba\x9b");
    }

    #[test]
    fn verify_whole_tags_only() {
        for algorithm in ALGORITHMS {
            let key = Key::new(algorithm, b"key");
            let tag = sign(&key, b"message");
            assert_eq!(tag.as_ref().len(), algorithm.tag_len());
            assert_eq!(verify(&key, b"message", tag.as_ref()), Ok(()));

            let short = &tag.as_ref()[..algorithm.tag_len() - 1];
            assert_eq!(verify(&key, b"message", short), Err(Error::BadSignature));
            assert_eq!(verify(&key, b"message", &[]), Err(Error::BadSignature));
            let mut long = tag.as_ref().to_vec();
            long.push(0);
            assert_eq!(verify(&key, b"message", &long), Err(Error::BadSignature));
        }
    }

    #[test]
    fn secret_key_and_message() {
        // Under `admin/ctgrind`, nothing may branch on or index by the key or
        // message. Keys longer than a block are hashed first.
        for algorithm in ALGORITHMS {
            for key_len in [16, 200] {
                let key = vec![0x5a; key_len];
                let message = [0xa5; 300];
                let wanted = sign(&Key::new(algorithm, &key), &message);

                crate::low::ct::secret_slice(&key);
                crate::low::ct::secret_slice(&message);
                let key = Key::new(algorithm, &key);
                let mut ctx = Context::with_key(&key);
                ctx.update(&message[..100]);
                ctx.update(&message[100..]);
                assert_eq!(
                    crate::low::ct::into_public(ctx.sign()).as_ref(),
                    wanted.as_ref()
                );
                assert_eq!(verify(&key, &message, wanted.as_ref()), Ok(()));
            }
        }
    }

    #[test]
    fn cavp() {
        #[derive(Debug, Default)]
        struct Cavp {
            algorithm: Option<Algorithm>,
            key: Vec<u8>,
            message: Vec<u8>,
        }

        impl CavpSink for Cavp {
            fn on_meta(&mut self, meta: &str) {
                self.algorithm = match meta {
                    "L=20" => Some(HMAC_SHA1_FOR_LEGACY_USE_ONLY),
                    // SHA-224, which rind does not offer.
                    "L=28" => None,
                    "L=32" => Some(HMAC_SHA256),
                    "L=48" => Some(HMAC_SHA384),
                    "L=64" => Some(HMAC_SHA512),
                    _ => panic!("unhandled {meta:?}"),
                };
            }

            fn on_value(&mut self, name: &str, value: Value<'_>) {
                match name {
                    "Klen" | "Tlen" => {}
                    "Count" => println!("  test {}", value.int()),
                    "Key" => self.key = value.bytes(),
                    "Msg" => self.message = value.bytes(),
                    "Mac" => {
                        let Some(algorithm) = self.algorithm else {
                            return;
                        };
                        let tag = sign(&Key::new(algorithm, &self.key), &self.message);
                        // Most vectors truncate the tag.
                        let wanted = value.bytes();
                        assert_eq!(&tag.as_ref()[..wanted.len()], wanted);
                    }
                    _ => {
                        todo!("{self:?} value {name} = {value:?}");
                    }
                }
            }
        }

        process_cavp("../thirdparty/cavp/hmac/HMAC.rsp", &mut Cavp::default());
    }

    static ALGORITHMS: [Algorithm; 4] = [
        HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        HMAC_SHA256,
        HMAC_SHA384,
        HMAC_SHA512,
    ];
}
