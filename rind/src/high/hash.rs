// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::ops::{Deref, DerefMut};

use super::digest::{Algorithm, Digest, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512};
use crate::mid::{sha1, sha2};

/// One block of hash function input.
#[derive(Copy, Clone)]
pub struct HashBlock {
    buf: [u8; 128],
    len: usize,
}

impl HashBlock {
    /// Creates a new `HashBlock`, containing `len` zeroed bytes.
    fn new(len: usize) -> Self {
        Self {
            buf: [0u8; 128],
            len,
        }
    }
}

impl Deref for HashBlock {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.buf[..self.len]
    }
}

impl DerefMut for HashBlock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf[..self.len]
    }
}

/// A generic trait over supported hash functions.
///
/// This exists so (eg.) HMAC may be generic. It is not exported, so callers
/// hash through [`crate::digest`] and only name an implementor as a type
/// parameter.
pub trait Hash {
    /// The associated context type.
    type Context: HashContext;

    /// This hash function's [`crate::digest`] constant.
    const ALGORITHM: &'static Algorithm;

    /// Create a new hash context.
    fn new() -> Self::Context;

    /// Hash the given bytes (one-shot style) and return the output.
    fn hash(bytes: &[u8]) -> Digest {
        let mut ctx = Self::new();
        ctx.update(bytes);
        ctx.finish()
    }

    /// Return a zeroed `HashBlock` of the correct size.
    fn zeroed_block() -> HashBlock;

    /// Return a zeroed [`Digest`] of the correct size.
    fn zeroed_output() -> Digest {
        Digest::zeroed(Self::ALGORITHM)
    }
}

/// A [`Hash`] whose collision resistance holds, so signatures may use it.
///
/// This excludes [`LegacySha1`].
pub(crate) trait SignatureHash: Hash {}

/// A generic trait over supported hash function contexts.
///
/// These may be cloned: the semantics of that forks the
/// computation so two different messages with the same
/// prefix can be computed, without reprocessing the prefix.
/// This property is essential to efficiently compute HMAC
/// when used for PBKDF2.
pub trait HashContext: Clone {
    /// Hash the given `bytes`.
    fn update(&mut self, bytes: &[u8]);

    /// Complete the computation.
    fn finish(self) -> Digest;
}

/// SHA-1, for legacy protocols only.
///
/// SHA1 is standardized in [FIPS180](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
/// Its collision resistance is broken, so no signature accepts it.
/// HMAC-SHA1 does not rely on collision resistance, and remains
/// required by STUN (RFC 8489) and SRTP (RFC 3711).
#[derive(Clone)]
pub struct LegacySha1;

impl Hash for LegacySha1 {
    type Context = sha1::Sha1Context;
    const ALGORITHM: &'static Algorithm = &SHA1_FOR_LEGACY_USE_ONLY;

    fn new() -> Self::Context {
        sha1::Sha1Context::new()
    }

    fn zeroed_block() -> HashBlock {
        HashBlock::new(sha1::Sha1Context::BLOCK_SZ)
    }
}

impl HashContext for sha1::Sha1Context {
    fn update(&mut self, bytes: &[u8]) {
        Self::update(self, bytes)
    }

    fn finish(self) -> Digest {
        Digest::new(LegacySha1::ALGORITHM, &Self::finish(self))
    }
}

/// SHA-256.
///
/// SHA256 is standardized in [FIPS180](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
#[derive(Clone)]
pub struct Sha256;

impl Hash for Sha256 {
    type Context = sha2::Sha256Context;
    const ALGORITHM: &'static Algorithm = &SHA256;

    fn new() -> Self::Context {
        sha2::Sha256Context::new()
    }

    fn zeroed_block() -> HashBlock {
        HashBlock::new(sha2::Sha256Context::BLOCK_SZ)
    }
}

impl SignatureHash for Sha256 {}

impl HashContext for sha2::Sha256Context {
    fn update(&mut self, bytes: &[u8]) {
        Self::update(self, bytes)
    }

    fn finish(self) -> Digest {
        Digest::new(Sha256::ALGORITHM, &Self::finish(self))
    }
}

/// SHA-384.
///
/// SHA384 is standardized in [FIPS180](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
#[derive(Clone)]
pub struct Sha384;

impl Hash for Sha384 {
    type Context = sha2::Sha384Context;
    const ALGORITHM: &'static Algorithm = &SHA384;

    fn new() -> Self::Context {
        sha2::Sha384Context::new()
    }

    fn zeroed_block() -> HashBlock {
        HashBlock::new(sha2::Sha512Context::BLOCK_SZ)
    }
}

impl SignatureHash for Sha384 {}

impl HashContext for sha2::Sha384Context {
    fn update(&mut self, bytes: &[u8]) {
        Self::update(self, bytes)
    }

    fn finish(self) -> Digest {
        Digest::new(Sha384::ALGORITHM, &Self::finish(self))
    }
}

/// SHA-512.
///
/// SHA512 is standardized in [FIPS180](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
#[derive(Clone)]
pub struct Sha512;

impl Hash for Sha512 {
    type Context = sha2::Sha512Context;
    const ALGORITHM: &'static Algorithm = &SHA512;

    fn new() -> Self::Context {
        sha2::Sha512Context::new()
    }

    fn zeroed_block() -> HashBlock {
        HashBlock::new(sha2::Sha512Context::BLOCK_SZ)
    }
}

impl SignatureHash for Sha512 {}

impl HashContext for sha2::Sha512Context {
    fn update(&mut self, bytes: &[u8]) {
        Self::update(self, bytes)
    }

    fn finish(self) -> Digest {
        Digest::new(Sha512::ALGORITHM, &Self::finish(self))
    }
}
