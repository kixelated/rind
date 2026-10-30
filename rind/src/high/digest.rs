// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! Hashing through an algorithm constant, following aws-lc-rs's `digest`.

use core::fmt;

use super::hash::{Hash, HashContext, LegacySha1, Sha256, Sha384, Sha512};
use crate::low::{ct, ct_equal};
use crate::mid::{sha1, sha2};

/// A hash function, chosen by one of this module's constants.
#[derive(Debug)]
pub struct Algorithm {
    pub(super) id: Id,
    output_len: usize,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Id {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Algorithm {
    /// The length of this algorithm's digest, in bytes.
    pub fn output_len(&self) -> usize {
        self.output_len
    }
}

/// SHA-1, for legacy protocols only: its collision resistance is broken.
///
/// HMAC-SHA1 does not rely on collision resistance, and remains required by
/// STUN (RFC 8489) and SRTP (RFC 3711). No signature algorithm accepts it.
pub static SHA1_FOR_LEGACY_USE_ONLY: Algorithm = Algorithm {
    id: Id::Sha1,
    output_len: sha1::Sha1Context::OUTPUT_SZ,
};

/// SHA-256, from [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
pub static SHA256: Algorithm = Algorithm {
    id: Id::Sha256,
    output_len: sha2::Sha256Context::OUTPUT_SZ,
};

/// SHA-384, from [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
pub static SHA384: Algorithm = Algorithm {
    id: Id::Sha384,
    output_len: sha2::Sha384Context::OUTPUT_SZ,
};

/// SHA-512, from [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
pub static SHA512: Algorithm = Algorithm {
    id: Id::Sha512,
    output_len: sha2::Sha512Context::OUTPUT_SZ,
};

/// Hashes `data` in one go.
pub fn digest(algorithm: &'static Algorithm, data: &[u8]) -> Digest {
    let mut ctx = Context::new(algorithm);
    ctx.update(data);
    ctx.finish()
}

/// An in-progress hash computation.
///
/// A clone forks the computation, so messages sharing a prefix hash it once.
#[derive(Clone)]
pub struct Context(State);

#[derive(Clone)]
enum State {
    Sha1(<LegacySha1 as Hash>::Context),
    Sha256(<Sha256 as Hash>::Context),
    Sha384(<Sha384 as Hash>::Context),
    Sha512(<Sha512 as Hash>::Context),
}

impl Context {
    /// Starts hashing with `algorithm`.
    pub fn new(algorithm: &'static Algorithm) -> Self {
        Self(match algorithm.id {
            Id::Sha1 => State::Sha1(LegacySha1::new()),
            Id::Sha256 => State::Sha256(Sha256::new()),
            Id::Sha384 => State::Sha384(Sha384::new()),
            Id::Sha512 => State::Sha512(Sha512::new()),
        })
    }

    /// Adds `data` to the message.
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.0 {
            State::Sha1(ctx) => ctx.update(data),
            State::Sha256(ctx) => ctx.update(data),
            State::Sha384(ctx) => ctx.update(data),
            State::Sha512(ctx) => ctx.update(data),
        }
    }

    /// Returns the digest of the message.
    pub fn finish(self) -> Digest {
        match self.0 {
            State::Sha1(ctx) => HashContext::finish(ctx),
            State::Sha256(ctx) => HashContext::finish(ctx),
            State::Sha384(ctx) => HashContext::finish(ctx),
            State::Sha512(ctx) => HashContext::finish(ctx),
        }
    }
}

/// The output of a hash function.
#[derive(Clone)]
pub struct Digest {
    algorithm: &'static Algorithm,
    value: [u8; MAX_OUTPUT_LEN],
}

pub(super) const MAX_OUTPUT_LEN: usize = sha2::Sha512Context::OUTPUT_SZ;

impl Digest {
    /// A digest of `algorithm` holding `value`, which must be its output length.
    pub(crate) fn new(algorithm: &'static Algorithm, value: &[u8]) -> Self {
        let mut digest = Self::zeroed(algorithm);
        digest.as_mut().copy_from_slice(value);
        digest
    }

    /// A zeroed digest of `algorithm`, for building one in place.
    pub(crate) fn zeroed(algorithm: &'static Algorithm) -> Self {
        Self {
            algorithm,
            value: [0; MAX_OUTPUT_LEN],
        }
    }

    pub(crate) fn as_mut(&mut self) -> &mut [u8] {
        &mut self.value[..self.algorithm.output_len]
    }

    /// Constant-time equality, `other` may not be truncated.
    pub(crate) fn ct_equal(&self, other: &[u8]) -> bool {
        ct::into_public(ct_equal(self.as_ref(), other))
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.value[..self.algorithm.output_len]
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Digest")
            .field("algorithm", &self.algorithm.id)
            .field("value", &self.as_ref())
            .finish()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::test::*;

    // CAVP's `[L = n]` header names the hash by its output length.
    fn algorithm(meta: &str) -> &'static Algorithm {
        match meta {
            "L = 20" => &SHA1_FOR_LEGACY_USE_ONLY,
            "L = 32" => &SHA256,
            "L = 48" => &SHA384,
            "L = 64" => &SHA512,
            _ => panic!("unhandled {meta:?}"),
        }
    }

    #[test]
    fn cavp() {
        #[derive(Debug, Default)]
        struct Cavp {
            algorithm: Option<&'static Algorithm>,
            message: Vec<u8>,
            message_bytes: usize,
        }

        impl CavpSink for Cavp {
            fn on_meta(&mut self, meta: &str) {
                self.algorithm = Some(algorithm(meta));
            }

            fn on_value(&mut self, name: &str, value: Value<'_>) {
                match name {
                    "Len" => self.message_bytes = (value.int() / 8) as usize,
                    "Msg" => {
                        self.message = value.bytes();
                        self.message.truncate(self.message_bytes);
                    }
                    "MD" => {
                        let digest = digest(self.algorithm.unwrap(), &self.message);
                        assert_eq!(digest.as_ref(), value.bytes());
                    }
                    _ => todo!("{self:?} value {name} = {value:?}"),
                }
            }
        }

        for file in [
            "../thirdparty/cavp-sha1/SHA1ShortMsg.rsp",
            "../thirdparty/cavp/sha2/SHA256ShortMsg.rsp",
            "../thirdparty/cavp/sha2/SHA256LongMsg.rsp",
            "../thirdparty/cavp/sha2/SHA384ShortMsg.rsp",
            "../thirdparty/cavp/sha2/SHA384LongMsg.rsp",
            "../thirdparty/cavp/sha2/SHA512ShortMsg.rsp",
            "../thirdparty/cavp/sha2/SHA512LongMsg.rsp",
        ] {
            process_cavp(file, &mut Cavp::default());
        }
    }

    #[test]
    fn cavp_monte_carlo() {
        #[derive(Debug, Default)]
        struct Cavp {
            algorithm: Option<&'static Algorithm>,
            seed: Vec<u8>,
        }

        impl CavpSink for Cavp {
            fn on_meta(&mut self, meta: &str) {
                self.algorithm = Some(algorithm(meta));
            }

            fn on_value(&mut self, name: &str, value: Value<'_>) {
                match name {
                    "Seed" => self.seed = value.bytes(),
                    "COUNT" => {}
                    "MD" => {
                        self.seed = monte_carlo_1000(self.algorithm.unwrap(), &self.seed);
                        assert_eq!(self.seed, value.bytes());
                    }
                    _ => todo!("{self:?} value {name} = {value:?}"),
                }
            }
        }

        fn monte_carlo_1000(algorithm: &'static Algorithm, seed: &[u8]) -> Vec<u8> {
            let mut window = [seed.to_vec(), seed.to_vec(), seed.to_vec()];
            for _ in 0..1000 {
                let mut ctx = Context::new(algorithm);
                ctx.update(&window[0]);
                ctx.update(&window[1]);
                ctx.update(&window[2]);
                let r = ctx.finish();
                window.rotate_left(1);
                window[2].copy_from_slice(r.as_ref());
            }
            window[2].clone()
        }

        if std::env::var_os("SLOW_TESTS").is_some() {
            for file in [
                "../thirdparty/cavp-sha1/SHA1Monte.rsp",
                "../thirdparty/cavp/sha2/SHA256Monte.rsp",
                "../thirdparty/cavp/sha2/SHA384Monte.rsp",
                "../thirdparty/cavp/sha2/SHA512Monte.rsp",
            ] {
                process_cavp(file, &mut Cavp::default());
            }
        }
    }
}
