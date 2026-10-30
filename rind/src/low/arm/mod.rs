// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! 32-bit ARM, backed by libcrux's portable Rust, and by aws-lc's assembly for
//! the ARMv8 crypto extension where the CPU has it.
//!
//! libcrux exposes only a few operations at this layer's granularity.  The
//! rest are swapped in `mid`, where libcrux's whole operations fit, except
//! P-384, whose arithmetic is fiat-crypto's in `generic::p384`.

/// The symbol for an aws-lc routine, qualified by rind's version so two
/// semver-incompatible copies of rind can link into one binary.
macro_rules! aws_lc_symbol {
    ($name:literal) => {
        concat!(
            "rind_",
            env!("CARGO_PKG_VERSION_MAJOR"),
            "_",
            env!("CARGO_PKG_VERSION_MINOR"),
            "_",
            env!("CARGO_PKG_VERSION_PATCH"),
            "_",
            $name
        )
    };
}

pub(crate) mod aes;
pub(crate) mod aes_ctr;
pub(crate) mod aesv8_armx;
pub(crate) mod bignum_eq;
pub(crate) mod chacha20;
pub(crate) mod cpu;
pub(crate) mod curve25519;
pub(crate) mod ghashv8_armx;
pub(crate) mod poly1305;
pub(crate) mod posint;
pub(crate) mod sha_armv4;
