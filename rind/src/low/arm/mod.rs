// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! 32-bit ARM, backed by libcrux's verified portable Rust.
//!
//! libcrux exposes only a few operations at this layer's granularity.  The
//! rest are swapped in `mid`, where libcrux's whole operations fit, except
//! P-384, whose arithmetic is fiat-crypto's in `generic::p384`.

pub(crate) mod aes;
pub(crate) mod aes_ctr;
pub(crate) mod bignum_eq;
pub(crate) mod chacha20;
pub(crate) mod cpu;
pub(crate) mod curve25519;
pub(crate) mod poly1305;
pub(crate) mod posint;
