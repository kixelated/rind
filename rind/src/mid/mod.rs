// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

#![deny(unsafe_code)]

cfg_if::cfg_if! {
    if #[cfg(target_arch = "arm")] {
        // libcrux exposes whole operations rather than the field and bignum
        // arithmetic these build on, so 32-bit ARM swaps them at this layer.
        #[path = "arm/aes_gcm.rs"]
        pub(super) mod aes_gcm;
        #[path = "arm/chacha20poly1305.rs"]
        pub(super) mod chacha20poly1305;
        #[path = "arm/ed25519.rs"]
        pub(super) mod ed25519;
        #[path = "arm/mlkem768.rs"]
        pub(super) mod mlkem768;
        #[path = "arm/p256.rs"]
        pub(super) mod p256;
        #[path = "arm/rsa_priv.rs"]
        pub(super) mod rsa_priv;
        #[path = "arm/rsa_pub.rs"]
        pub(super) mod rsa_pub;
        #[path = "arm/xchacha20poly1305.rs"]
        pub(super) mod xchacha20poly1305;
    } else {
        pub(super) mod aes_gcm;
        pub(super) mod chacha20poly1305;
        pub(super) mod ed25519;
        pub(super) mod mlkem768;
        pub(super) mod p256;
        pub(super) mod rsa_priv;
        pub(super) mod rsa_pub;
        pub mod sha3;
        pub(super) mod xchacha20poly1305;
    }
}

pub(super) mod aes;
pub(super) mod chacha20;
pub(super) mod p384;
pub(super) mod rng;
pub(super) mod sha1;
pub mod sha2;
pub(super) mod util;
pub(super) mod x25519;
