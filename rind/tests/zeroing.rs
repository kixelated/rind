//! Verification that long-term key data is zeroed.
//!
//! Some of this is subject to whims of the compiler, and
//! hand-written drop impls, so we test it here.
//!
//! Is this test sound? Well, it's a deliberate use-after-drop,
//! so no.
//!
//! To make this work deterministically, we depend on two things:
//!  1. The test checks for zeroisation after dropping
//!     a value but before deallocating it. See the function
//!     `check_zeroed_on_drop` for details.
//!  2. The types whose zeroization is being tested must be
//!     _completely_ filled with zero bytes upon drop, including
//!     any padding bytes. If you have a type like this:
//!     ```
//!     #[repr(C)]
//!     struct Key {
//!         a: u8,
//!         // Note: 7 bytes of padding here, due to the "repr(C)"
//!         b: u64,
//!     }
//!     ```
//!     its drop function can't just do a field-wise zeroing
//!     ```
//!     self.a = 0;
//!     self.b = 0;
//!     ```
//!     because this test will check that the padding bytes between
//!     `a` and `b` have been zeroised too.
//!     Similarly, if the object is an enum wrapping different sized
//!     types, like this:
//!     ```
//!     enum Key {
//!         Key128([u8; 16]),
//!         Key256([u8; 32]),
//!     }
//!     ```
//!     this test will check that all `mem::size_of<Key>` bytes have
//!     been zeroised upon drop, even if the value was a `Key::Key128`
//!     that only initialized half of that space.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use core::mem::size_of;
use core::ops::Deref;
use core::pin::Pin;
use core::ptr;
use std::alloc::{Layout, dealloc};

#[test]
fn rsa() {
    use rind::signature::RsaKeyPair;
    let rsa = RsaKeyPair::from_der(include_bytes!("../src/high/rsa/rsa8192.der")).unwrap();
    check_zeroed_on_drop(Box::pin(rsa));
}

#[test]
fn ecdsa() {
    use rind::signature::*;
    for (algorithm, pkcs8) in [
        (
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &include_bytes!("../src/high/ecdsa/secp256r1.pkcs8.der")[..],
        ),
        (
            &ECDSA_P384_SHA384_ASN1_SIGNING,
            &include_bytes!("../src/high/ecdsa/secp384r1.pkcs8.der")[..],
        ),
    ] {
        check_zeroed_on_drop(Box::pin(
            EcdsaKeyPair::from_pkcs8(algorithm, pkcs8).unwrap(),
        ));
    }
}

#[test]
fn ed25519() {
    use rind::signature::Ed25519KeyPair;
    let ed25519 =
        Ed25519KeyPair::from_pkcs8(include_bytes!("../src/high/asn1/testdata/ed25519-p8v2.bin"))
            .unwrap();
    check_zeroed_on_drop(Box::pin(ed25519));
}

#[test]
fn ecdh() {
    use rind::agreement::*;
    for algorithm in [&X25519, &ECDH_P256, &ECDH_P384] {
        let key = EphemeralPrivateKey::generate(algorithm).unwrap();
        check_zeroed_on_drop(Box::pin(key));
    }
}

#[test]
fn mlkem768() {
    use rind::kem::*;
    check_zeroed_on_drop(Box::pin(DecapsulationKey::generate(&ML_KEM_768).unwrap()));
}

#[test]
fn hkdf() {
    use rind::hashing::hkdf::Prk;
    use rind::hashing::{Sha256, Sha512};

    check_zeroed_on_drop(Box::pin(Prk::<Sha256>::extract(b"salt", b"ikm")));
    check_zeroed_on_drop(Box::pin(Prk::<Sha512>::extract(b"salt", b"ikm")));
}

#[test]
fn hmac() {
    use rind::hashing::hmac::Hmac;
    use rind::hashing::{LegacySha1, Sha256, Sha384, Sha512};

    // A partial block leaves message bytes buffered beside the keyed states.
    macro_rules! check {
        ($($H:ty),*) => {$({
            let mut hmac = Hmac::<$H>::new([0xffu8; 32]);
            hmac.update([0xffu8; 3]);
            check_zeroed_on_drop(Box::pin(hmac));
        })*};
    }

    check!(LegacySha1, Sha256, Sha384, Sha512);
}

#[test]
fn aead() {
    use rind::aead::{
        AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305, LessSafeKey, RandomizedNonceKey, UnboundKey,
    };

    for algorithm in [&AES_128_GCM, &AES_256_GCM, &CHACHA20_POLY1305] {
        let key = UnboundKey::new(algorithm, &[0xffu8; 32][..algorithm.key_len()]).unwrap();
        check_zeroed_on_drop(Box::pin(LessSafeKey::new(key)));
    }
    check_zeroed_on_drop(Box::pin(RandomizedNonceKey::new(&[0xffu8; 32])));
}

#[test]
fn cipher() {
    use rind::cipher::{AES_128, AES_256, Aes, AesCtr, ChaCha20};
    for (algorithm, len) in [(&AES_128, 16), (&AES_256, 32)] {
        let key = &[0xffu8; 32][..len];
        check_zeroed_on_drop(Box::pin(Aes::new(algorithm, key).unwrap()));
        check_zeroed_on_drop(Box::pin(AesCtr::new(algorithm, key).unwrap()));
    }
    check_zeroed_on_drop(Box::pin(ChaCha20::new([0xffu8; 32])));
}

fn check_zeroed_on_drop<T: Unpin>(value: Pin<Box<T>>) {
    let ptr = value.deref() as *const T as *const u8;
    let len = size_of::<T>();
    assert_ne!(len, 0);
    println!("this value is {len} bytes in length");
    let before_drop = read_into_vec(ptr, len);

    // Drop `value` and then read its contents to verify they've been zeroed.
    //
    // Note that we can't just do `drop(value)` and then read the memory where
    // `value` used to be, because of a race condition: if any code in this or
    // any other thread does a heap allocation between the freeing of `value`
    // and the read, that allocation might reuse the same memory where `value`
    // used to live, and those bytes could be overwritten before the read begins.
    //
    // Instead, we unwrap `value`'s `Pin<Box>` to get a raw pointer, call
    // `drop_in_place` on that raw pointer to invoke the object's `Drop`
    // implementation, then make a copy of the memory where `value` used to live,
    // and then finally deallocate the raw pointer to free the memory.

    // SAFETY: After unpinning `value`, we do not do anything that might move it before dropping it.
    let addr = Box::into_raw(unsafe { Pin::into_inner_unchecked(value) });

    // SAFETY: We obtained `addr` by unwrapping a valid `Box<T>`, so it is aligned and non-null.
    unsafe {
        ptr::drop_in_place(addr);
    }
    let after_drop = read_into_vec(ptr, len);
    // SAFETY: We obtained `addr` by unwrapping a valid `Box<T>`, so it is allocated and `T-`aligned.
    unsafe {
        dealloc(addr as *mut u8, Layout::new::<T>());
    }

    for i in HEAP_FREELIST_ZONE.0..len - HEAP_FREELIST_ZONE.1 {
        if after_drop[i] != 0x00 {
            println!("before_drop: {before_drop:02x?}");
            println!("after_drop: {after_drop:02x?}");
            panic!(
                "byte {i} (0x{:x?}) was not cleared after drop",
                after_drop[i]
            );
        }
    }
}

fn read_into_vec(ptr: *const u8, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);

    for i in 0..len {
        // Safety: none
        let byte = unsafe { ptr::read_volatile(ptr.add(i)) };
        out.push(byte);
    }
    out
}

/// Bytes written by the heap to (probably) keep the freed chunk
/// in the freelist.
///
/// These values from observation; likely very fragile.
const HEAP_FREELIST_ZONE: (usize, usize) = (16, 0);
