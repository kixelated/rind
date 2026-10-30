//! Constant-time checks for each secret path, run under valgrind by
//! `admin/ctgrind`.
//!
//! Outputs that are public by design are marked defined before the test checks
//! them. rind itself marks the private key it generates, so memcheck flags any
//! branch or memory index that depends on it.

use crabgrind::memcheck::{self, MemState};
use crabgrind::valgrind::{self, RunningMode};
use rcgen::{CertificateParams, PublicKeyData, SerialNumber};
use rind::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _,
    UnparsedPublicKey,
};
use rind_rcgen::KeyPair;

/// Marks `value` public, so the test may branch on it.
fn public<T: ?Sized>(value: &T) {
    mark(value, MemState::Defined);
}

fn mark<T: ?Sized>(value: &T, state: MemState) {
    if let RunningMode::Valgrind = valgrind::running_mode() {
        memcheck::mark_memory((value as *const T).cast(), size_of_val(value), state).unwrap();
    }
}

#[test]
fn self_signed() {
    let key = KeyPair::generate().unwrap();

    let mut params = CertificateParams::new(["localhost".to_string()]).unwrap();
    params.serial_number = Some(SerialNumber::from_slice(&[1]));
    let cert = params.self_signed(&key).unwrap();
    public(cert.der().as_ref());
    assert!(!cert.der().is_empty());

    let signature = rcgen::SigningKey::sign(&key, b"message").unwrap();
    public(&signature[..]);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key.der_bytes())
        .verify(b"message", &signature)
        .unwrap();
}

#[test]
fn export() {
    let key = KeyPair::generate().unwrap();
    // rind treats an exported key as leaving its care, so the encoding is public.
    let der = key.to_pkcs8_der().unwrap();

    let reloaded =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der.secret_pkcs8_der()).unwrap();
    let public_key = reloaded.public_key().as_ref();
    public(public_key);
    assert_eq!(public_key, key.der_bytes());
}
