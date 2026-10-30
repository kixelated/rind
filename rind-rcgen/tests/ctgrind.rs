//! Constant-time checks for each secret path, run under valgrind by
//! `admin/ctgrind`.
//!
//! Outputs that are public by design are marked defined before the test checks
//! them. rind itself marks the private key it generates, so memcheck flags any
//! branch or memory index that depends on it.

use crabgrind::memcheck::{self, MemState};
use crabgrind::valgrind::{self, RunningMode};
use rcgen::{CertificateParams, PublicKeyData, SerialNumber};
use rind::hashing::Sha256;
use rind::signing::ecdsa::{P256, SigningKey, VerifyingKey};
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
    VerifyingKey::<P256>::from_x962_uncompressed(key.der_bytes())
        .unwrap()
        .verify_asn1::<Sha256>(&[b"message"], &signature)
        .unwrap();
}

#[test]
fn export() {
    let key = KeyPair::generate().unwrap();
    // rind treats an exported key as leaving its care, so the encoding is public.
    let der = key.to_pkcs8_der().unwrap();

    let reloaded = SigningKey::<P256>::from_pkcs8_der(der.secret_pkcs8_der()).unwrap();
    let public_key = reloaded
        .public_key()
        .unwrap()
        .public_key
        .as_bytes_uncompressed();
    public(&public_key);
    assert_eq!(public_key, key.der_bytes());
}
