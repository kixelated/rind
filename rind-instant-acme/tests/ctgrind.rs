//! Constant-time checks for each secret path, run under valgrind by
//! `admin/ctgrind`.
//!
//! Secret inputs are marked undefined, so memcheck flags any branch or memory
//! index that depends on them. Outputs that are public by design are marked
//! defined before the test checks them. rind itself marks the account keys it
//! generates or parses.

use crabgrind::memcheck::{self, MemState};
use crabgrind::valgrind::{self, RunningMode};
use instant_acme::{CryptoProvider, JwkThumbFields};
use rind::hashing::Sha256;
use rind::signing::ecdsa::{P256, VerifyingKey};
use rind_instant_acme::DEFAULT_PROVIDER;

/// Marks `value` secret: memcheck flags any branch or index that depends on it.
fn secret<T: ?Sized>(value: &T) {
    mark(value, MemState::Undefined);
}

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
fn account_key() {
    let (generated, pkcs8) = DEFAULT_PROVIDER.key_provider.generate_key().unwrap();
    let loaded = DEFAULT_PROVIDER.key_provider.load_key(pkcs8).unwrap();
    let message = b"eyJhbGciOiJFUzI1NiJ9.eyJyaW5kIjp0cnVlfQ";

    for key in [generated, loaded] {
        let JwkThumbFields::Ec { x, y, .. } = key.as_jwk().key else {
            panic!("not an EC key");
        };
        let point = [&[4], x, y].concat();
        // The JWK goes out base64url-encoded, which indexes a table by each byte.
        serde_json::to_string(&key.as_jwk()).unwrap();

        let signature = key.sign(message).unwrap();
        public(&signature[..]);
        VerifyingKey::<P256>::from_x962_uncompressed(&point)
            .unwrap()
            .verify::<Sha256>(&[message], &signature)
            .unwrap();
    }
}

#[test]
fn external_account_binding() {
    let key = [0x42u8; 32];
    let message = b"eyJhbGciOiJIUzI1NiJ9.eyJyaW5kIjp0cnVlfQ";
    let expected = CryptoProvider::aws_lc_rs()
        .hmac
        .load_key(&key)
        .sign(message);

    secret(&key);
    let tag = DEFAULT_PROVIDER.hmac.load_key(&key).sign(message);
    public(&tag[..]);
    assert_eq!(tag, expected);
}
