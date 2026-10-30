//! Every provider operation agrees with instant-acme's aws-lc-rs provider.

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use instant_acme::{CryptoProvider, Error, JwkThumbFields, SigningKey};
use rind::hashing::Sha256;
use rind::signing::ecdsa::{self, P256, P384};
use rind::signing::eddsa::Ed25519SigningKey;
use rustls_pki_types::PrivatePkcs8KeyDer;

const RIND: &CryptoProvider = &rind_instant_acme::DEFAULT_PROVIDER;

fn aws_lc() -> &'static CryptoProvider {
    CryptoProvider::aws_lc_rs()
}

/// A fixed-seed xorshift, so a failure reproduces.
struct Rng(u64);

impl Rng {
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len)
            .map(|_| {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                self.0 as u8
            })
            .collect()
    }
}

fn jwk(key: &dyn SigningKey) -> String {
    serde_json::to_string(&key.as_jwk()).unwrap()
}

fn alg(key: &dyn SigningKey) -> String {
    serde_json::to_string(&key.algorithm()).unwrap()
}

/// The uncompressed point a JWK carries, for verifying its key's signatures.
fn point(key: &dyn SigningKey) -> Vec<u8> {
    match key.as_jwk().key {
        JwkThumbFields::Ec { x, y, .. } => [&[4], x, y].concat(),
        other => panic!("not an EC key: {other:?}"),
    }
}

fn load(provider: &CryptoProvider, pkcs8: &[u8]) -> Result<Box<dyn SigningKey>, Error> {
    provider
        .key_provider
        .load_key(PrivatePkcs8KeyDer::from(pkcs8.to_vec()))
}

#[test]
fn generated_keys_load_in_both_providers() {
    for (generator, name) in [(RIND, "rind"), (aws_lc(), "aws-lc-rs")] {
        let (key, pkcs8) = generator.key_provider.generate_key().unwrap();
        let pkcs8 = pkcs8.secret_pkcs8_der();

        let ours = load(RIND, pkcs8).unwrap_or_else(|e| panic!("{name} key in rind: {e}"));
        let theirs = load(aws_lc(), pkcs8).unwrap_or_else(|e| panic!("{name} key in aws-lc: {e}"));

        assert_eq!(jwk(&*key), jwk(&*ours), "{name}");
        assert_eq!(jwk(&*key), jwk(&*theirs), "{name}");
        assert_eq!(alg(&*ours), alg(&*theirs), "{name}");
    }
}

#[test]
fn signatures_verify_across_providers() {
    let (key, pkcs8) = RIND.key_provider.generate_key().unwrap();
    let theirs = load(aws_lc(), pkcs8.secret_pkcs8_der()).unwrap();
    let point = point(&*key);
    let message = b"eyJhbGciOiJFUzI1NiJ9.eyJyaW5kIjp0cnVlfQ";

    let signature = key.sign(message).unwrap();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
        .verify(message, &signature)
        .expect("rind's signature verifies on aws-lc-rs");
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
        .verify(b"other", &signature)
        .expect_err("rind's signature binds the message");

    let signature = theirs.sign(message).unwrap();
    ecdsa::VerifyingKey::<P256>::from_x962_uncompressed(&point)
        .unwrap()
        .verify::<Sha256>(&[message], &signature)
        .expect("aws-lc-rs's signature verifies on rind");
}

#[test]
fn malformed_keys_are_rejected_by_both_providers() {
    let (_, p256) = RIND.key_provider.generate_key().unwrap();
    let p256 = p256.secret_pkcs8_der();
    let p384 = ecdsa::SigningKey::<P384>::generate()
        .unwrap()
        .to_pkcs8_der(&mut [0; 256])
        .unwrap()
        .to_vec();
    let ed25519 = Ed25519SigningKey::generate()
        .unwrap()
        .to_pkcs8_der(&mut [0; 128])
        .unwrap()
        .to_vec();
    let mut flipped = p256.to_vec();
    // The last byte is in the embedded public key, which no longer matches.
    *flipped.last_mut().unwrap() ^= 1;

    for (pkcs8, what) in [
        (&[][..], "empty"),
        (&p256[..p256.len() - 1], "truncated"),
        (&flipped[..], "mismatched public key"),
        (&p384[..], "P-384 key"),
        (&ed25519[..], "Ed25519 key"),
    ] {
        assert!(
            matches!(load(aws_lc(), pkcs8), Err(Error::KeyRejected)),
            "aws-lc-rs accepted {what}"
        );
        assert!(
            matches!(load(RIND, pkcs8), Err(Error::KeyRejected)),
            "rind accepted {what}"
        );
    }
}

#[test]
fn sha256_matches() {
    let mut rng = Rng(0x5eed);
    // Past several 64-byte blocks, so every padding boundary is covered.
    for len in 0..300 {
        let data = rng.bytes(len);
        assert_eq!(
            RIND.sha256.hash(&data),
            aws_lc().sha256.hash(&data),
            "{len}"
        );
    }
}

#[test]
fn hmac_matches() {
    let mut rng = Rng(0xeab);
    // Keys either side of the 64-byte block, past which HMAC hashes the key.
    for key_len in [0, 1, 16, 32, 63, 64, 65, 128, 200] {
        let key = rng.bytes(key_len);
        let ours = RIND.hmac.load_key(&key);
        let theirs = aws_lc().hmac.load_key(&key);
        assert_eq!(
            serde_json::to_string(&ours.algorithm()).unwrap(),
            serde_json::to_string(&theirs.algorithm()).unwrap()
        );

        for len in [0, 1, 55, 56, 64, 65, 300] {
            let data = rng.bytes(len);
            assert_eq!(ours.sign(&data), theirs.sign(&data), "{key_len} {len}");
        }
    }
}
