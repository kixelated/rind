use aws_lc_rs::{digest, hmac, rsa::KeyPair, signature::Ed25519KeyPair};
use proptest::collection::vec;
use proptest::prelude::*;
use rind::hashing::{Hash, HashContext, LegacySha1, hmac::Hmac};
use rind::signing::{
    eddsa::Ed25519SigningKey,
    rsa::{KeySize, SigningKey},
};

#[test]
fn rsa_2048_key_generation() {
    check_key_generation(KeySize::Rsa2048);
}

#[test]
fn rsa_2048_key_generation_soak() {
    if std::env::var_os("SLOW_TESTS").is_some() {
        for _ in 0..512 {
            check_key_generation(KeySize::Rsa2048);
        }
    }
}

#[test]
fn rsa_3072_key_generation() {
    check_key_generation(KeySize::Rsa3072);
}

#[test]
fn rsa_4096_key_generation() {
    check_key_generation(KeySize::Rsa4096);
}

#[test]
fn rsa_6144_key_generation() {
    if std::env::var_os("SLOW_TESTS").is_some() {
        check_key_generation(KeySize::Rsa6144);
    }
}

#[test]
fn rsa_8192_key_generation() {
    if std::env::var_os("SLOW_TESTS").is_some() {
        check_key_generation(KeySize::Rsa8192);
    }
}

fn check_key_generation(size: KeySize) {
    let key = SigningKey::generate(size).unwrap();
    let mut buf = [0u8; 8192];
    let key_enc = key.to_pkcs8_der(&mut buf).unwrap();

    KeyPair::from_pkcs8(key_enc).expect("aws-lc-rs rejected a key we generated");
}

#[test]
fn ed25519_key_generation() {
    for _ in 0..100 {
        let key = Ed25519SigningKey::generate().unwrap();

        let mut buf = [0u8; 128];
        let key_enc = key.to_pkcs8_der(&mut buf).unwrap();

        let aws = Ed25519KeyPair::from_pkcs8(key_enc)
            .expect("aws-lc-rs rejected an ed25519 key we generated");
        assert_eq!(
            aws.to_pkcs8().unwrap().as_ref(),
            key_enc,
            "aws-lc-rs varied our ed25519 key encoding"
        );
    }
}

proptest! {
    #[test]
    fn sha1_matches_aws_lc_rs(
        message in vec(any::<u8>(), 0..1024),
        split in any::<prop::sample::Index>(),
    ) {
        // Two updates split anywhere exercise the partial-block buffering.
        let split = split.index(message.len() + 1);
        let mut ctx = LegacySha1::new();
        ctx.update(&message[..split]);
        ctx.update(&message[split..]);

        let got = ctx.finish();
        let wanted = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &message);
        prop_assert_eq!(got.as_ref(), wanted.as_ref());
    }

    #[test]
    fn hmac_sha1_matches_aws_lc_rs(
        key in vec(any::<u8>(), 0..200),
        message in vec(any::<u8>(), 0..1024),
    ) {
        let mut ctx = Hmac::<LegacySha1>::new(&key);
        ctx.update(&message);
        let got = ctx.finish();

        let wanted = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &key),
            &message,
        );
        prop_assert_eq!(got.as_ref(), wanted.as_ref());
    }
}
