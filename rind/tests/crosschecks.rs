use aws_lc_rs::{rsa::KeyPair, signature::Ed25519KeyPair};
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

mod hkdf {
    use aws_lc_rs::hkdf::{self, HKDF_SHA256, HKDF_SHA384, HKDF_SHA512, KeyType};
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rind::Error;
    use rind::hashing::hkdf::Prk;
    use rind::hashing::{Hash, Sha256, Sha384, Sha512};

    struct Len(usize);

    impl KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }

    fn check<H: Hash>(
        alg: hkdf::Algorithm,
        salt: &[u8],
        ikm: &[u8],
        info: &[Vec<u8>],
        len: usize,
    ) -> Result<(), TestCaseError> {
        let info: Vec<&[u8]> = info.iter().map(Vec::as_slice).collect();

        let mut ours = vec![0u8; len];
        let result = Prk::<H>::extract(salt, ikm).expand(&info, &mut ours);

        let prk = hkdf::Salt::new(alg, salt).extract(ikm);
        match prk.expand(&info, Len(len)) {
            Ok(okm) => {
                result.unwrap();
                let mut theirs = vec![0u8; len];
                okm.fill(&mut theirs).unwrap();
                prop_assert_eq!(ours, theirs);
            }
            Err(_) => {
                prop_assert_eq!(result, Err(Error::WrongLength));
                prop_assert!(ours.iter().all(|b| *b == 0));
            }
        }
        Ok(())
    }

    // Lengths up to a few blocks, or either side of the 255-block limit.
    fn out_len(hash_len: usize) -> impl Strategy<Value = usize> {
        prop_oneof![0..200usize, (255 * hash_len - 70)..(255 * hash_len + 70)]
    }

    // Salts either side of the block size, and info split into parts.
    proptest! {
        #[test]
        fn sha256(
            salt in vec(any::<u8>(), 0..200),
            ikm in vec(any::<u8>(), 0..200),
            info in vec(vec(any::<u8>(), 0..100), 0..4),
            len in out_len(32),
        ) {
            check::<Sha256>(HKDF_SHA256, &salt, &ikm, &info, len)?;
        }

        #[test]
        fn sha384(
            salt in vec(any::<u8>(), 0..200),
            ikm in vec(any::<u8>(), 0..200),
            info in vec(vec(any::<u8>(), 0..100), 0..4),
            len in out_len(48),
        ) {
            check::<Sha384>(HKDF_SHA384, &salt, &ikm, &info, len)?;
        }

        #[test]
        fn sha512(
            salt in vec(any::<u8>(), 0..200),
            ikm in vec(any::<u8>(), 0..200),
            info in vec(vec(any::<u8>(), 0..100), 0..4),
            len in out_len(64),
        ) {
            check::<Sha512>(HKDF_SHA512, &salt, &ikm, &info, len)?;
        }
    }
}
