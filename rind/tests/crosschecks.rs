use aws_lc_rs::rsa::KeyPair;
use aws_lc_rs::{digest, hmac, signature::Ed25519KeyPair};
use proptest::collection::vec;
use proptest::prelude::*;
use rind::hashing::{Hash, HashContext, LegacySha1, hmac::Hmac};
use rind::signing::eddsa::Ed25519SigningKey;
use rind::signing::rsa::{KeySize, SigningKey};

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

mod cipher {
    use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey, quic};
    use aws_lc_rs::cipher::{AES_128, AES_256, EncryptingKey, EncryptionContext, UnboundCipherKey};
    use proptest::prelude::*;
    use rind::Error;
    use rind::cipher::{Aes, AesCtr, ChaCha20};

    fn aes_key() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            prop::collection::vec(any::<u8>(), 16),
            prop::collection::vec(any::<u8>(), 32)
        ]
    }

    fn aws_aes_key(key: &[u8]) -> UnboundCipherKey {
        let alg = if key.len() == 16 { &AES_128 } else { &AES_256 };
        UnboundCipherKey::new(alg, key).unwrap()
    }

    // Counters near the top of the range exercise the wrap refusal.
    fn counter() -> impl Strategy<Value = u32> {
        prop_oneof![any::<u32>(), (u32::MAX - 80)..=u32::MAX]
    }

    proptest! {
        #[test]
        fn aes_block(key in aes_key(), block in any::<[u8; 16]>()) {
            let mut ours = block;
            Aes::new(&key).unwrap().encrypt_block(&mut ours);

            let mut theirs = block;
            EncryptingKey::ecb(aws_aes_key(&key))
                .unwrap()
                .less_safe_encrypt(&mut theirs, EncryptionContext::None)
                .unwrap();
            prop_assert_eq!(ours, theirs);
        }

        #[test]
        fn aes_ctr(
            key in aes_key(),
            nonce in any::<[u8; 12]>(),
            counter in counter(),
            msg in prop::collection::vec(any::<u8>(), 0..1100),
        ) {
            let mut ours = msg.clone();
            let result = AesCtr::new(&key).unwrap().apply_keystream(&nonce, counter, &mut ours);

            // aws-lc-rs carries into the nonce where we refuse, so compare only
            // what we accept.
            let blocks = msg.len().div_ceil(16) as u64;
            if u64::from(counter) + blocks > 1 << 32 {
                prop_assert_eq!(result, Err(Error::WrongLength));
                prop_assert_eq!(ours, msg);
                return Ok(());
            }
            result.unwrap();

            let mut iv = [0u8; 16];
            iv[..12].copy_from_slice(&nonce);
            iv[12..].copy_from_slice(&counter.to_be_bytes());
            let mut theirs = msg.clone();
            if !theirs.is_empty() {
                EncryptingKey::ctr(aws_aes_key(&key))
                    .unwrap()
                    .less_safe_encrypt(&mut theirs, EncryptionContext::Iv128(iv.into()))
                    .unwrap();
            }
            prop_assert_eq!(ours, theirs);
        }

        #[test]
        fn chacha20_header_protection_mask(key in any::<[u8; 32]>(), sample in any::<[u8; 16]>()) {
            let (counter, nonce) = sample.split_at(4);
            let mut ours = [0u8; 5];
            ChaCha20::new(key)
                .apply_keystream(
                    nonce.try_into().unwrap(),
                    u32::from_le_bytes(counter.try_into().unwrap()),
                    &mut ours,
                )
                .unwrap();

            let theirs = quic::HeaderProtectionKey::new(&quic::CHACHA20, &key)
                .unwrap()
                .new_mask(&sample)
                .unwrap();
            prop_assert_eq!(ours, theirs);
        }

        // ChaCha20-Poly1305's ciphertext is the plaintext XORed with the
        // keystream from block 1, which checks long, ragged outputs.
        #[test]
        fn chacha20_keystream(
            key in any::<[u8; 32]>(),
            nonce in any::<[u8; 12]>(),
            msg in prop::collection::vec(any::<u8>(), 0..1100),
        ) {
            let mut ours = msg.clone();
            ChaCha20::new(key).apply_keystream(&nonce, 1, &mut ours).unwrap();

            let mut theirs = msg.clone();
            let _tag = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap())
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::empty(),
                    &mut theirs,
                )
                .unwrap();
            prop_assert_eq!(ours, theirs);
        }
    }
}

mod aead {
    use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::sample::Index;
    use rind::Error;
    use rind::aead::ChaCha20Poly1305;

    proptest! {
        // Decryption opens what aws-lc-rs seals, and refuses it with any one
        // bit of the AAD, ciphertext, or tag flipped.
        #[test]
        fn chacha20_poly1305(
            key in any::<[u8; 32]>(),
            nonce in any::<[u8; 12]>(),
            aad in vec(any::<u8>(), 0..40),
            msg in vec(any::<u8>(), 0..300),
            flip in any::<Index>(),
        ) {
            let mut sealed = msg.clone();
            let tag = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap())
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&aad),
                    &mut sealed,
                )
                .unwrap();
            let ours = ChaCha20Poly1305::new(key);

            let mut opened = sealed.clone();
            ours.decrypt(&nonce, &aad, &mut opened, tag.as_ref()).unwrap();
            prop_assert_eq!(&opened, &msg);

            let mut parts = [aad, sealed, tag.as_ref().to_vec()];
            let mut bit = flip.index(parts.iter().map(|p| p.len() * 8).sum());
            for part in &mut parts {
                if bit < part.len() * 8 {
                    part[bit / 8] ^= 1 << (bit % 8);
                    break;
                }
                bit -= part.len() * 8;
            }
            let [aad, mut forged, tag] = parts;
            prop_assert_eq!(
                ours.decrypt(&nonce, &aad, &mut forged, &tag),
                Err(Error::DecryptFailed)
            );
            prop_assert!(forged.iter().all(|&b| b == 0));
        }
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

mod p384 {
    use aws_lc_rs::agreement::{self, ECDH_P384, EphemeralPrivateKey};
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING,
        EcdsaKeyPair, KeyPair, UnparsedPublicKey,
    };
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rind::hashing::Sha384;
    use rind::key_agreement::p384::{PrivateKey, PublicKey};
    use rind::signing::ecdsa::{P384, SigningKey, VerifyingKey};

    // Each case generates keys on both sides, which is slow under emulation.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn ecdsa(message in vec(any::<u8>(), 0..300)) {
            // aws-lc-rs accepts our key and derives the same public key.
            let ours = SigningKey::<P384>::generate().unwrap();
            let public = ours.private_key.public_key_uncompressed();
            let theirs_from_ours = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P384_SHA384_FIXED_SIGNING,
                ours.to_pkcs8_der(&mut [0; 256]).unwrap(),
            )
            .expect("aws-lc-rs rejected a P-384 key we generated");
            prop_assert_eq!(theirs_from_ours.public_key().as_ref(), &public[..]);

            // It verifies our signatures, in both encodings.
            let theirs_verifier = |alg| UnparsedPublicKey::new(alg, public);
            let mut buf = [0; 128];
            let signature = ours.sign::<Sha384>(&[&message], &mut buf).unwrap();
            theirs_verifier(&ECDSA_P384_SHA384_FIXED).verify(&message, signature).unwrap();
            let signature = ours.sign_asn1::<Sha384>(&[&message], &mut buf).unwrap();
            theirs_verifier(&ECDSA_P384_SHA384_ASN1).verify(&message, signature).unwrap();

            // We verify its signatures, and refuse one over another message.
            let theirs = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).unwrap();
            let signature = theirs.sign(&SystemRandom::new(), &message).unwrap();
            let verifier = VerifyingKey::<P384>::from_x962_uncompressed(theirs.public_key().as_ref())
                .unwrap();
            verifier.verify::<Sha384>(&[&message], signature.as_ref()).unwrap();
            prop_assert!(verifier.verify::<Sha384>(&[&message, b"!"], signature.as_ref()).is_err());
        }

        #[test]
        fn ecdh(_case in any::<u8>()) {
            let ours = PrivateKey::new_random().unwrap();
            let ours_public = ours.public_key_uncompressed();
            let theirs = EphemeralPrivateKey::generate(&ECDH_P384, &SystemRandom::new()).unwrap();
            let theirs_public = theirs.compute_public_key().unwrap();

            let ours_secret = ours
                .diffie_hellman(&PublicKey::from_x962_uncompressed(theirs_public.as_ref()).unwrap())
                .unwrap();
            let theirs_secret = agreement::agree_ephemeral(
                theirs,
                agreement::UnparsedPublicKey::new(&ECDH_P384, ours_public),
                (),
                |secret| Ok(secret.to_vec()),
            )
            .unwrap();
            prop_assert_eq!(&ours_secret.0[..], &theirs_secret[..]);
        }
    }
}
