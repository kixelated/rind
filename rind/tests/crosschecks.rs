use aws_lc_rs::rsa::KeyPair;
use aws_lc_rs::{digest, hmac, signature::Ed25519KeyPair};
use proptest::collection::vec;
use proptest::prelude::*;
use rind::signature::{self, KeySize, RsaKeyPair};

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
    let key = RsaKeyPair::generate(size).unwrap();
    let mut buf = [0u8; 8192];
    let key_enc = key.to_pkcs8_der(&mut buf).unwrap();

    KeyPair::from_pkcs8(key_enc).expect("aws-lc-rs rejected a key we generated");
}

#[test]
fn ed25519_key_generation() {
    for _ in 0..100 {
        let key = signature::Ed25519KeyPair::generate().unwrap();

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
    fn hashes_match_aws_lc_rs(
        message in vec(any::<u8>(), 0..1024),
        split in any::<prop::sample::Index>(),
    ) {
        // Two updates split anywhere exercise the partial-block buffering.
        let split = split.index(message.len() + 1);
        for (ours, theirs) in [
            (&rind::digest::SHA1_FOR_LEGACY_USE_ONLY, &digest::SHA1_FOR_LEGACY_USE_ONLY),
            (&rind::digest::SHA256, &digest::SHA256),
            (&rind::digest::SHA384, &digest::SHA384),
            (&rind::digest::SHA512, &digest::SHA512),
        ] {
            let mut ctx = rind::digest::Context::new(ours);
            ctx.update(&message[..split]);
            ctx.update(&message[split..]);
            let (got, wanted) = (ctx.finish(), digest::digest(theirs, &message));
            prop_assert_eq!(got.as_ref(), wanted.as_ref());
        }
    }

    #[test]
    fn hmac_matches_aws_lc_rs(
        // Up to 300 bytes spans keys below, at, and above both block sizes (64 and 128).
        key in vec(any::<u8>(), 0..300),
        message in vec(any::<u8>(), 0..1024),
        split in any::<prop::sample::Index>(),
    ) {
        let split = split.index(message.len() + 1);
        for (ours, theirs) in [
            (rind::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY),
            (rind::hmac::HMAC_SHA256, hmac::HMAC_SHA256),
            (rind::hmac::HMAC_SHA384, hmac::HMAC_SHA384),
            (rind::hmac::HMAC_SHA512, hmac::HMAC_SHA512),
        ] {
            let ours = rind::hmac::Key::new(ours, &key);
            let mut ctx = rind::hmac::Context::with_key(&ours);
            ctx.update(&message[..split]);
            ctx.update(&message[split..]);
            let wanted = hmac::sign(&hmac::Key::new(theirs, &key), &message);
            let got = ctx.sign();
            prop_assert_eq!(got.as_ref(), wanted.as_ref());
            prop_assert_eq!(rind::hmac::verify(&ours, &message, wanted.as_ref()), Ok(()));
        }
    }
}

mod cipher {
    use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey, quic};
    use aws_lc_rs::cipher::{AES_128, AES_256, EncryptingKey, EncryptionContext, UnboundCipherKey};
    use proptest::prelude::*;
    use rind::Error;
    use rind::cipher::{self, Aes, AesCtr, ChaCha20};

    fn aes_key() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            prop::collection::vec(any::<u8>(), 16),
            prop::collection::vec(any::<u8>(), 32)
        ]
    }

    fn rind_aes_algorithm(key: &[u8]) -> &'static cipher::Algorithm {
        if key.len() == 16 {
            &cipher::AES_128
        } else {
            &cipher::AES_256
        }
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
            Aes::new(rind_aes_algorithm(&key), &key).unwrap().encrypt_block(&mut ours);

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
            let result = AesCtr::new(rind_aes_algorithm(&key), &key)
                .unwrap()
                .apply_keystream(&nonce, counter, &mut ours);

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

mod hkdf {
    use aws_lc_rs::{aead as their_aead, hkdf as theirs, hmac as their_hmac};
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rind::{Error, aead, hkdf, hmac};

    struct Len(usize);

    impl theirs::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }

    fn check(
        salt: &[u8],
        ikm: &[u8],
        info: &[Vec<u8>],
        len: usize,
    ) -> Result<(), TestCaseError> {
        let info: Vec<&[u8]> = info.iter().map(Vec::as_slice).collect();

        let mut ours_out = vec![0u8; len];
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);
        let result = prk
            .expand(&info, len)
            .and_then(|okm| okm.fill(&mut ours_out));

        let prk = theirs::Salt::new(theirs::HKDF_SHA256, salt).extract(ikm);
        match prk.expand(&info, Len(len)) {
            Ok(okm) => {
                result.unwrap();
                let mut theirs_out = vec![0u8; len];
                okm.fill(&mut theirs_out).unwrap();
                prop_assert_eq!(ours_out, theirs_out);
            }
            Err(_) => {
                prop_assert_eq!(result, Err(Error::WrongLength));
                prop_assert!(ours_out.iter().all(|b| *b == 0));
            }
        }
        Ok(())
    }

    // Salts either side of the block size, info split into parts, and
    // lengths up to a few blocks or either side of the 255-block limit.
    proptest! {
        #[test]
        fn sha256(
            salt in vec(any::<u8>(), 0..200),
            ikm in vec(any::<u8>(), 0..200),
            info in vec(vec(any::<u8>(), 0..100), 0..4),
            len in prop_oneof![0..200usize, (255 * 32 - 70usize)..(255 * 32 + 70)],
        ) {
            check(&salt, &ikm, &info, len)?;
        }

        // Keys built straight from an `Okm` match aws-lc-rs's conversions.
        #[test]
        fn keys(
            ikm in vec(any::<u8>(), 0..100),
            info in vec(vec(any::<u8>(), 0..50), 0..3),
            msg in vec(any::<u8>(), 0..100),
        ) {
            let info: Vec<&[u8]> = info.iter().map(Vec::as_slice).collect();
            let ours = hkdf::Salt::new(hkdf::HKDF_SHA256, b"salt").extract(&ikm);
            let theirs = theirs::Salt::new(theirs::HKDF_SHA256, b"salt").extract(&ikm);

            for (ours_alg, theirs_alg) in [
                (&aead::AES_128_GCM, &their_aead::AES_128_GCM),
                (&aead::AES_256_GCM, &their_aead::AES_256_GCM),
                (&aead::CHACHA20_POLY1305, &their_aead::CHACHA20_POLY1305),
            ] {
                let ours_key = aead::LessSafeKey::new(aead::UnboundKey::from(
                    ours.expand(&info, ours_alg).unwrap(),
                ));
                let mut ours_sealed = msg.clone();
                ours_key
                    .seal_in_place_append_tag(
                        aead::Nonce::assume_unique_for_key([0; 12]),
                        aead::Aad::empty(),
                        &mut ours_sealed,
                    )
                    .unwrap();

                let theirs_key = their_aead::LessSafeKey::new(their_aead::UnboundKey::from(
                    theirs.expand(&info, theirs_alg).unwrap(),
                ));
                let mut theirs_sealed = msg.clone();
                theirs_key
                    .seal_in_place_append_tag(
                        their_aead::Nonce::assume_unique_for_key([0; 12]),
                        their_aead::Aad::empty(),
                        &mut theirs_sealed,
                    )
                    .unwrap();
                prop_assert_eq!(ours_sealed, theirs_sealed);
            }

            for (ours_alg, theirs_alg) in [
                (hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, their_hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY),
                (hmac::HMAC_SHA256, their_hmac::HMAC_SHA256),
                (hmac::HMAC_SHA384, their_hmac::HMAC_SHA384),
                (hmac::HMAC_SHA512, their_hmac::HMAC_SHA512),
            ] {
                let ours_key = hmac::Key::from(ours.expand(&info, ours_alg).unwrap());
                let theirs_key = their_hmac::Key::from(theirs.expand(&info, theirs_alg).unwrap());
                let ours_tag = hmac::sign(&ours_key, &msg);
                let theirs_tag = their_hmac::sign(&theirs_key, &msg);
                prop_assert_eq!(ours_tag.as_ref(), theirs_tag.as_ref());
            }
        }
    }
}

mod aead {
    use aws_lc_rs::aead as theirs;
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::sample::Index;
    use rind::Error;
    use rind::aead::{
        AES_128_GCM, AES_256_GCM, Aad, Algorithm, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey,
    };

    /// Seals on both sides and compares, then opens aws-lc-rs's output,
    /// first with one bit of its ciphertext or tag flipped if `flip` is set.
    fn check(
        ours: &'static Algorithm,
        theirs: &'static theirs::Algorithm,
        key: &[u8],
        nonce: [u8; 12],
        aad: &[u8],
        msg: &[u8],
        flip: Option<Index>,
    ) -> Result<(), TestCaseError> {
        let ours = LessSafeKey::new(UnboundKey::new(ours, key).unwrap());
        let mut ours_sealed = msg.to_vec();
        ours.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut ours_sealed,
        )
        .unwrap();

        let mut theirs_sealed = msg.to_vec();
        theirs::LessSafeKey::new(theirs::UnboundKey::new(theirs, key).unwrap())
            .seal_in_place_append_tag(
                theirs::Nonce::assume_unique_for_key(nonce),
                theirs::Aad::from(aad),
                &mut theirs_sealed,
            )
            .unwrap();
        prop_assert_eq!(&ours_sealed, &theirs_sealed);

        if let Some(flip) = flip {
            let index = flip.index(theirs_sealed.len());
            theirs_sealed[index] ^= 1;
        }
        let result = ours
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut theirs_sealed,
            )
            .map(|plain| plain.to_vec());
        if flip.is_some() {
            prop_assert_eq!(result, Err(Error::DecryptFailed));
        } else {
            prop_assert_eq!(result, Ok(msg.to_vec()));
        }
        Ok(())
    }

    // Messages and AAD span several blocks with ragged tails.
    proptest! {
        #[test]
        fn aes_gcm(
            key in prop_oneof![vec(any::<u8>(), 16), vec(any::<u8>(), 32)],
            nonce in any::<[u8; 12]>(),
            aad in vec(any::<u8>(), 0..100),
            msg in vec(any::<u8>(), 0..1100),
            flip in any::<Option<Index>>(),
        ) {
            let (ours, theirs) = if key.len() == 16 {
                (&AES_128_GCM, &theirs::AES_128_GCM)
            } else {
                (&AES_256_GCM, &theirs::AES_256_GCM)
            };
            check(ours, theirs, &key, nonce, &aad, &msg, flip)?;
        }

        #[test]
        fn chacha20_poly1305(
            key in any::<[u8; 32]>(),
            nonce in any::<[u8; 12]>(),
            aad in vec(any::<u8>(), 0..100),
            msg in vec(any::<u8>(), 0..1100),
            flip in any::<Option<Index>>(),
        ) {
            check(&CHACHA20_POLY1305, &theirs::CHACHA20_POLY1305, &key, nonce, &aad, &msg, flip)?;
        }
    }
}

/// ECDSA and ECDH on one curve: aws-lc-rs and rind accept each other's keys,
/// signatures, and public keys.
macro_rules! ec_crosschecks {
    ($curve:ident, $ecdh:ident, $fixed_signing:ident, $fixed:ident, $asn1_signing:ident, $asn1:ident) => {
        mod $curve {
            use aws_lc_rs::agreement::{self, $ecdh, EphemeralPrivateKey};
            use aws_lc_rs::encoding::{AsBigEndian, AsDer};
            use aws_lc_rs::rand::SystemRandom;
            use aws_lc_rs::signature::{
                $asn1, $asn1_signing, $fixed, $fixed_signing, EcdsaKeyPair, KeyPair,
                UnparsedPublicKey,
            };
            use proptest::collection::vec;
            use proptest::prelude::*;
            use rind::signature::{self, KeyPair as _};

            // Each case generates keys on both sides, which is slow under emulation.
            proptest! {
                #![proptest_config(ProptestConfig::with_cases(32))]

                #[test]
                fn ecdsa(message in vec(any::<u8>(), 0..300)) {
                    // aws-lc-rs accepts our key and derives the same public
                    // key, encodings, and scalar.
                    let ours = signature::EcdsaKeyPair::generate(&signature::$fixed_signing).unwrap();
                    let public = ours.public_key().as_ref();
                    let theirs_from_ours = EcdsaKeyPair::from_pkcs8(
                        &$fixed_signing,
                        ours.to_pkcs8_der(&mut [0; 256]).unwrap(),
                    )
                    .expect("aws-lc-rs rejected a key we generated");
                    prop_assert_eq!(theirs_from_ours.public_key().as_ref(), public);
                    let spki = theirs_from_ours.public_key().as_der().unwrap();
                    prop_assert_eq!(spki.as_ref(), ours.to_spki_der(&mut [0; 256]).unwrap().to_vec());
                    let scalar = theirs_from_ours.private_key().as_be_bytes().unwrap();
                    prop_assert_eq!(scalar.as_ref(), ours.to_private_key_be(&mut [0; 64]).unwrap().to_vec());

                    // We load its scalar and point as the same key, and refuse
                    // the scalar with another key's point.
                    let reloaded = signature::EcdsaKeyPair::from_private_key_and_public_key(
                        &signature::$asn1_signing,
                        scalar.as_ref(),
                        public,
                    )
                    .unwrap();
                    prop_assert_eq!(reloaded.public_key().as_ref(), public);
                    let other = EcdsaKeyPair::generate(&$fixed_signing).unwrap();
                    prop_assert!(signature::EcdsaKeyPair::from_private_key_and_public_key(
                        &signature::$asn1_signing,
                        scalar.as_ref(),
                        other.public_key().as_ref(),
                    )
                    .is_err());

                    // It verifies our signatures, in both encodings.
                    let theirs_verifier = |alg| UnparsedPublicKey::new(alg, public);
                    let signature = ours.sign(&message).unwrap();
                    theirs_verifier(&$fixed).verify(&message, signature.as_ref()).unwrap();
                    let signature = reloaded.sign(&message).unwrap();
                    theirs_verifier(&$asn1).verify(&message, signature.as_ref()).unwrap();

                    // We verify its signatures, in both encodings, and refuse
                    // one over another message.
                    for (signing, ours_verification) in [
                        (&$fixed_signing, &signature::$fixed),
                        (&$asn1_signing, &signature::$asn1),
                    ] {
                        let theirs = EcdsaKeyPair::generate(signing).unwrap();
                        let signature = theirs.sign(&SystemRandom::new(), &message).unwrap();
                        let verifier =
                            signature::UnparsedPublicKey::new(ours_verification, theirs.public_key());
                        verifier.verify(&message, signature.as_ref()).unwrap();
                        prop_assert!(
                            verifier.verify(&[&message[..], b"!"].concat(), signature.as_ref()).is_err()
                        );
                    }
                }

                #[test]
                fn ecdh(_case in any::<u8>()) {
                    let ours = rind::agreement::EphemeralPrivateKey::generate(&rind::agreement::$ecdh)
                        .unwrap();
                    let ours_public = ours.compute_public_key();
                    let theirs = EphemeralPrivateKey::generate(&$ecdh, &SystemRandom::new()).unwrap();
                    let theirs_public = theirs.compute_public_key().unwrap();

                    let ours_secret = rind::agreement::agree_ephemeral(
                        ours,
                        &rind::agreement::UnparsedPublicKey::new(
                            &rind::agreement::$ecdh,
                            theirs_public.as_ref(),
                        ),
                    )
                    .unwrap();
                    let theirs_secret = agreement::agree_ephemeral(
                        theirs,
                        agreement::UnparsedPublicKey::new(&$ecdh, ours_public.as_ref()),
                        (),
                        |secret| Ok(secret.to_vec()),
                    )
                    .unwrap();
                    prop_assert_eq!(ours_secret.as_ref(), &theirs_secret[..]);
                }
            }
        }
    };
}

ec_crosschecks!(
    p256,
    ECDH_P256,
    ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P256_SHA256_ASN1
);

ec_crosschecks!(
    p384,
    ECDH_P384,
    ECDSA_P384_SHA384_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED,
    ECDSA_P384_SHA384_ASN1_SIGNING,
    ECDSA_P384_SHA384_ASN1
);

mod ed25519 {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::sample::Index;
    use rind::signature;

    proptest! {
        #[test]
        fn sign_verify(
            seed in any::<[u8; 32]>(),
            message in vec(any::<u8>(), 0..300),
            flip in any::<Option<Index>>(),
        ) {
            // Signing is deterministic, so one seed gives both sides the same
            // public key, encoding, and signatures; loading ours checks the
            // public key matches theirs.
            let theirs = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
            let public = theirs.public_key().as_ref();
            let ours = signature::Ed25519KeyPair::from_seed_and_public_key(&seed, public).unwrap();
            let spki = theirs.public_key().as_der().unwrap();
            prop_assert_eq!(ours.to_spki_der(&mut [0; 64]).unwrap().to_vec(), spki.as_ref());
            prop_assert_eq!(ours.seed(), seed);
            let signature = ours.sign(&message);
            let theirs_signature = theirs.sign(&message);
            prop_assert_eq!(signature.as_ref(), theirs_signature.as_ref());

            // Both verify it, and refuse it with any one bit flipped.
            let mut signature = signature.as_ref().to_vec();
            if let Some(flip) = flip {
                let bit = flip.index(signature.len() * 8);
                signature[bit / 8] ^= 1 << (bit % 8);
            }
            let ours_result =
                signature::UnparsedPublicKey::new(&signature::ED25519, public).verify(&message, &signature);
            let theirs_result = UnparsedPublicKey::new(&ED25519, public).verify(&message, &signature);
            prop_assert_eq!(ours_result.is_ok(), flip.is_none());
            prop_assert_eq!(theirs_result.is_ok(), flip.is_none());
        }

        #[test]
        fn seed_and_public_key(seed in any::<[u8; 32]>(), other in any::<[u8; 32]>()) {
            // Both load a seed with its public key, and refuse it with another's.
            let public = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
            let public = public.public_key().as_ref();
            let wrong = Ed25519KeyPair::from_seed_unchecked(&other).unwrap();
            let wrong = wrong.public_key().as_ref();

            signature::Ed25519KeyPair::from_seed_and_public_key(&seed, public).unwrap();
            Ed25519KeyPair::from_seed_and_public_key(&seed, public).unwrap();
            prop_assert_eq!(
                signature::Ed25519KeyPair::from_seed_and_public_key(&seed, wrong).is_ok(),
                seed == other
            );
            prop_assert_eq!(
                Ed25519KeyPair::from_seed_and_public_key(&seed, wrong).is_ok(),
                seed == other
            );
        }
    }
}

mod rsa {
    use std::sync::LazyLock;

    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::{KeyPair, KeySize};
    use aws_lc_rs::signature::{self, KeyPair as _, UnparsedPublicKey};
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rind::Error;
    use rind::signature::{KeyPair as _, RsaKeyPair};

    /// One padding and hash: each side's signing and verification constants.
    struct Scheme {
        ours_sign: &'static rind::signature::RsaSignatureEncoding,
        ours_verify: &'static rind::signature::RsaParameters,
        theirs_sign: &'static signature::RsaSignatureEncoding,
        theirs_verify: &'static signature::RsaParameters,
        /// PKCS#1 v1.5 signatures have no randomness, so both sides must agree.
        deterministic: bool,
    }

    const SCHEMES: [Scheme; 6] = [
        Scheme {
            ours_sign: &rind::signature::RSA_PKCS1_SHA256,
            ours_verify: &rind::signature::RSA_PKCS1_2048_8192_SHA256,
            theirs_sign: &signature::RSA_PKCS1_SHA256,
            theirs_verify: &signature::RSA_PKCS1_2048_8192_SHA256,
            deterministic: true,
        },
        Scheme {
            ours_sign: &rind::signature::RSA_PKCS1_SHA384,
            ours_verify: &rind::signature::RSA_PKCS1_2048_8192_SHA384,
            theirs_sign: &signature::RSA_PKCS1_SHA384,
            theirs_verify: &signature::RSA_PKCS1_2048_8192_SHA384,
            deterministic: true,
        },
        Scheme {
            ours_sign: &rind::signature::RSA_PKCS1_SHA512,
            ours_verify: &rind::signature::RSA_PKCS1_2048_8192_SHA512,
            theirs_sign: &signature::RSA_PKCS1_SHA512,
            theirs_verify: &signature::RSA_PKCS1_2048_8192_SHA512,
            deterministic: true,
        },
        Scheme {
            ours_sign: &rind::signature::RSA_PSS_SHA256,
            ours_verify: &rind::signature::RSA_PSS_2048_8192_SHA256,
            theirs_sign: &signature::RSA_PSS_SHA256,
            theirs_verify: &signature::RSA_PSS_2048_8192_SHA256,
            deterministic: false,
        },
        Scheme {
            ours_sign: &rind::signature::RSA_PSS_SHA384,
            ours_verify: &rind::signature::RSA_PSS_2048_8192_SHA384,
            theirs_sign: &signature::RSA_PSS_SHA384,
            theirs_verify: &signature::RSA_PSS_2048_8192_SHA384,
            deterministic: false,
        },
        Scheme {
            ours_sign: &rind::signature::RSA_PSS_SHA512,
            ours_verify: &rind::signature::RSA_PSS_2048_8192_SHA512,
            theirs_sign: &signature::RSA_PSS_SHA512,
            theirs_verify: &signature::RSA_PSS_2048_8192_SHA512,
            deterministic: false,
        },
    ];

    // Loaded by both: one key generated by aws-lc-rs (`check_key_generation`
    // covers the reverse), and OpenSSL keys whose moduli are not a whole
    // number of words, which aws-lc-rs cannot generate. At 2049 bits PSS's
    // encoded message is a byte shorter than the modulus, at 2050 bits it
    // masks seven top bits, and 2056 bits is a whole number of bytes.
    // Key generation is slow under emulation, so there is one of each.
    static THEIRS: LazyLock<[KeyPair; 4]> = LazyLock::new(|| {
        [
            KeyPair::generate(KeySize::Rsa2048).unwrap(),
            KeyPair::from_pkcs8(include_bytes!("../src/high/rsa/rsa2049.pkcs8.der")).unwrap(),
            KeyPair::from_pkcs8(include_bytes!("../src/high/rsa/rsa2050.pkcs8.der")).unwrap(),
            KeyPair::from_pkcs8(include_bytes!("../src/high/rsa/rsa2056.pkcs8.der")).unwrap(),
        ]
    });

    // Each case makes a dozen private-key operations per key, which are slow
    // under emulation.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        #[test]
        fn sign_verify(message in vec(any::<u8>(), 0..300)) {
            for theirs in &*THEIRS {
                let ours = RsaKeyPair::from_pkcs8(theirs.as_der().unwrap().as_ref()).unwrap();
                let public = theirs.public_key().as_ref();
                prop_assert_eq!(ours.public_key().as_ref(), public);
                let spki = theirs.public_key().as_der().unwrap();
                prop_assert_eq!(ours.to_spki_der(&mut [0; 512]).unwrap().to_vec(), spki.as_ref());
                let rng = SystemRandom::new();
                let len = theirs.public_modulus_len();
                prop_assert_eq!(ours.public_modulus_len(), len);

                for scheme in &SCHEMES {
                    // It verifies our signature.
                    let mut ours_signature = vec![0u8; len];
                    ours.sign(scheme.ours_sign, &message, &mut ours_signature).unwrap();
                    UnparsedPublicKey::new(scheme.theirs_verify, public)
                        .verify(&message, &ours_signature)
                        .unwrap();

                    // We verify its signature, and refuse it over another message.
                    let mut theirs_signature = vec![0u8; len];
                    theirs
                        .sign(scheme.theirs_sign, &rng, &message, &mut theirs_signature)
                        .unwrap();
                    if scheme.deterministic {
                        prop_assert_eq!(&ours_signature, &theirs_signature);
                    }
                    let verifier = rind::signature::UnparsedPublicKey::new(scheme.ours_verify, public);
                    verifier.verify(&message, &theirs_signature).unwrap();
                    prop_assert_eq!(
                        verifier.verify(&[&message[..], b"!"].concat(), &theirs_signature),
                        Err(Error::BadSignature)
                    );
                }
            }
        }
    }

    #[test]
    fn refuses_modulus_below_2048_bits() {
        let private = include_bytes!("../src/high/rsa/rsa2047.pkcs8.der");
        assert!(KeyPair::from_pkcs8(private).is_err());
        assert_eq!(
            RsaKeyPair::from_pkcs8(private).err(),
            Some(Error::OutOfRange)
        );
        let public = include_bytes!("../src/high/rsa/rsa2047.pub.der");
        assert_eq!(
            rind::signature::UnparsedPublicKey::new(
                &rind::signature::RSA_PKCS1_2048_8192_SHA256,
                public
            )
            .verify(b"", &[0; 256])
            .err(),
            Some(Error::OutOfRange)
        );
    }
}

mod mlkem768 {
    use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, ML_KEM_768};
    use proptest::prelude::*;
    use rind::kem;

    // Each case generates a key, which is slow under emulation.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        // aws-lc-rs decapsulates what we encapsulate to its key.
        #[test]
        fn encapsulated_by_ours(_case in any::<u8>()) {
            let theirs = DecapsulationKey::generate(&ML_KEM_768).unwrap();
            let theirs_public = theirs.encapsulation_key().unwrap().key_bytes().unwrap();
            let (ciphertext, secret) =
                kem::EncapsulationKey::new(&kem::ML_KEM_768, theirs_public.as_ref())
                    .unwrap()
                    .encapsulate()
                    .unwrap();
            let theirs_secret = theirs
                .decapsulate(Ciphertext::from(ciphertext.as_ref()))
                .unwrap();
            prop_assert_eq!(secret.as_ref(), theirs_secret.as_ref());
        }
    }
}
