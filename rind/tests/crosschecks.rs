use aws_lc_rs::rsa::KeyPair;
use aws_lc_rs::{digest, hmac, signature::Ed25519KeyPair};
use proptest::collection::vec;
use proptest::prelude::*;
use rind::hashing::{Hash, HashContext, LegacySha1, Sha256, Sha384, Sha512, hmac::Hmac};
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
    fn hashes_match_aws_lc_rs(
        message in vec(any::<u8>(), 0..1024),
        split in any::<prop::sample::Index>(),
    ) {
        // Two updates split anywhere exercise the partial-block buffering.
        let split = split.index(message.len() + 1);
        check_hash::<LegacySha1>(&digest::SHA1_FOR_LEGACY_USE_ONLY, &message, split)?;
        check_hash::<Sha256>(&digest::SHA256, &message, split)?;
        check_hash::<Sha384>(&digest::SHA384, &message, split)?;
        check_hash::<Sha512>(&digest::SHA512, &message, split)?;
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

    #[test]
    fn hmac_sha2_matches_aws_lc_rs(
        // Up to 300 bytes spans keys below, at, and above both block sizes (64 and 128).
        key in vec(any::<u8>(), 0..300),
        message in vec(any::<u8>(), 0..1024),
    ) {
        check_hmac::<Sha256>(hmac::HMAC_SHA256, &key, &message)?;
        check_hmac::<Sha384>(hmac::HMAC_SHA384, &key, &message)?;
        check_hmac::<Sha512>(hmac::HMAC_SHA512, &key, &message)?;
    }
}

fn check_hash<H: Hash>(
    algorithm: &'static digest::Algorithm,
    message: &[u8],
    split: usize,
) -> Result<(), TestCaseError> {
    let mut ctx = H::new();
    ctx.update(&message[..split]);
    ctx.update(&message[split..]);

    let got = ctx.finish();
    let wanted = digest::digest(algorithm, message);
    prop_assert_eq!(got.as_ref(), wanted.as_ref());
    Ok(())
}

fn check_hmac<H: Hash>(
    algorithm: hmac::Algorithm,
    key: &[u8],
    message: &[u8],
) -> Result<(), TestCaseError> {
    let mut ctx = Hmac::<H>::new(key);
    ctx.update(message);
    let got = ctx.finish();

    let wanted = hmac::sign(&hmac::Key::new(algorithm, key), message);
    prop_assert_eq!(got.as_ref(), wanted.as_ref());
    Ok(())
}

// SHA-3 is not built on armv7.
#[cfg(not(target_arch = "arm"))]
mod sha3 {
    use aws_lc_rs::digest;
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rind::hashing::sha3::{Sha3_256Context, Sha3_512Context};

    proptest! {
        #[test]
        fn matches_aws_lc_rs(
            message in vec(any::<u8>(), 0..1024),
            split in any::<prop::sample::Index>(),
        ) {
            // Two updates split anywhere exercise the partial-block buffering.
            let split = split.index(message.len() + 1);

            let mut ctx = Sha3_256Context::new();
            ctx.update(&message[..split]);
            ctx.update(&message[split..]);
            let wanted = digest::digest(&digest::SHA3_256, &message);
            prop_assert_eq!(&ctx.finish()[..], wanted.as_ref());

            let mut ctx = Sha3_512Context::new();
            ctx.update(&message[..split]);
            ctx.update(&message[split..]);
            let wanted = digest::digest(&digest::SHA3_512, &message);
            prop_assert_eq!(&ctx.finish()[..], wanted.as_ref());
        }
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

mod aead {
    use aws_lc_rs::aead::{
        AES_128_GCM, AES_256_GCM, Aad, Algorithm, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey,
    };
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::sample::Index;
    use rind::Error;
    use rind::aead::{AesGcm, ChaCha20Poly1305};

    /// The shape AES-GCM and ChaCha20-Poly1305 share.
    trait Aead {
        fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], inout: &mut [u8], tag: &mut [u8; 16]);
        fn decrypt(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            inout: &mut [u8],
            tag: &[u8],
        ) -> Result<(), Error>;
    }

    impl Aead for AesGcm {
        fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], inout: &mut [u8], tag: &mut [u8; 16]) {
            self.encrypt(nonce, aad, inout, tag).unwrap();
        }

        fn decrypt(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            inout: &mut [u8],
            tag: &[u8],
        ) -> Result<(), Error> {
            self.decrypt(nonce, aad, inout, tag)
        }
    }

    impl Aead for ChaCha20Poly1305 {
        fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], inout: &mut [u8], tag: &mut [u8; 16]) {
            self.encrypt(nonce, aad, inout, tag).unwrap();
        }

        fn decrypt(
            &self,
            nonce: &[u8; 12],
            aad: &[u8],
            inout: &mut [u8],
            tag: &[u8],
        ) -> Result<(), Error> {
            self.decrypt(nonce, aad, inout, tag)
        }
    }

    /// Seals on both sides and compares, then opens aws-lc-rs's output,
    /// first with one bit of its ciphertext or tag flipped if `flip` is set.
    fn check(
        ours: &impl Aead,
        theirs: &'static Algorithm,
        key: &[u8],
        nonce: [u8; 12],
        aad: &[u8],
        msg: &[u8],
        flip: Option<Index>,
    ) -> Result<(), TestCaseError> {
        let mut ours_sealed = msg.to_vec();
        let mut tag = [0u8; 16];
        ours.encrypt(&nonce, aad, &mut ours_sealed, &mut tag);
        ours_sealed.extend_from_slice(&tag);

        let mut theirs_sealed = msg.to_vec();
        LessSafeKey::new(UnboundKey::new(theirs, key).unwrap())
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut theirs_sealed,
            )
            .unwrap();
        prop_assert_eq!(&ours_sealed, &theirs_sealed);

        if let Some(flip) = flip {
            let index = flip.index(theirs_sealed.len());
            theirs_sealed[index] ^= 1;
        }
        let (inout, tag) = theirs_sealed.split_at_mut(msg.len());
        let result = ours.decrypt(&nonce, aad, inout, tag);
        if flip.is_some() {
            prop_assert_eq!(result, Err(Error::DecryptFailed));
        } else {
            prop_assert_eq!(result, Ok(()));
            prop_assert_eq!(&inout[..], msg);
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
            let theirs = if key.len() == 16 { &AES_128_GCM } else { &AES_256_GCM };
            check(&AesGcm::new(&key).unwrap(), theirs, &key, nonce, &aad, &msg, flip)?;
        }

        #[test]
        fn chacha20_poly1305(
            key in any::<[u8; 32]>(),
            nonce in any::<[u8; 12]>(),
            aad in vec(any::<u8>(), 0..100),
            msg in vec(any::<u8>(), 0..1100),
            flip in any::<Option<Index>>(),
        ) {
            let ours = ChaCha20Poly1305::new(key);
            check(&ours, &CHACHA20_POLY1305, &key, nonce, &aad, &msg, flip)?;
        }
    }
}

/// ECDSA and ECDH on one curve: aws-lc-rs and rind accept each other's keys,
/// signatures, and public keys.
macro_rules! ec_crosschecks {
    ($curve:ident, $Curve:ident, $Hash:ident, $ecdh:ident, $signing:ident, $fixed:ident, $asn1:ident) => {
        mod $curve {
            use aws_lc_rs::agreement::{self, $ecdh, EphemeralPrivateKey};
            use aws_lc_rs::rand::SystemRandom;
            use aws_lc_rs::signature::{
                $asn1, $fixed, $signing, EcdsaKeyPair, KeyPair, UnparsedPublicKey,
            };
            use proptest::collection::vec;
            use proptest::prelude::*;
            use rind::hashing::$Hash;
            use rind::signing::ecdsa::{$Curve, SigningKey, VerifyingKey};

            // Each case generates keys on both sides, which is slow under emulation.
            proptest! {
                #![proptest_config(ProptestConfig::with_cases(32))]

                #[test]
                fn ecdsa(message in vec(any::<u8>(), 0..300)) {
                    // aws-lc-rs accepts our key and derives the same public key.
                    let ours = SigningKey::<$Curve>::generate().unwrap();
                    let public = ours.public_key().unwrap().public_key.as_bytes_uncompressed();
                    let theirs_from_ours = EcdsaKeyPair::from_pkcs8(
                        &$signing,
                        ours.to_pkcs8_der(&mut [0; 256]).unwrap(),
                    )
                    .expect("aws-lc-rs rejected a key we generated");
                    prop_assert_eq!(theirs_from_ours.public_key().as_ref(), &public[..]);

                    // It verifies our signatures, in both encodings.
                    let theirs_verifier = |alg| UnparsedPublicKey::new(alg, public);
                    let mut buf = [0; 128];
                    let signature = ours.sign::<$Hash>(&[&message], &mut buf).unwrap();
                    theirs_verifier(&$fixed).verify(&message, signature).unwrap();
                    let signature = ours.sign_asn1::<$Hash>(&[&message], &mut buf).unwrap();
                    theirs_verifier(&$asn1).verify(&message, signature).unwrap();

                    // We verify its signatures, and refuse one over another message.
                    let theirs = EcdsaKeyPair::generate(&$signing).unwrap();
                    let signature = theirs.sign(&SystemRandom::new(), &message).unwrap();
                    let verifier =
                        VerifyingKey::<$Curve>::from_x962_uncompressed(theirs.public_key().as_ref())
                            .unwrap();
                    verifier.verify::<$Hash>(&[&message], signature.as_ref()).unwrap();
                    prop_assert!(
                        verifier.verify::<$Hash>(&[&message, b"!"], signature.as_ref()).is_err()
                    );
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
    P256,
    Sha256,
    ECDH_P256,
    ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_ASN1
);

ec_crosschecks!(
    p384,
    P384,
    Sha384,
    ECDH_P384,
    ECDSA_P384_SHA384_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED,
    ECDSA_P384_SHA384_ASN1
);

mod ed25519 {
    use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
    use proptest::collection::vec;
    use proptest::prelude::*;
    use proptest::sample::Index;
    use rind::signing::eddsa::{Ed25519SigningKey, Ed25519VerifyingKey};

    proptest! {
        #[test]
        fn sign_verify(
            seed in any::<[u8; 32]>(),
            message in vec(any::<u8>(), 0..300),
            flip in any::<Option<Index>>(),
        ) {
            // Signing is deterministic, so one seed gives both sides the same
            // public key and signatures.
            let ours = Ed25519SigningKey::from_bytes(&seed).unwrap();
            let theirs = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
            let public = ours.public_key().as_bytes();
            prop_assert_eq!(&public[..], theirs.public_key().as_ref());
            let mut signature = ours.sign(&message);
            let theirs_signature = theirs.sign(&message);
            prop_assert_eq!(&signature[..], theirs_signature.as_ref());

            // Both verify it, and refuse it with any one bit flipped.
            if let Some(flip) = flip {
                let bit = flip.index(signature.len() * 8);
                signature[bit / 8] ^= 1 << (bit % 8);
            }
            let ours_result = Ed25519VerifyingKey::from_bytes(&public)
                .unwrap()
                .verify(&signature, &message);
            let theirs_result = UnparsedPublicKey::new(&ED25519, public).verify(&message, &signature);
            prop_assert_eq!(ours_result.is_ok(), flip.is_none());
            prop_assert_eq!(theirs_result.is_ok(), flip.is_none());
        }
    }
}

mod rsa {
    use std::sync::LazyLock;

    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::{KeyPair, KeySize};
    use aws_lc_rs::signature::{
        self, KeyPair as _, RsaEncoding, UnparsedPublicKey, VerificationAlgorithm,
    };
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rind::Error;
    use rind::signing::rsa::{SigningKey, VerifyingKey};

    type Sign = for<'a> fn(&SigningKey, &'a mut [u8], &[u8]) -> Result<&'a [u8], Error>;
    type Verify = fn(&VerifyingKey, &[u8], &[u8]) -> Result<(), Error>;

    struct Scheme {
        sign: Sign,
        verify: Verify,
        theirs_sign: &'static dyn RsaEncoding,
        theirs_verify: &'static dyn VerificationAlgorithm,
        /// PKCS#1 v1.5 signatures have no randomness, so both sides must agree.
        deterministic: bool,
    }

    const SCHEMES: [Scheme; 6] = [
        Scheme {
            sign: SigningKey::sign_pkcs1_sha256,
            verify: VerifyingKey::verify_pkcs1_sha256,
            theirs_sign: &signature::RSA_PKCS1_SHA256,
            theirs_verify: &signature::RSA_PKCS1_2048_8192_SHA256,
            deterministic: true,
        },
        Scheme {
            sign: SigningKey::sign_pkcs1_sha384,
            verify: VerifyingKey::verify_pkcs1_sha384,
            theirs_sign: &signature::RSA_PKCS1_SHA384,
            theirs_verify: &signature::RSA_PKCS1_2048_8192_SHA384,
            deterministic: true,
        },
        Scheme {
            sign: SigningKey::sign_pkcs1_sha512,
            verify: VerifyingKey::verify_pkcs1_sha512,
            theirs_sign: &signature::RSA_PKCS1_SHA512,
            theirs_verify: &signature::RSA_PKCS1_2048_8192_SHA512,
            deterministic: true,
        },
        Scheme {
            sign: SigningKey::sign_pss_sha256,
            verify: VerifyingKey::verify_pss_sha256,
            theirs_sign: &signature::RSA_PSS_SHA256,
            theirs_verify: &signature::RSA_PSS_2048_8192_SHA256,
            deterministic: false,
        },
        Scheme {
            sign: SigningKey::sign_pss_sha384,
            verify: VerifyingKey::verify_pss_sha384,
            theirs_sign: &signature::RSA_PSS_SHA384,
            theirs_verify: &signature::RSA_PSS_2048_8192_SHA384,
            deterministic: false,
        },
        Scheme {
            sign: SigningKey::sign_pss_sha512,
            verify: VerifyingKey::verify_pss_sha512,
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
                let ours = SigningKey::from_pkcs8_der(theirs.as_der().unwrap().as_ref()).unwrap();
                let public = theirs.public_key().as_ref();
                let verifier = VerifyingKey::from_pkcs1_der(public).unwrap();
                let rng = SystemRandom::new();
                let len = theirs.public_modulus_len();
                prop_assert_eq!(ours.modulus_len_bytes(), len);

                for scheme in &SCHEMES {
                    // It verifies our signature.
                    let mut buf = vec![0u8; len];
                    let ours_signature = (scheme.sign)(&ours, &mut buf, &message).unwrap();
                    UnparsedPublicKey::new(scheme.theirs_verify, public)
                        .verify(&message, ours_signature)
                        .unwrap();

                    // We verify its signature, and refuse it over another message.
                    let mut theirs_signature = vec![0u8; len];
                    theirs
                        .sign(scheme.theirs_sign, &rng, &message, &mut theirs_signature)
                        .unwrap();
                    if scheme.deterministic {
                        prop_assert_eq!(ours_signature, &theirs_signature[..]);
                    }
                    (scheme.verify)(&verifier, &theirs_signature, &message).unwrap();
                    prop_assert_eq!(
                        (scheme.verify)(&verifier, &theirs_signature, &[&message[..], b"!"].concat()),
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
            SigningKey::from_pkcs8_der(private).err(),
            Some(Error::OutOfRange)
        );
        assert_eq!(
            VerifyingKey::from_pkcs1_der(include_bytes!("../src/high/rsa/rsa2047.pub.der")).err(),
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
