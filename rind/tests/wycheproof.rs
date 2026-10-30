use std::fs::File;
use std::io::BufReader;

use rind::Error;
use rind::aead::{
    AES_128_GCM, AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, RandomNonce,
    RandomizedNonceKey, UnboundKey,
};
use rind::cipher::ChaCha20;
use rind::signature;
use rind::{hkdf, hmac};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct TestFile {
    #[serde(rename(deserialize = "testGroups"))]
    groups: Vec<TestGroup>,
}

#[derive(Deserialize, Debug)]
struct TestGroup {
    #[serde(rename(deserialize = "type"))]
    typ: String,

    #[serde(default, rename(deserialize = "publicKey"))]
    public_key: PublicKey,

    #[serde(default, rename(deserialize = "publicKeyAsn"), with = "hex::serde")]
    public_key_asn: Vec<u8>,

    #[serde(default, rename(deserialize = "privateKeyPkcs8"), with = "hex::serde")]
    private_key_pkcs8: Vec<u8>,

    #[serde(default)]
    sha: String,

    #[serde(default, rename(deserialize = "mgfSha"))]
    mgf_sha: String,

    #[serde(default, rename(deserialize = "sLen"))]
    salt_len: usize,

    tests: Vec<Test>,
}

#[derive(Deserialize, Debug)]
struct Test {
    #[serde(rename(deserialize = "tcId"))]
    #[allow(unused)] // for Debug
    id: usize,
    #[allow(unused)] // for Debug
    comment: Option<String>,
    #[serde(default, with = "hex::serde")]
    key: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    msg: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    tag: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    sig: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    ct: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    aad: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    iv: Vec<u8>,
    #[serde(default, rename(deserialize = "initialCounter"), with = "hex::serde")]
    initial_counter: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    ikm: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    salt: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    info: Vec<u8>,
    #[serde(default)]
    size: usize,
    #[serde(default, with = "hex::serde")]
    okm: Vec<u8>,
    result: ExpectedResult,
}

#[derive(Deserialize, Debug, Default)]
struct PublicKey {
    #[serde(default, with = "hex::serde")]
    uncompressed: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    pk: Vec<u8>,
}

#[derive(Copy, Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
enum ExpectedResult {
    Valid,
    Invalid,
    Acceptable,
}

struct Summary {
    started: usize,
    skipped: usize,
    in_test: bool,
}

impl Summary {
    fn new() -> Self {
        Self {
            started: 0,
            skipped: 0,
            in_test: false,
        }
    }

    fn group(&mut self, group: &TestGroup) {
        println!("  group: {:?}", group.typ);
        self.in_test = false;
    }

    fn start(&mut self, test: &Test) {
        println!("    test {}:", test.id);
        self.started += 1;
        self.in_test = true;
    }

    fn skipped(&mut self, why: &str) {
        if self.in_test {
            println!("      skipped: {why}");
            self.skipped += 1;
            self.in_test = false;
        } else {
            println!("    skipped group: {why}");
        }
    }
}

impl Drop for Summary {
    fn drop(&mut self) {
        let passed = self.started - self.skipped;
        println!(
            "DONE: started {} passed {} skipped {}",
            self.started, passed, self.skipped
        );
        assert_ne!(self.started, self.skipped, "all tests were skipped");
    }
}

#[test]
fn hmac_tests() {
    for (file, algorithm) in [
        ("hmac_sha1_test.json", hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY),
        ("hmac_sha256_test.json", hmac::HMAC_SHA256),
        ("hmac_sha384_test.json", hmac::HMAC_SHA384),
        ("hmac_sha512_test.json", hmac::HMAC_SHA512),
    ] {
        let data_file = File::open(format!("../thirdparty/wycheproof/testvectors_v1/{file}"))
            .unwrap_or_else(|_| panic!("failed to open data file {file}"));

        let reader = BufReader::new(data_file);
        let tests: TestFile = serde_json::from_reader(reader).expect("invalid test JSON");
        let mut summary = Summary::new();

        for group in tests.groups {
            summary.group(&group);
            for test in group.tests {
                summary.start(&test);

                let key = hmac::Key::new(algorithm, &test.key);
                let result = match test.tag.len() == algorithm.tag_len() {
                    true => hmac::verify(&key, &test.msg, &test.tag),
                    false => truncated(hmac::sign(&key, &test.msg).as_ref(), &test.tag),
                };

                match (test.result, result) {
                    (ExpectedResult::Valid, Ok(())) => {}
                    (ExpectedResult::Invalid, Err(Error::BadSignature)) => {}
                    _ => panic!("expected {:?} got {:?}", test.result, result),
                }
            }
        }
    }
}

// rind compares only whole tags; these vectors also truncate them.
fn truncated(tag: &[u8], expected: &[u8]) -> Result<(), Error> {
    match tag.starts_with(expected) {
        true => Ok(()),
        false => Err(Error::BadSignature),
    }
}

#[test]
fn hkdf_tests() {
    fn check(file: &str, algorithm: hkdf::Algorithm) {
        let data_file = File::open(file).expect("failed to open data file");
        let reader = BufReader::new(data_file);
        let tests: TestFile = serde_json::from_reader(reader).expect("invalid test JSON");
        let mut summary = Summary::new();

        for group in tests.groups {
            summary.group(&group);
            for test in group.tests {
                summary.start(&test);

                let mut okm = vec![0u8; test.size];
                let prk = hkdf::Salt::new(algorithm, &test.salt).extract(&test.ikm);
                let info = [test.info.as_slice()];
                let result = prk
                    .expand(&info, okm.len())
                    .and_then(|expanded| expanded.fill(&mut okm));

                match (test.result, result) {
                    (ExpectedResult::Valid, Ok(())) => assert_eq!(okm, test.okm),
                    (ExpectedResult::Invalid, Err(Error::WrongLength)) => {}
                    _ => panic!("expected {:?} got {:?}", test.result, result),
                }
            }
        }
    }

    check(
        "../thirdparty/wycheproof/testvectors_v1/hkdf_sha256_test.json",
        hkdf::HKDF_SHA256,
    );
}

#[test]
fn test_verify_ecdsa() {
    // Each file whose curve, hash, and encoding has a constant.
    for (file, algorithm) in [
        (
            "ecdsa_secp256r1_sha256_p1363_test.json",
            &signature::ECDSA_P256_SHA256_FIXED,
        ),
        (
            "ecdsa_secp256r1_sha256_test.json",
            &signature::ECDSA_P256_SHA256_ASN1,
        ),
        (
            "ecdsa_secp256r1_sha512_test.json",
            &signature::ECDSA_P256_SHA512_ASN1,
        ),
        (
            "ecdsa_secp384r1_sha256_test.json",
            &signature::ECDSA_P384_SHA256_ASN1,
        ),
        (
            "ecdsa_secp384r1_sha384_p1363_test.json",
            &signature::ECDSA_P384_SHA384_FIXED,
        ),
        (
            "ecdsa_secp384r1_sha384_test.json",
            &signature::ECDSA_P384_SHA384_ASN1,
        ),
        (
            "ecdsa_secp384r1_sha512_test.json",
            &signature::ECDSA_P384_SHA512_ASN1,
        ),
    ] {
        let data_file = File::open(format!("../thirdparty/wycheproof/testvectors_v1/{file}"))
            .unwrap_or_else(|_| panic!("failed to open data file {}", file));

        let reader = BufReader::new(data_file);
        let tests: TestFile = serde_json::from_reader(reader).expect("invalid test JSON");
        let mut summary = Summary::new();

        for group in tests.groups {
            summary.group(&group);

            let public_key =
                signature::UnparsedPublicKey::new(algorithm, &group.public_key.uncompressed);

            for test in group.tests {
                summary.start(&test);

                let result = public_key.verify(&test.msg, &test.sig);
                match (test.result, result) {
                    (ExpectedResult::Valid, Ok(())) => {}
                    (
                        ExpectedResult::Invalid,
                        Err(Error::BadSignature) | Err(Error::WrongLength),
                    ) => {}
                    _ => panic!("expected {:?} got {:?}", test.result, result),
                }
            }
        }
    }
}

#[test]
fn test_aes_gcm() {
    let data_file = File::open("../thirdparty/wycheproof/testvectors_v1/aes_gcm_test.json")
        .expect("failed to open data file");

    let reader = BufReader::new(data_file);
    let tests: TestFile = serde_json::from_reader(reader).expect("invalid test JSON");
    let mut summary = Summary::new();

    for group in tests.groups {
        summary.group(&group);

        for test in group.tests {
            summary.start(&test);

            let algorithm = match test.key.len() {
                16 => &AES_128_GCM,
                32 => &AES_256_GCM,
                24 => {
                    summary.skipped("aes-192 not supported");
                    continue;
                }
                len => panic!("unexpected key length {len}"),
            };
            let ctx = LessSafeKey::new(UnboundKey::new(algorithm, &test.key).unwrap());
            let iv: [u8; 12] = match test.iv.try_into() {
                Ok(iv) => iv,
                Err(_) => {
                    summary.skipped("gcm nonces must be 96 bits");
                    continue;
                }
            };
            let nonce = || Nonce::assume_unique_for_key(iv);

            // try decrypt
            let mut msg = test.ct.clone();
            let result = ctx
                .open_in_place_separate_tag(nonce(), Aad::from(&test.aad), &test.tag, &mut msg)
                .map(|_| ());

            match (test.result, &result) {
                (ExpectedResult::Valid, Ok(())) => {
                    assert_eq!(msg, test.msg);
                }
                (ExpectedResult::Invalid, Err(Error::DecryptFailed)) => {}
                _ => panic!("expected {:?} got {:?}", test.result, result.err()),
            }

            // and encrypt
            let mut ct = test.msg.clone();
            let tag = ctx
                .seal_in_place_separate_tag(nonce(), Aad::from(&test.aad), &mut ct)
                .unwrap();

            if test.result == ExpectedResult::Valid {
                assert_eq!(ct, test.ct);
                assert_eq!(tag.as_ref(), &test.tag[..]);
            }
        }
    }
}

#[test]
fn test_aes_gmac() {
    let data_file = File::open("../thirdparty/wycheproof/testvectors_v1/aes_gmac_test.json")
        .expect("failed to open data file");

    let reader = BufReader::new(data_file);
    let tests: TestFile = serde_json::from_reader(reader).expect("invalid test JSON");
    let mut summary = Summary::new();

    for group in tests.groups {
        summary.group(&group);

        for test in group.tests {
            summary.start(&test);

            let algorithm = match test.key.len() {
                16 => &AES_128_GCM,
                32 => &AES_256_GCM,
                24 => {
                    summary.skipped("aes-192 not supported");
                    continue;
                }
                len => panic!("unexpected key length {len}"),
            };
            let ctx = LessSafeKey::new(UnboundKey::new(algorithm, &test.key).unwrap());
            let iv: [u8; 12] = match test.iv.try_into() {
                Ok(iv) => iv,
                Err(_) => {
                    summary.skipped("gcm nonces must be 96 bits");
                    continue;
                }
            };
            let nonce = || Nonce::assume_unique_for_key(iv);

            // try decrypt
            let result = ctx
                .open_in_place_separate_tag(nonce(), Aad::from(&test.msg), &test.tag, &mut [])
                .map(|_| ());

            match (test.result, &result) {
                (ExpectedResult::Valid, Ok(())) => {}
                (ExpectedResult::Invalid, Err(Error::DecryptFailed)) => {}
                _ => panic!("expected {:?} got {:?}", test.result, result.err()),
            }

            // and encrypt
            let tag = ctx
                .seal_in_place_separate_tag(nonce(), Aad::from(&test.msg), &mut [])
                .unwrap();

            if test.result == ExpectedResult::Valid {
                assert_eq!(tag.as_ref(), &test.tag[..]);
            }
        }
    }
}

#[test]
fn test_rsa_pkcs1_verify() {
    for file in &[
        "rsa_signature_2048_sha256_test.json",
        "rsa_signature_2048_sha384_test.json",
        "rsa_signature_2048_sha512_test.json",
        "rsa_signature_3072_sha256_test.json",
        "rsa_signature_3072_sha384_test.json",
        "rsa_signature_3072_sha512_test.json",
        "rsa_signature_4096_sha256_test.json",
        "rsa_signature_4096_sha384_test.json",
        "rsa_signature_4096_sha512_test.json",
        "rsa_signature_8192_sha256_test.json",
        "rsa_signature_8192_sha384_test.json",
        "rsa_signature_8192_sha512_test.json",
    ] {
        let data_file = File::open(format!("../thirdparty/wycheproof/testvectors_v1/{file}"))
            .expect("failed to open data file");
        println!("file: {data_file:?}");

        let reader = BufReader::new(data_file);
        let tests: TestFile = serde_json::from_reader(reader).expect("invalid test JSON");
        let mut summary = Summary::new();

        for group in tests.groups {
            summary.group(&group);

            let algorithm = match group.sha.as_ref() {
                "SHA-256" => &signature::RSA_PKCS1_2048_8192_SHA256,
                "SHA-384" => &signature::RSA_PKCS1_2048_8192_SHA384,
                "SHA-512" => &signature::RSA_PKCS1_2048_8192_SHA512,
                other => panic!("unhandled sha {other:?}"),
            };
            let key = signature::UnparsedPublicKey::new(algorithm, &group.public_key_asn);

            for test in group.tests {
                summary.start(&test);

                let result = key.verify(&test.msg, &test.sig);
                match (test.result, &result) {
                    (ExpectedResult::Valid, Ok(())) => {}
                    (
                        ExpectedResult::Invalid | ExpectedResult::Acceptable,
                        Err(Error::BadSignature),
                    ) => {}
                    _ => panic!("expected {:?} got {:?}", test.result, result.err()),
                }
            }
        }
    }
}

#[test]
fn test_rsa_pkcs1_sign() {
    // The 1024- and 1536-bit files hold only keys below our 2048-bit minimum.
    for file in &[
        "rsa_pkcs1_2048_sig_gen_test.json",
        "rsa_pkcs1_3072_sig_gen_test.json",
        "rsa_pkcs1_4096_sig_gen_test.json",
    ] {
        let data_file = File::open(format!("../thirdparty/wycheproof/testvectors_v1/{file}"))
            .expect("failed to open data file");
        println!("file: {data_file:?}");

        let reader = BufReader::new(data_file);
        let tests: TestFile = serde_json::from_reader(reader).expect("invalid test JSON");
        let mut summary = Summary::new();

        for group in tests.groups {
            summary.group(&group);

            let padding = match group.sha.as_ref() {
                "SHA-256" => &signature::RSA_PKCS1_SHA256,
                "SHA-384" => &signature::RSA_PKCS1_SHA384,
                "SHA-512" => &signature::RSA_PKCS1_SHA512,
                other => {
                    summary.skipped(&format!("pkcs1 signing with {other} not supported"));
                    continue;
                }
            };

            let key = signature::RsaKeyPair::from_pkcs8(&group.private_key_pkcs8).unwrap();

            for test in group.tests {
                summary.start(&test);

                let mut signature = vec![0u8; key.public_modulus_len()];
                key.sign(padding, &test.msg, &mut signature).unwrap();

                // Every case is valid or acceptable (a small public exponent),
                // and PKCS#1 v1.5 signing is deterministic.
                assert_eq!(signature, test.sig);
            }
        }
    }
}

#[test]
fn test_rsa_pss_verify() {
    for file in &[
        "rsa_pss_2048_sha256_mgf1_32_test.json",
        "rsa_pss_2048_sha384_mgf1_48_test.json",
        "rsa_pss_3072_sha256_mgf1_32_test.json",
        "rsa_pss_4096_sha256_mgf1_32_test.json",
        "rsa_pss_4096_sha384_mgf1_48_test.json",
        "rsa_pss_4096_sha512_mgf1_64_test.json",
        "rsa_pss_misc_test.json",
    ] {
        let data_file = File::open(format!("../thirdparty/wycheproof/testvectors_v1/{file}"))
            .expect("failed to open data file");
        println!("file: {data_file:?}");

        let reader = BufReader::new(data_file);
        let tests: TestFile = serde_json::from_reader(reader).expect("invalid test JSON");
        let mut summary = Summary::new();

        for group in tests.groups {
            summary.group(&group);

            let algorithm = match (group.sha.as_ref(), group.mgf_sha.as_ref(), group.salt_len) {
                ("SHA-256", "SHA-256", 32) => &signature::RSA_PSS_2048_8192_SHA256,
                ("SHA-384", "SHA-384", 48) => &signature::RSA_PSS_2048_8192_SHA384,
                ("SHA-512", "SHA-512", 64) => &signature::RSA_PSS_2048_8192_SHA512,
                other => {
                    summary.skipped(&format!(
                        "pss with sha={} mgf={} salt_len={} not supported",
                        other.0, other.1, other.2
                    ));
                    continue;
                }
            };
            let key = signature::UnparsedPublicKey::new(algorithm, &group.public_key_asn);

            for test in group.tests {
                summary.start(&test);

                let result = key.verify(&test.msg, &test.sig);
                match (test.result, &result) {
                    (ExpectedResult::Valid, Ok(())) => {}
                    (
                        ExpectedResult::Invalid | ExpectedResult::Acceptable,
                        Err(Error::BadSignature),
                    ) => {}
                    _ => panic!("expected {:?} got {:?}", test.result, result.err()),
                }
            }
        }
    }
}

#[test]
fn test_ed25519_verify() {
    let data_file = File::open("../thirdparty/wycheproof/testvectors_v1/ed25519_test.json")
        .expect("failed to open data file");
    println!("file: {data_file:?}");

    let reader = BufReader::new(data_file);
    let tests: TestFile = serde_json::from_reader(reader).expect("invalid test JSON");
    let mut summary = Summary::new();

    for group in tests.groups {
        summary.group(&group);

        let key = signature::UnparsedPublicKey::new(&signature::ED25519, &group.public_key.pk);

        for test in group.tests {
            summary.start(&test);

            let result = key.verify(&test.msg, &test.sig);
            match (test.result, result) {
                // "acceptable" cases are small- and mixed-order public keys
                (ExpectedResult::Valid | ExpectedResult::Acceptable, Ok(())) => {}
                (
                    ExpectedResult::Invalid | ExpectedResult::Acceptable,
                    Err(Error::BadSignature),
                ) => {}
                _ => panic!("expected {:?} got {:?}", test.result, result.err()),
            }
        }
    }
}

#[test]
fn test_chacha20poly1305() {
    let data_file =
        File::open("../thirdparty/wycheproof/testvectors_v1/chacha20_poly1305_test.json")
            .expect("failed to open data file");

    let reader = BufReader::new(data_file);
    let tests: TestFile = serde_json::from_reader(reader).expect("invalid test JSON");
    let mut summary = Summary::new();

    for group in tests.groups {
        summary.group(&group);

        for test in group.tests {
            summary.start(&test);

            if test.iv.len() != 12 {
                summary.skipped("chacha20_poly1305 nonce must be 96 bit");
                continue;
            }

            let ctx = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &test.key).unwrap());
            let iv: [u8; 12] = test.iv.try_into().unwrap();
            let nonce = || Nonce::assume_unique_for_key(iv);

            // try decrypt
            let mut msg = test.ct.clone();
            let result = ctx
                .open_in_place_separate_tag(nonce(), Aad::from(&test.aad), &test.tag, &mut msg)
                .map(|_| ());

            match (test.result, &result) {
                (ExpectedResult::Valid, Ok(())) => {
                    assert_eq!(msg, test.msg);
                }
                (ExpectedResult::Invalid, Err(Error::DecryptFailed)) => {}
                _ => panic!("expected {:?} got {:?}", test.result, result.err()),
            }

            // and encrypt
            let mut ct = test.msg.clone();
            let tag = ctx
                .seal_in_place_separate_tag(nonce(), Aad::from(&test.aad), &mut ct)
                .unwrap();

            if test.result == ExpectedResult::Valid {
                assert_eq!(ct, test.ct);
                assert_eq!(tag.as_ref(), &test.tag[..]);
            }
        }
    }
}

#[test]
fn test_chacha20() {
    let data_file =
        File::open("../thirdparty/wycheproof/testvectors_v1/chacha20_counter_test.json")
            .expect("failed to open data file");

    let reader = BufReader::new(data_file);
    let tests: TestFile = serde_json::from_reader(reader).expect("invalid test JSON");
    let mut summary = Summary::new();

    for group in tests.groups {
        summary.group(&group);

        for test in group.tests {
            summary.start(&test);

            if test.iv.len() != 12 {
                summary.skipped("only the 96-bit nonce variant is exposed");
                continue;
            }

            let ctx = ChaCha20::new(test.key.try_into().unwrap());
            let counter = u32::from_le_bytes(test.initial_counter.try_into().unwrap());

            let mut buf = test.msg.clone();
            let result = ctx.apply_keystream(&test.iv.try_into().unwrap(), counter, &mut buf);

            match (test.result, result) {
                (ExpectedResult::Valid, Ok(())) => assert_eq!(buf, test.ct),
                (ExpectedResult::Invalid, Err(Error::WrongLength)) => assert_eq!(buf, test.msg),
                (_, result) => panic!("expected {:?} got {:?}", test.result, result),
            }
        }
    }
}

#[test]
fn test_xchacha20poly1305() {
    let data_file =
        File::open("../thirdparty/wycheproof/testvectors_v1/xchacha20_poly1305_test.json")
            .expect("failed to open data file");

    let reader = BufReader::new(data_file);
    let tests: TestFile = serde_json::from_reader(reader).expect("invalid test JSON");
    let mut summary = Summary::new();

    for group in tests.groups {
        summary.group(&group);

        for test in group.tests {
            summary.start(&test);

            if test.iv.len() != 24 {
                summary.skipped("xchacha20_poly1305 nonce must be 192 bit");
                continue;
            }

            let ctx = RandomizedNonceKey::new(&test.key.try_into().unwrap());
            let iv: [u8; 24] = test.iv.try_into().unwrap();

            // try decrypt
            let mut sealed = [&test.ct[..], &test.tag[..]].concat();
            let result = ctx
                .open_in_place(RandomNonce::from(iv), Aad::from(&test.aad), &mut sealed)
                .map(|msg| msg.to_vec());

            match (test.result, &result) {
                (ExpectedResult::Valid, Ok(msg)) => {
                    assert_eq!(msg, &test.msg);
                }
                (ExpectedResult::Invalid, Err(Error::DecryptFailed)) => {}
                _ => panic!("expected {:?} got {:?}", test.result, result.err()),
            }

            // Sealing picks its own nonce, so check it round trips; the unit
            // tests check a sealed vector.
            let mut sealed = test.msg.clone();
            let nonce = ctx
                .seal_in_place_append_tag(Aad::from(&test.aad), &mut sealed)
                .unwrap();
            assert_eq!(
                ctx.open_in_place(nonce, Aad::from(&test.aad), &mut sealed)
                    .unwrap(),
                &test.msg[..]
            );
        }
    }
}
