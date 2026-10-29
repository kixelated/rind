//! Constant-time checks for each secret path, run under valgrind by
//! `admin/ctgrind`.
//!
//! Secret inputs are marked undefined, so memcheck flags any branch or memory
//! index that depends on them. Outputs that are public by design are marked
//! defined before the test checks them. DTLS runs on `rind-dimpl`, and its
//! certificate key on `rind-rcgen`, whose own ctgrind tests cover them.

use crabgrind::memcheck::{self, MemState};
use crabgrind::valgrind::{self, RunningMode};
use str0m_proto::crypto::{AeadAes128Gcm, Aes128CmSha1_80, CryptoProvider};

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

fn providers() -> (CryptoProvider, CryptoProvider) {
    (
        rind_str0m::default_provider(),
        str0m_aws_lc_rs::default_provider(),
    )
}

#[test]
fn key_derivation() {
    let (rind, aws) = providers();
    let input = [0x24; 16];
    let (key128, key256) = ([0x42; 16], [0x42; 32]);
    let (mut ours, mut theirs) = ([0u8; 32], [0u8; 32]);

    aws.srtp_provider
        .srtp_aes_128_ecb_round(&key128, &input, &mut theirs);
    secret(&key128);
    rind.srtp_provider
        .srtp_aes_128_ecb_round(&key128, &input, &mut ours);
    public(&ours);
    assert_eq!(ours[..16], theirs[..16]);

    aws.srtp_provider
        .srtp_aes_256_ecb_round(&key256, &input, &mut theirs);
    secret(&key256);
    rind.srtp_provider
        .srtp_aes_256_ecb_round(&key256, &input, &mut ours);
    public(&ours);
    assert_eq!(ours[..16], theirs[..16]);
}

#[test]
fn aes_cm() {
    let (rind, aws) = providers();
    let key = [0x42; 16];
    let iv = Aes128CmSha1_80::rtp_iv([0x24; 14], 0x1234_5678, 7);
    let input = [0x11; 100];

    let mut expected = [0u8; 100 + 16];
    aws.srtp_provider
        .aes_128_cm_sha1_80()
        .create_cipher(key, true)
        .encrypt(&iv, &input, &mut expected)
        .unwrap();

    secret(&key);
    let srtp = rind.srtp_provider.aes_128_cm_sha1_80();
    let mut ciphertext = [0u8; 100];
    srtp.create_cipher(key, true)
        .encrypt(&iv, &input, &mut ciphertext)
        .unwrap();
    public(&ciphertext);
    assert_eq!(ciphertext, expected[..100]);

    let mut plaintext = [0u8; 100];
    srtp.create_cipher(key, false)
        .decrypt(&iv, &ciphertext, &mut plaintext)
        .unwrap();
    public(&plaintext);
    assert_eq!(plaintext, input);
}

#[test]
fn aes_gcm() {
    let (rind, aws) = providers();
    let iv = AeadAes128Gcm::rtp_iv([0x24; 12], 0x1234_5678, 7, 7);
    let aad = [0x33; 12];
    let input = [0x11; 100];

    let key = [0x42; 16];
    let mut expected = [0u8; 100 + 16];
    aws.srtp_provider
        .aead_aes_128_gcm()
        .create_cipher(key, true)
        .encrypt(&iv, &aad, &input, &mut expected)
        .unwrap();
    secret(&key);
    let srtp = rind.srtp_provider.aead_aes_128_gcm();
    let mut sealed = [0u8; 100 + 16];
    srtp.create_cipher(key, true)
        .encrypt(&iv, &aad, &input, &mut sealed)
        .unwrap();
    public(&sealed);
    assert_eq!(sealed, expected);
    let mut plaintext = [0u8; 100];
    let len = srtp
        .create_cipher(key, false)
        .decrypt(&iv, &[&aad], &sealed, &mut plaintext)
        .unwrap();
    public(&plaintext);
    assert_eq!(plaintext[..len], input);

    let key = [0x42; 32];
    aws.srtp_provider
        .aead_aes_256_gcm()
        .create_cipher(key, true)
        .encrypt(&iv, &aad, &input, &mut expected)
        .unwrap();
    secret(&key);
    let srtp = rind.srtp_provider.aead_aes_256_gcm();
    srtp.create_cipher(key, true)
        .encrypt(&iv, &aad, &input, &mut sealed)
        .unwrap();
    public(&sealed);
    assert_eq!(sealed, expected);
    let len = srtp
        .create_cipher(key, false)
        .decrypt(&iv, &[&aad], &sealed, &mut plaintext)
        .unwrap();
    public(&plaintext);
    assert_eq!(plaintext[..len], input);
}

#[test]
fn stun_hmac() {
    let (rind, aws) = providers();
    let key = *b"a STUN password";
    let expected = aws
        .sha1_hmac_provider
        .sha1_hmac(&key, &[b"binding request"]);

    secret(&key);
    let tag = rind
        .sha1_hmac_provider
        .sha1_hmac(&key, &[b"binding ", b"request"]);
    public(&tag);
    assert_eq!(tag, expected);
}
