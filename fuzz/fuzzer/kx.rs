#![no_main]

use aws_lc_rs::agreement as theirs;
use libfuzzer_sys::{arbitrary, arbitrary::Arbitrary, fuzz_target};
use rind::agreement as ours;

fuzz_target!(|op: Operation| {
    match op {
        Operation::X25519 { scalar, peer } => {
            check(&ours::X25519, &theirs::X25519, &scalar, &peer);
        }
        Operation::P256 { scalar, peer } => {
            check(&ours::ECDH_P256, &theirs::ECDH_P256, &scalar, &peer);
        }
        Operation::P384 { scalar, peer } => {
            check(&ours::ECDH_P384, &theirs::ECDH_P384, &scalar, &peer);
        }
    }
});

// rind only has ephemeral keys, so the fuzzer picks aws-lc-rs's scalar and
// the peer key, and rind's scalar is random.
fn check(
    ours_algorithm: &'static ours::Algorithm,
    theirs_algorithm: &'static theirs::Algorithm,
    scalar: &[u8],
    peer: &[u8],
) {
    // Both accept or refuse the same peer key, whatever their own scalar.
    let ours_result = ours::agree_ephemeral(
        ours::EphemeralPrivateKey::generate(ours_algorithm).unwrap(),
        &ours::UnparsedPublicKey::new(ours_algorithm, peer),
    );
    let theirs_result = theirs::agree_ephemeral(
        theirs::EphemeralPrivateKey::generate(
            theirs_algorithm,
            &aws_lc_rs::rand::SystemRandom::new(),
        )
        .unwrap(),
        theirs::UnparsedPublicKey::new(theirs_algorithm, peer),
        (),
        |_| Ok(()),
    );
    assert_eq!(ours_result.is_ok(), theirs_result.is_ok());

    // Agreeing with aws-lc-rs's key for the fuzzed scalar checks our base
    // and variable-base multiplication against its.
    let Ok(theirs_key) = theirs::PrivateKey::from_private_key(theirs_algorithm, scalar) else {
        return;
    };
    let ours_key = ours::EphemeralPrivateKey::generate(ours_algorithm).unwrap();
    let ours_public = ours_key.compute_public_key();
    let theirs_public = theirs_key.compute_public_key().unwrap();

    let ours_secret = ours::agree_ephemeral(
        ours_key,
        &ours::UnparsedPublicKey::new(ours_algorithm, theirs_public.as_ref()),
    )
    .unwrap();
    let theirs_secret = theirs::agree(
        &theirs_key,
        theirs::UnparsedPublicKey::new(theirs_algorithm, ours_public.as_ref()),
        (),
        |secret| Ok(secret.to_vec()),
    )
    .unwrap();
    assert_eq!(ours_secret.as_ref(), &theirs_secret[..]);
}

#[derive(Arbitrary, Debug)]
enum Operation {
    X25519 { scalar: [u8; 32], peer: [u8; 32] },
    P256 { scalar: [u8; 32], peer: [u8; 65] },
    P384 { scalar: [u8; 48], peer: [u8; 97] },
}
