#![no_main]

use aws_lc_rs::{digest, hmac};
use libfuzzer_sys::{arbitrary, arbitrary::Arbitrary, fuzz_target};
use rind::hashing;

fuzz_target!(|op: Operation| {
    match op {
        Operation::Sha256(steps) => {
            let mut left = digest::Context::new(&digest::SHA256);
            let mut right = rind::digest::Context::new(&rind::digest::SHA256);

            for s in steps {
                match s {
                    Step::Clone => {
                        left = left.clone();
                        right = right.clone();
                    }
                    Step::Input(d) => {
                        left.update(&d);
                        right.update(&d);
                    }
                }
            }

            let left = left.finish();
            let right = right.finish();
            assert_eq!(left.as_ref(), right.as_ref());
        }
        Operation::Sha384(steps) => {
            let mut left = digest::Context::new(&digest::SHA384);
            let mut right = rind::digest::Context::new(&rind::digest::SHA384);

            for s in steps {
                match s {
                    Step::Clone => {
                        left = left.clone();
                        right = right.clone();
                    }
                    Step::Input(d) => {
                        left.update(&d);
                        right.update(&d);
                    }
                }
            }

            let left = left.finish();
            let right = right.finish();
            assert_eq!(left.as_ref(), right.as_ref());
        }
        Operation::Sha512(steps) => {
            let mut left = digest::Context::new(&digest::SHA512);
            let mut right = rind::digest::Context::new(&rind::digest::SHA512);

            for s in steps {
                match s {
                    Step::Clone => {
                        left = left.clone();
                        right = right.clone();
                    }
                    Step::Input(d) => {
                        left.update(&d);
                        right.update(&d);
                    }
                }
            }

            let left = left.finish();
            let right = right.finish();
            assert_eq!(left.as_ref(), right.as_ref());
        }
        Operation::HmacSha256 { key, steps } => {
            let mut left = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, &key));
            let mut right = hashing::hmac::Hmac::<hashing::Sha256>::new(key);

            for s in steps {
                match s {
                    Step::Clone => {
                        left = left.clone();
                        right = right.clone();
                    }
                    Step::Input(d) => {
                        left.update(&d);
                        right.update(&d);
                    }
                }
            }

            let left = left.sign();
            let right = right.finish();
            assert_eq!(left.as_ref(), right.as_ref());
        }
        Operation::HmacSha384 { key, steps } => {
            let mut left = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA384, &key));
            let mut right = hashing::hmac::Hmac::<hashing::Sha384>::new(key);

            for s in steps {
                match s {
                    Step::Clone => {
                        left = left.clone();
                        right = right.clone();
                    }
                    Step::Input(d) => {
                        left.update(&d);
                        right.update(&d);
                    }
                }
            }

            let left = left.sign();
            let right = right.finish();
            assert_eq!(left.as_ref(), right.as_ref());
        }
        Operation::HmacSha512 { key, steps } => {
            let mut left = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA512, &key));
            let mut right = hashing::hmac::Hmac::<hashing::Sha512>::new(key);

            for s in steps {
                match s {
                    Step::Clone => {
                        left = left.clone();
                        right = right.clone();
                    }
                    Step::Input(d) => {
                        left.update(&d);
                        right.update(&d);
                    }
                }
            }

            let left = left.sign();
            let right = right.finish();
            assert_eq!(left.as_ref(), right.as_ref());
        }
    }
});

#[derive(Arbitrary, Debug)]
enum Operation {
    Sha256(Vec<Step>),
    Sha384(Vec<Step>),
    Sha512(Vec<Step>),
    HmacSha256 { key: Vec<u8>, steps: Vec<Step> },
    HmacSha384 { key: Vec<u8>, steps: Vec<Step> },
    HmacSha512 { key: Vec<u8>, steps: Vec<Step> },
}

#[derive(Arbitrary, Debug)]
enum Step {
    Clone,
    Input(Vec<u8>),
}
