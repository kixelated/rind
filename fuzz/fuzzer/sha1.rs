#![no_main]

use aws_lc_rs::{digest, hmac};
use libfuzzer_sys::{arbitrary, arbitrary::Arbitrary, fuzz_target};

fuzz_target!(|op: Operation| {
    match op {
        Operation::Sha1(steps) => {
            let mut left = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
            let mut right = rind::digest::Context::new(&rind::digest::SHA1_FOR_LEGACY_USE_ONLY);

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
        Operation::HmacSha1 { key, steps } => {
            let mut left =
                hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &key));
            let mut right = rind::hmac::Context::with_key(&rind::hmac::Key::new(
                rind::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
                &key,
            ));

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
            let right = right.sign();
            assert_eq!(left.as_ref(), right.as_ref());
        }
    }
});

#[derive(Arbitrary, Debug)]
enum Operation {
    Sha1(Vec<Step>),
    HmacSha1 { key: Vec<u8>, steps: Vec<Step> },
}

#[derive(Arbitrary, Debug)]
enum Step {
    Clone,
    Input(Vec<u8>),
}
