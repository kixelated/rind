// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

/// A CPU feature rind requires that this CPU lacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MissingFeature(&'static str);

impl fmt::Display for MissingFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rind requires {} CPU support on {}",
            self.0,
            std::env::consts::ARCH
        )
    }
}

impl core::error::Error for MissingFeature {}

/// Checks that this CPU has every feature rind requires, naming the first one missing.
pub fn check() -> Result<(), MissingFeature> {
    match super::missing_cpu_feature() {
        Some(feature) => Err(MissingFeature(feature)),
        None => Ok(()),
    }
}

/// Panics with [`check`]'s error rather than run instructions this CPU lacks.
pub(crate) fn verify_cpu_features() {
    // Every operation calls this, and a single-block one costs little more
    // than testing each feature, so a pass is remembered.
    static VERIFIED: AtomicBool = AtomicBool::new(false);

    #[cold]
    fn verify() {
        if let Err(missing) = check() {
            panic!("{missing}");
        }
        VERIFIED.store(true, Ordering::Relaxed);
    }

    if !VERIFIED.load(Ordering::Relaxed) {
        verify();
    }
}
