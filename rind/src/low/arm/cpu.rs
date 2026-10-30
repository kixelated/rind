// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::sync::atomic::{AtomicU8, Ordering};

/// The portable code needs nothing beyond the base instruction set, so the
/// crypto extension speeds things up where present but is never required.
pub(crate) fn missing_cpu_feature() -> Option<&'static str> {
    None
}

/// Proof that the CPU has the ARMv8 Crypto Extension in AArch32: NEON, AES,
/// PMULL, SHA-1, and SHA-256.
///
/// ARMv8 cores ship the extension as one unit, so one token keeps the paths
/// to two: all of it, or the portable code.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HaveCryptoExt(());

impl HaveCryptoExt {
    /// Detects the extension once, then answers from the cached result.
    pub(crate) fn check() -> Option<Self> {
        const UNKNOWN: u8 = 0;
        const ABSENT: u8 = 1;
        const PRESENT: u8 = 2;
        static DETECTED: AtomicU8 = AtomicU8::new(UNKNOWN);

        let detected = match DETECTED.load(Ordering::Relaxed) {
            UNKNOWN => {
                let detected = if detect() { PRESENT } else { ABSENT };
                DETECTED.store(detected, Ordering::Relaxed);
                detected
            }
            detected => detected,
        };
        (detected == PRESENT).then_some(Self(()))
    }
}

/// Reads the features the kernel reports to 32-bit processes, as aws-lc does
/// (`crypto/fipsmodule/cpucap/cpu_arm_linux.c`). A kernel that omits
/// `AT_HWCAP2` gets the portable code: aws-lc parses `/proc/cpuinfo` for those
/// early ARMv8 Android kernels instead, which rind does not.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn detect() -> bool {
    // Bits from the kernel's arch/arm/include/uapi/asm/hwcap.h.
    const HWCAP_NEON: libc::c_ulong = 1 << 12;
    const HWCAP2_AES: libc::c_ulong = 1 << 0;
    const HWCAP2_PMULL: libc::c_ulong = 1 << 1;
    const HWCAP2_SHA1: libc::c_ulong = 1 << 2;
    const HWCAP2_SHA2: libc::c_ulong = 1 << 3;

    // SAFETY: `getauxval` only reads the process's auxiliary vector, and
    // returns 0 for an entry it lacks.
    let (hwcap, hwcap2) = unsafe {
        (
            libc::getauxval(libc::AT_HWCAP),
            libc::getauxval(libc::AT_HWCAP2),
        )
    };
    test_toggle("neon", hwcap & HWCAP_NEON != 0)
        && test_toggle("aes", hwcap2 & HWCAP2_AES != 0)
        && test_toggle("pmull", hwcap2 & HWCAP2_PMULL != 0)
        && test_toggle("sha1", hwcap2 & HWCAP2_SHA1 != 0)
        && test_toggle("sha2", hwcap2 & HWCAP2_SHA2 != 0)
}

/// Other operating systems report the extension differently, so they get the
/// portable code.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn detect() -> bool {
    false
}

#[cfg(all(not(debug_assertions), any(target_os = "linux", target_os = "android")))]
fn test_toggle(_id: &str, detected: bool) -> bool {
    detected
}

/// Lets a debug build deny a feature with `RIND_CPU_DISABLE_<id>`, as on
/// x86_64, so a CPU with the extension also tests the portable code.
#[cfg(all(debug_assertions, any(target_os = "linux", target_os = "android")))]
fn test_toggle(id: &str, detected: bool) -> bool {
    if std::env::var(format!("RIND_CPU_DISABLE_{id}")).is_ok() {
        println!("DEBUG: denying cpuid {id:?}");
        false
    } else {
        detected
    }
}

/// armv7 has no data-independent timing mode to enable.
pub(crate) fn enter_cpu_state() -> u32 {
    0
}

/// Nothing to restore, since `enter_cpu_state` changed nothing.
pub(crate) fn leave_cpu_state(_old: u32) {}

/// Effectively memset(ptr, 0, len), but not visible to optimiser
///
/// # Safety:
/// There must be `len` writable bytes at `ptr`; with no alignment
/// requirement.
pub(in crate::low) fn zero_bytes(ptr: *mut u8, len: usize) {
    // SAFETY: inline assembly. all written registers are listed as clobbers.
    unsafe {
        core::arch::asm!(
            "   2:  subs {len}, {len}, #1",
            "       blo 3f",
            "       strb {zero}, [{ptr}], #1",
            "       b 2b",
            "   3:",

            ptr = inout(reg) ptr => _,
            len = inout(reg) len => _,
            zero = in(reg) 0u32,
            options(nostack),
        )
    }
}

/// Effectively memcmp(a, b, len), but guaranteed to visit every element
/// of a and b.
///
/// The return value does not follow memcmp semantics: it is zero if
/// `a == b`, otherwise it is non-zero.
///
/// # Safety
/// The caller must ensure that there are `len` bytes readable at `a` and `b`,
pub(in crate::low) unsafe fn ct_compare_bytes(a: *const u8, b: *const u8, len: usize) -> u8 {
    let mut acc = 0u32;
    // SAFETY: inline assembly. all written registers are listed as clobbers.
    unsafe {
        core::arch::asm!(
            "   2:  subs {len}, {len}, #1",
            "       blo 3f",
            "       ldrb {tmpa}, [{a}], #1",
            "       ldrb {tmpb}, [{b}], #1",
            "       eor {tmpa}, {tmpa}, {tmpb}",
            "       orr {acc}, {acc}, {tmpa}",
            "       b 2b",
            "   3:",

            a = inout(reg) a => _,
            b = inout(reg) b => _,
            len = inout(reg) len => _,
            acc = inout(reg) acc,
            tmpa = out(reg) _,
            tmpb = out(reg) _,
            options(readonly, nostack),
        )
    }
    acc as u8
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    // CI runs the armv7 suite on a CPU model with the extension and one
    // without, and names which, so neither run silently tests only one path.
    #[test]
    fn detects_the_expected_cpu() {
        if let Some(expected) = std::env::var_os("RIND_TEST_ARM_CRYPTO_EXT") {
            assert_eq!(HaveCryptoExt::check().is_some(), expected == "1");
        }
    }
}
