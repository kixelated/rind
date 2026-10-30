// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

/// The portable backend needs nothing beyond the base instruction set.
pub(crate) fn missing_cpu_feature() -> Option<&'static str> {
    None
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
