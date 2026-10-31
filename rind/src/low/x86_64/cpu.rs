// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

use core::arch::x86_64::*;

pub(crate) fn enter_cpu_state() -> u32 {
    // DOIT: "Data Operand Independent Timing" -- turning this on
    // is under kernel control, because MSRs are privileged.
    // <https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/data-operand-independent-timing-isa-guidance.html>
    0
}

/// Nothing to restore, since `enter_cpu_state` changed nothing. Vector
/// registers hold scratch, not owned secrets, so like aws-lc we leave them.
pub(crate) fn leave_cpu_state(_old: u32) {}

/// Effectively memset(ptr, 0, len), but not visible to optimiser
///
/// # Safety
/// The caller must ensure that there are `len` bytes writable at `ptr`,
/// and that the pointed-to object has a safe all-zeroes representation.
/// (see `low::generic::zeroise` which expresses this within the type system).
pub(in crate::low) fn zero_bytes(ptr: *mut u8, len: usize) {
    // SAFETY: this crate requires the `avx` cpu feature
    unsafe { _zero_bytes(ptr, len) }
}

#[target_feature(enable = "avx,avx2")]
unsafe fn _zero_bytes(ptr: *mut u8, len: usize) {
    // SAFETY: writes to `len` bytes at `ptr`, which the caller guarantees
    unsafe {
        core::arch::asm!(
            "       vpxor   {zero}, {zero}, {zero}",
            // by-32 loop
            "   2:  cmp {len}, 32",
            "       jl  3f",
            "       vmovdqu [{ptr}], {zero}",
            "       add {ptr}, 32",
            "       sub {len}, 32",
            "       jmp 2b",
            // by-1 loop
            "   3:  sub {len}, 1",
            "       jl  4f",
            "       mov byte ptr [{ptr}], 0",
            "       add {ptr}, 1",
            "       jmp 3b",
            "   4:  ",

            ptr = inout(reg) ptr => _,
            len = inout(reg) len => _,

            // clobbers
            zero = out(ymm_reg) _,
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
    let mut acc = 0u8;
    // SAFETY: reads `len` bytes from `a` and `b`, which the caller guarantees
    unsafe {
        core::arch::asm!(
            "   2: cmp {len}, 0",
            "      je  3f",
            "      mov {tmp}, [{a}]",
            "      xor {tmp}, [{b}]",
            "      or  {acc}, {tmp}",
            "      add {a}, 1",
            "      add {b}, 1",
            "      sub {len}, 1",
            "      jmp 2b",
            "   3:  ",
            a = inout(reg) a => _,
            b = inout(reg) b => _,
            len = inout(reg) len => _,
            tmp = inout(reg_byte) 0u8 => _,
            acc = inout(reg_byte) acc,
        );
    }
    acc
}

/// This macro interdicts is_x86_feature_detected to
/// allow testability.
macro_rules! have_cpu_feature {
    ("aes") => {
        crate::low::x86_64::cpu::test_toggle("aes", is_x86_feature_detected!("aes"))
    };
    ("vaes") => {
        crate::low::x86_64::cpu::test_toggle("vaes", is_x86_feature_detected!("vaes"))
    };
    ("pclmulqdq") => {
        crate::low::x86_64::cpu::test_toggle("pclmulqdq", is_x86_feature_detected!("pclmulqdq"))
    };
    ("vpclmulqdq") => {
        crate::low::x86_64::cpu::test_toggle("vpclmulqdq", is_x86_feature_detected!("vpclmulqdq"))
    };
    ("bmi2") => {
        crate::low::x86_64::cpu::test_toggle("bmi2", is_x86_feature_detected!("bmi2"))
    };
    ("adx") => {
        crate::low::x86_64::cpu::test_toggle("adx", is_x86_feature_detected!("adx"))
    };
    ("popcnt") => {
        crate::low::x86_64::cpu::test_toggle("popcnt", is_x86_feature_detected!("popcnt"))
    };
    ("ssse3") => {
        crate::low::x86_64::cpu::test_toggle("ssse3", is_x86_feature_detected!("ssse3"))
    };
    ("avx") => {
        crate::low::x86_64::cpu::test_toggle("avx", is_x86_feature_detected!("avx"))
    };
    ("avx2") => {
        crate::low::x86_64::cpu::test_toggle("avx2", is_x86_feature_detected!("avx2"))
    };
    ("avx512f") => {
        crate::low::x86_64::cpu::test_toggle("avx512f", is_x86_feature_detected!("avx512f"))
    };
    ("avx512bw") => {
        crate::low::x86_64::cpu::test_toggle("avx512bw", is_x86_feature_detected!("avx512bw"))
    };
    ("avx512vl") => {
        crate::low::x86_64::cpu::test_toggle("avx512vl", is_x86_feature_detected!("avx512vl"))
    };
    ("avx512vbmi") => {
        crate::low::x86_64::cpu::test_toggle("avx512vbmi", is_x86_feature_detected!("avx512vbmi"))
    };
    ("avx512vbmi2") => {
        crate::low::x86_64::cpu::test_toggle("avx512vbmi2", is_x86_feature_detected!("avx512vbmi2"))
    };
    ("sha") => {
        crate::low::x86_64::cpu::test_toggle("sha", is_x86_feature_detected!("sha"))
    };
}

/// Token type reflecting the check for CPU features needed for AVX512-AES-GCM
///
/// A value of this type is proof that the CPU dynamic feature check has happened.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HaveAvx512ForAesGcm(());

impl HaveAvx512ForAesGcm {
    pub(crate) fn check() -> Option<Self> {
        match have_cpu_feature!("avx512f")
            && have_cpu_feature!("avx512bw")
            && have_cpu_feature!("avx512vl")
            && have_cpu_feature!("vpclmulqdq")
            && have_cpu_feature!("vaes")
        {
            true => Some(Self(())),
            false => None,
        }
    }
}

/// Token type reflecting the check for CPU features needed for AVX512-ML-KEM
///
/// A value of this type is proof that the CPU dynamic feature check has happened.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HaveAvx512ForMlKem(());

impl HaveAvx512ForMlKem {
    pub(crate) fn check() -> Option<Self> {
        match have_cpu_feature!("avx512f")
            && have_cpu_feature!("avx512bw")
            && have_cpu_feature!("avx512vbmi")
            && have_cpu_feature!("avx512vbmi2")
        {
            true => Some(Self(())),
            false => None,
        }
    }
}

/// Token type reflecting the check for CPU features needed for SHA1 using SHA-NI
///
/// A value of this type is proof that the CPU dynamic feature check has happened.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HaveSha1(());

impl HaveSha1 {
    pub(crate) fn check() -> Option<Self> {
        match have_cpu_feature!("sha") {
            true => Some(Self(())),
            false => None,
        }
    }
}

/// Token type reflecting the check for CPU features needed for SHA256 using SHA-NI
///
/// A value of this type is proof that the CPU dynamic feature check has happened.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HaveSha256(());

impl HaveSha256 {
    pub(crate) fn check() -> Option<Self> {
        match have_cpu_feature!("sha") {
            true => Some(Self(())),
            false => None,
        }
    }
}

/// Whether the CPU is Intel's, for code that is fastest on one vendor's cores.
///
/// Reads the vendor once, then answers from the cached result: `cpuid` is
/// slow, and traps to the hypervisor in a VM.
pub(crate) fn is_intel() -> bool {
    const UNKNOWN: u8 = 0;
    const OTHER: u8 = 1;
    const INTEL: u8 = 2;
    static VENDOR: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(UNKNOWN);

    let vendor = match VENDOR.load(core::sync::atomic::Ordering::Relaxed) {
        UNKNOWN => {
            // "GenuineIntel", spread over ebx, edx, and ecx.
            let id = __cpuid(0);
            let intel = (id.ebx, id.edx, id.ecx) == (0x756e_6547, 0x4965_6e69, 0x6c65_746e);
            let vendor = if test_toggle("intel", intel) {
                INTEL
            } else {
                OTHER
            };
            VENDOR.store(vendor, core::sync::atomic::Ordering::Relaxed);
            vendor
        }
        vendor => vendor,
    };
    vendor == INTEL
}

#[cfg(not(debug_assertions))]
pub(crate) fn test_toggle(_id: &str, detected: bool) -> bool {
    detected
}

#[cfg(debug_assertions)]
pub(crate) fn test_toggle(id: &str, detected: bool) -> bool {
    if std::env::var(format!("RIND_CPU_DISABLE_{id}")).is_ok() {
        println!("DEBUG: denying cpuid {id:?}");
        false
    } else {
        detected
    }
}

/// Returns the first CPU feature we require unconditionally that this CPU lacks.
///
/// This limits the library to x86_64 processors released after approx 2014.
/// Ordered oldest first, so the name points at the real gap. `sse3` and
/// `sse4.1` are implied by `avx` in rustc's feature model.
pub(crate) fn missing_cpu_feature() -> Option<&'static str> {
    // assorted intrinsic code
    if !have_cpu_feature!("ssse3") {
        return Some("ssse3");
    }
    // ML-KEM rejection sampling
    if !have_cpu_feature!("popcnt") {
        return Some("popcnt");
    }
    // our aes-gcm
    if !have_cpu_feature!("aes") {
        return Some("aes");
    }
    if !have_cpu_feature!("pclmulqdq") {
        return Some("pclmulqdq");
    }
    // assorted intrinsic code
    if !have_cpu_feature!("avx") {
        return Some("avx");
    }
    if !have_cpu_feature!("avx2") {
        return Some("avx2");
    }
    // s2n-bignum non _alt versions: mulx
    if !have_cpu_feature!("bmi2") {
        return Some("bmi2");
    }
    // s2n-bignum non _alt versions: adcx and adox.
    // see this valgrind bug: https://bugs.kde.org/show_bug.cgi?id=494162
    // (build with VALGRIND_BUG_494162 set to run under valgrind)
    if !have_cpu_feature!("adx") && option_env!("VALGRIND_BUG_494162").is_none() {
        return Some("adx");
    }
    None
}

// --- Safe abstractions over common intrinsics operations ---

/// Prefetch both `table` and `table[stride]`
///
/// `table[stride]` is not range checked, as prefetching doesn't need a valid
/// pointer.
#[target_feature(enable = "sse")]
#[inline]
pub(crate) fn prefetch<T>(table: &[T], stride: usize) {
    // SAFETY: prefetches do not fault and are not architecturally visible
    unsafe {
        _mm_prefetch(table.as_ptr().cast(), _MM_HINT_T0);
        _mm_prefetch(table.as_ptr().add(stride).cast(), _MM_HINT_T0);
    }
}
