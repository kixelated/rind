// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! AES-GCM on VAES and VPCLMULQDQ, with BoringSSL's `aes-gcm-avx2-x86_64` and
//! `aes-gcm-avx512-x86_64` kernels, imported by `admin/import-boringssl`.
//!
//! Neither is formally verified: their correctness rests on their use and
//! testing in BoringSSL and Linux, and on rind's tests of them against the
//! portable GHASH, Wycheproof, and aws-lc-rs. Both support in-place use.

use super::aes::AesKey;
use super::cpu::{HaveAvx512ForAesGcm, HaveVaesAvx2ForAesGcm};
use super::ghash::{Ghash, GhashTableAvx};

/// Which kernel runs, decided once from the CPU's features.
#[derive(Clone, Copy)]
enum Kernel {
    /// 256-bit vectors, for VAES cores without AVX-512.
    Avx2(HaveVaesAvx2ForAesGcm),
    /// 512-bit vectors.
    Avx512(HaveAvx512ForAesGcm),
}

/// Powers of a GHASH key: BoringSSL's `u128 Htable[16]`, as its kernel lays
/// them out.
#[repr(C, align(64))]
struct Htable([[u64; 2]; 16]);

/// A GHASH key for one of the VAES kernels.
pub(crate) struct GhashTableVaes {
    htable: Htable,
    kernel: Kernel,
    /// The AVX path's powers, for inputs too short to fill the kernel's
    /// vectors: the AAD, the lengths block, and short messages.
    avx: GhashTableAvx,
}

impl GhashTableVaes {
    /// Precomputes for the GHASH key `h` if the CPU has VAES, or returns `None`.
    pub(crate) fn new(h: u128) -> Option<Self> {
        let kernel = match HaveAvx512ForAesGcm::check() {
            Some(token) => Kernel::Avx512(token),
            None => Kernel::Avx2(HaveVaesAvx2ForAesGcm::check()?),
        };
        let words = [(h >> 64) as u64, h as u64];
        let mut htable = Htable([[0; 2]; 16]);
        // SAFETY: `htable` is an `Htable` and `h` two words. The token proves
        // the CPU has the kernel's features.
        unsafe {
            match kernel {
                Kernel::Avx2(_) => gcm_init_vpclmulqdq_avx2(&mut htable, &words),
                Kernel::Avx512(_) => gcm_init_vpclmulqdq_avx512(&mut htable, &words),
            }
        }
        Some(Self {
            htable,
            kernel,
            avx: GhashTableAvx::new(h),
        })
    }

    /// The AVX path's powers of the same key.
    pub(crate) fn avx(&self) -> &GhashTableAvx {
        &self.avx
    }

    /// Encrypts (if `ENC`) or decrypts `inout` in place, from the counter
    /// block after `y0`, folding the ciphertext into `ghash`.
    pub(crate) fn cipher<const ENC: bool>(
        &self,
        key: &AesKey,
        y0: &[u8; 16],
        ghash: &mut Ghash<'_>,
        inout: &mut [u8],
    ) {
        let mut counter = *y0;
        add_to_counter(&mut counter, 1);

        // The AVX2 kernel takes only whole blocks, so a partial last one is
        // done here; the AVX-512 kernel masks it.
        let bulk = match self.kernel {
            Kernel::Avx2(_) => inout.len() & !15,
            Kernel::Avx512(_) => inout.len(),
        };
        let (bulk, partial) = inout.split_at_mut(bulk);

        if !bulk.is_empty() {
            let mut xi = ghash.xi();
            let (inout, len, key, htable, xi_ptr) = (
                bulk.as_mut_ptr(),
                bulk.len(),
                key.as_aes_key(),
                &self.htable,
                &mut xi,
            );
            // SAFETY: `inout` is `len` readable and writable bytes, which the
            // kernels support in place, `key` is an `AES_KEY`, and the token
            // proves the CPU has the kernel's features. `len` is a multiple of
            // 16 for the AVX2 kernel.
            unsafe {
                match (self.kernel, ENC) {
                    (Kernel::Avx2(_), true) => aes_gcm_enc_update_vaes_avx2(
                        inout, inout, len, key, &counter, htable, xi_ptr,
                    ),
                    (Kernel::Avx2(_), false) => aes_gcm_dec_update_vaes_avx2(
                        inout, inout, len, key, &counter, htable, xi_ptr,
                    ),
                    (Kernel::Avx512(_), true) => aes_gcm_enc_update_vaes_avx512(
                        inout, inout, len, key, &counter, htable, xi_ptr,
                    ),
                    (Kernel::Avx512(_), false) => aes_gcm_dec_update_vaes_avx512(
                        inout, inout, len, key, &counter, htable, xi_ptr,
                    ),
                }
            }
            ghash.set_xi(xi);
        }

        if !partial.is_empty() {
            // The kernel took `bulk.len() / 16` counter blocks, modulo 2^32
            // as GCM increments them.
            add_to_counter(&mut counter, (bulk.len() / 16) as u32);
            let mut keystream = counter;
            key.encrypt_block(&mut keystream);
            if !ENC {
                ghash.add(partial);
            }
            for (b, k) in partial.iter_mut().zip(keystream) {
                *b ^= k;
            }
            if ENC {
                ghash.add(partial);
            }
        }
    }
}

/// Adds `n` to the big-endian 32-bit counter in the last four bytes of `block`.
fn add_to_counter(block: &mut [u8; 16], n: u32) {
    let [.., a, b, c, d] = block;
    let ctr = u32::from_be_bytes([*a, *b, *c, *d]).wrapping_add(n);
    [*a, *b, *c, *d] = ctr.to_be_bytes();
}

/// A table the kernels load, aligned so no load splits a cache line.
#[repr(C, align(64))]
struct Table<const N: usize>([u64; N]);

static AVX2_BSWAP_MASK: Table<2> = Table(include!("boringssl/aes-gcm-avx2-x86_64.bswap_mask.rs"));
static AVX2_GFPOLY: Table<2> = Table(include!("boringssl/aes-gcm-avx2-x86_64.gfpoly.rs"));
static AVX2_GFPOLY_AND_INTERNAL_CARRYBIT: Table<2> = Table(include!(
    "boringssl/aes-gcm-avx2-x86_64.gfpoly_and_internal_carrybit.rs"
));
static AVX2_CTR_PATTERN: Table<4> = Table(include!("boringssl/aes-gcm-avx2-x86_64.ctr_pattern.rs"));
static AVX2_INC_2BLOCKS: Table<4> = Table(include!("boringssl/aes-gcm-avx2-x86_64.inc_2blocks.rs"));

static AVX512_BSWAP_MASK: Table<2> =
    Table(include!("boringssl/aes-gcm-avx512-x86_64.bswap_mask.rs"));
static AVX512_GFPOLY: Table<2> = Table(include!("boringssl/aes-gcm-avx512-x86_64.gfpoly.rs"));
static AVX512_GFPOLY_AND_INTERNAL_CARRYBIT: Table<2> = Table(include!(
    "boringssl/aes-gcm-avx512-x86_64.gfpoly_and_internal_carrybit.rs"
));
static AVX512_CTR_PATTERN: Table<8> =
    Table(include!("boringssl/aes-gcm-avx512-x86_64.ctr_pattern.rs"));
static AVX512_INC_4BLOCKS: Table<2> =
    Table(include!("boringssl/aes-gcm-avx512-x86_64.inc_4blocks.rs"));

/// Declares a kernel as a naked function over BoringSSL's text, binding each
/// table it loads.
///
/// They take the System V ABI on every OS, since their text is BoringSSL's ELF
/// and Mach-O flavors, which read their arguments from its registers.
macro_rules! kernel {
    (fn $name:ident($($arg:ident: $ty:ty),* $(,)?); $($op:ident = $table:ident),* $(,)?) => {
        #[unsafe(naked)]
        unsafe extern "sysv64" fn $name($($arg: $ty),*) {
            #[cfg(not(target_vendor = "apple"))]
            core::arch::naked_asm!(
                include_str!(concat!("boringssl/", stringify!($name), ".linux.s")),
                $($op = sym $table,)*
                options(att_syntax),
            );
            #[cfg(target_vendor = "apple")]
            core::arch::naked_asm!(
                include_str!(concat!("boringssl/", stringify!($name), ".apple.s")),
                $($op = sym $table,)*
                options(att_syntax),
            );
        }
    };
}

kernel! {
    fn gcm_init_vpclmulqdq_avx2(htable: *mut Htable, h: *const [u64; 2]);
    gfpoly = AVX2_GFPOLY,
    gfpoly_and_internal_carrybit = AVX2_GFPOLY_AND_INTERNAL_CARRYBIT,
}
kernel! {
    fn aes_gcm_enc_update_vaes_avx2(
        input: *const u8,
        output: *mut u8,
        len: usize,
        key: *const u8,
        ivec: *const [u8; 16],
        htable: *const Htable,
        xi: *mut [u8; 16],
    );
    bswap_mask = AVX2_BSWAP_MASK,
    ctr_pattern = AVX2_CTR_PATTERN,
    gfpoly = AVX2_GFPOLY,
    inc_2blocks = AVX2_INC_2BLOCKS,
}
kernel! {
    fn aes_gcm_dec_update_vaes_avx2(
        input: *const u8,
        output: *mut u8,
        len: usize,
        key: *const u8,
        ivec: *const [u8; 16],
        htable: *const Htable,
        xi: *mut [u8; 16],
    );
    bswap_mask = AVX2_BSWAP_MASK,
    ctr_pattern = AVX2_CTR_PATTERN,
    gfpoly = AVX2_GFPOLY,
    inc_2blocks = AVX2_INC_2BLOCKS,
}

kernel! {
    fn gcm_init_vpclmulqdq_avx512(htable: *mut Htable, h: *const [u64; 2]);
    gfpoly = AVX512_GFPOLY,
    gfpoly_and_internal_carrybit = AVX512_GFPOLY_AND_INTERNAL_CARRYBIT,
}
kernel! {
    fn aes_gcm_enc_update_vaes_avx512(
        input: *const u8,
        output: *mut u8,
        len: usize,
        key: *const u8,
        ivec: *const [u8; 16],
        htable: *const Htable,
        xi: *mut [u8; 16],
    );
    bswap_mask = AVX512_BSWAP_MASK,
    ctr_pattern = AVX512_CTR_PATTERN,
    gfpoly = AVX512_GFPOLY,
    inc_4blocks = AVX512_INC_4BLOCKS,
}
kernel! {
    fn aes_gcm_dec_update_vaes_avx512(
        input: *const u8,
        output: *mut u8,
        len: usize,
        key: *const u8,
        ivec: *const [u8; 16],
        htable: *const Htable,
        xi: *mut [u8; 16],
    );
    bswap_mask = AVX512_BSWAP_MASK,
    ctr_pattern = AVX512_CTR_PATTERN,
    gfpoly = AVX512_GFPOLY,
    inc_4blocks = AVX512_INC_4BLOCKS,
}
