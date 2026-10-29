// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

/// Constant-time equality of two little-endian bignums, of any widths.
pub(crate) fn bignum_eq(x: &[u64], y: &[u64]) -> bool {
    let mut diff = 0u64;
    for i in 0..x.len().max(y.len()) {
        diff |= x.get(i).copied().unwrap_or(0) ^ y.get(i).copied().unwrap_or(0);
    }
    core::hint::black_box(diff) == 0
}
