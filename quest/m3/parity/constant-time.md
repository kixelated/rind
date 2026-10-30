# [XS] Constant-time comparison

## Goal

rind exposes a constant-time slice comparison returning `Result<(), Error>`, as ring's `constant_time::verify_slices_are_equal` does, so callers stop writing their own.

## Plan

Decided by the maintainer on 2026-10-30, planning ring and aws-lc-rs parity.

- Reuse `low::ct_equal`, keep the ctgrind marks, and refuse unequal lengths
  without branching on contents.
