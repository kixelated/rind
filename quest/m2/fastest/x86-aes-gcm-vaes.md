# [M] x86_64 AES-GCM on a compact VAES kernel

## Goal

On x86_64 cores with VAES, AES-GCM runs the fastest kernel available, closing
the 1.1-1.6x gap at 16 KB to aws-lc's AVX-512 code, and giving VAES cores
without AVX-512 (Zen 3, Alder Lake) a VAES path.

## Plan

Decided by the maintainer on 2026-10-30, from the follow-ups of
[moq-dev/rind#109](https://github.com/moq-dev/rind/pull/109). That PR found
aws-lc's non-VAES kernel no faster than Graviola's on Zen 3-5, but aws-lc's
AVX-512 code up to 1.6x faster than rind's AVX-512 path at 16 KB. aws-lc's
file is about 700 KB of machine code, too large to import.

- Measure a compact VAES source, such as BoringSSL's `aes-gcm-avx2-x86_64`
  and `aes-gcm-avx10-x86_64`, against rind's current paths at 32 B, 1200 B
  (a QUIC packet), and 16 KB on the hosted Zen 4 and Zen 5 runners and a
  VAES core without AVX-512.
- Import mechanically with `admin/import-aws-lc`, as SHA-512 is, decide the
  path once at setup from CPU features, and keep `cpu::check()`'s
  requirements. Mark the cell ⚡ unless a proof covers rind's in-place use.
- Update the README cell and LICENSE with the code.
