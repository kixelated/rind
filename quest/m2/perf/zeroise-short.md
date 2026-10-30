# [XS] Faster short zeroing

## Goal

x86_64's `zero_bytes` (`rind/src/low/x86_64/cpu.rs`) clears buffers under 32
bytes with wide stores instead of one byte at a time, winning back most of
the 3 to 7% that wiping hash contexts added to a 32-byte HMAC.

## Plan

Decided by the maintainer on 2026-10-29, from the follow-ups of
[moq-dev/rind#42](https://github.com/moq-dev/rind/pull/42).

- The wipe must still not be optimized away; keep whatever barrier the
  helper uses now.
- Measure HMAC at 32 bytes and plain hashes against aws-lc-rs before and
  after.
