# [S] SHA-256 without SHA-NI

## Goal

On x86_64 hosts without SHA extensions, rind's SHA-256 runs within about
1.2x of aws-lc-rs, closing the gap that leaves HKDF expand at 2x ring there.

## Plan

Decided by the maintainer on 2026-10-30, from the follow-ups of
[moq-dev/rind#63](https://github.com/moq-dev/rind/pull/63).

- Follow [moq-dev/rind#64](https://github.com/moq-dev/rind/pull/64)'s design
  for SHA-1: an AVX2 message schedule for two blocks at once, in plain Rust
  (no new inline assembly).
- Measure first on CodSpeed and MoQ's callers, as the epic says.
