# [XS] SHA-1 AVX2 rounds in Rust

## Goal

The x86_64 AVX2 SHA-1 from [moq-dev/rind#64](https://github.com/moq-dev/rind/pull/64)
runs its rounds in plain Rust instead of hand-written inline assembly, so
rind ships no new unverified assembly.

## Plan

Decided by the maintainer on 2026-10-30: about 7% slower (267 against 248
cycles per block in #64's measurement) is an acceptable price under the
`AGENTS.md` preference for verified sources over new arithmetic. Keep #64's
message-schedule design and its tests; benchmark against aws-lc-rs.
