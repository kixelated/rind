# Fastest source per cell

## Goal

Every cell of the README's algorithm table runs the fastest source for that
primitive on that backend, preferring a formally verified one when it is as
fast within noise, as `AGENTS.md` requires. Each child is a cell where the
audit found rind off that rule: unverified code slower than or level with a
verified alternative, or code slower than another source.

## Plan

The audit's per-cell numbers are in the PR that created this epic. Each child
re-measures on one head before switching, and updates the README's markers
(✓ verified, ⚡ unverified and measured faster than a verified alternative)
with the code.

## Required

- [armv7 X25519 ladder on NEON](/quest/m2/fastest/armv7-curve25519.md) - BoringSSL's NEON assembly beat curve25519-dalek's X25519 by 13% (161.4 / 185.9 µs per key exchange)
