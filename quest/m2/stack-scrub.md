# [M] Scrub the stack after keyed hashing

## Goal

After an HMAC or HKDF call, no copy of the keyed chaining value survives in
stack memory, including the copies an optimizing compiler spills, which no
wipe of a named variable can reach. Decide whether a bounded stack scrub is
worth its cost, and land it if so.

## Plan

Decided by the maintainer on 2026-10-29, from the follow-ups of
[moq-dev/rind#41](https://github.com/moq-dev/rind/pull/41): m2, because it
goes beyond what aws-lc-rs and other libraries do.

- Measure first: how deep the spills reach, and what a scrub of that depth
  costs per call. rind allows `unsafe` only in `low`.
- [moq-dev/rind#30](https://github.com/moq-dev/rind/pull/30) found stack scans
  unreliable as tests; find a check that is reliable, or say why none is.
