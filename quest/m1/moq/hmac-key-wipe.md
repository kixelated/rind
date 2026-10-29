# [XS] Wipe HMAC's padded key

## Goal

`Hmac::new` zeroes the padded key block it builds on the stack before
returning, so no copy of an HMAC key outlives the call, as rind's other key
types already guarantee.

## Plan

Planned by the maintainer on 2026-10-28, from the follow-ups of the m1 PRs. Found while reviewing
[kixelated/rind#13](https://github.com/kixelated/rind/pull/13) (HKDF), whose
stored key is wipeable but whose HMAC setup is not.

- Wipe it the way rind's existing zeroing does, and extend
  `rind/tests/zeroing.rs` to cover HMAC and HKDF setup.
