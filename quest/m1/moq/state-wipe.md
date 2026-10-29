# [S] Wipe HMAC and DRBG state

## Goal

`Hmac` and `HmacDrbg` wipe their keyed state when dropped: HMAC's inner and
outer hash states, and HMAC-DRBG's K and V, which derive ECDSA nonces under
RFC 6979. No copy of an HMAC key or a nonce-generator state outlives its
owner.

## Plan

Decided by the maintainer on 2026-10-29, from the follow-ups of
[kixelated/rind#39](https://github.com/kixelated/rind/pull/39).

- m1, before release, beside the HMAC key wipe
  ([kixelated/rind#30](https://github.com/kixelated/rind/pull/30)) and the
  hash scratch wipe quest planned in
  [kixelated/rind#38](https://github.com/kixelated/rind/pull/38).
- rind allows `unsafe` only in `low`, so the wipe comes from a safe zeroing
  of the hash context types or a `low` helper. `Hmac::finish` moves both
  states out of `self`, so it needs restructuring.
- Extend `rind/tests/zeroing.rs` only where the check is reliable; #30 showed
  stack scans are not.
- [HKDF expand speed](/quest/m2/perf/hkdf-expand.md) builds on this: once
  `Hmac` wipes itself, `Prk` can keep the pre-keyed state.
