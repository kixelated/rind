# [S] ctgrind covers every secret

## Goal

`admin/ctgrind` checks every path that handles a secret, so a branch or
lookup on one fails the run instead of passing unmarked. Three gaps remain
after [kixelated/rind#19](https://github.com/kixelated/rind/pull/19):

- ML-KEM-768 marks its decapsulation key and shared secret secret; `mid::mlkem768` marks nothing today.
- ECDSA's nonce derivation runs on a secret key. `ecdsa.rs` encodes the private
  key through `as_bytes`, which declassifies it (`mid::p256`, `mid::p384`), so
  the HMAC-DRBG and `generate_random_key` path is unchecked.
- `Aes::new` and `AesCtr::new` mark their own key copy secret, not the
  caller's buffer: `expand_key` in `mid::aes` marks the caller's slice, which
  stays marked after the call.

## Plan

Planned by the maintainer on 2026-10-28, from the follow-ups of
[kixelated/rind#19](https://github.com/kixelated/rind/pull/19).

- Give the ECDSA signer an internal encoding that keeps the scalar secret; the
  public `as_bytes` keeps declassifying, since its caller owns the bytes.
- Fix any leak the new marks expose in the same PR, as #19 did.
- Cover the armv7 and arm backends the same way where they hold these secrets.
