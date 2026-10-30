# [S] Wipe hash scratch

## Goal

Hashing a secret leaves no copy of it on the stack: rind's SHA-1, SHA-256,
and SHA-512 compress functions zero their message-schedule scratch before
returning, so an HMAC key, an Ed25519 seed, or HMAC-DRBG state hashed through
them does not outlive the call. The cost is measured against aws-lc-rs.

## Plan

Decided by the maintainer on 2026-10-29, from the follow-ups of
[kixelated/rind#30](https://github.com/kixelated/rind/pull/30), which found
the copies while testing the HMAC key wipe.

- m1, before release, so `Hmac::new`'s guarantee that no copy of the key
  outlives the call holds in full. OpenSSL and BoringSSL leave this scratch,
  so it goes past them on purpose.
- The scratch is the `w` arrays in `rind/src/low/generic/sha{1,256,512}.rs`
  and the byte-swapped block words in x86_64's 4-block SHA-512 path
  (`rind/src/low/x86_64/sha512.rs`). Paths that keep the block in registers
  (SHA extensions) need nothing. Check the armv7 hash paths the same way.
- Wipe with rind's existing `zeroise`, once per compress call rather than
  per block where the loop allows it, and benchmark each hash against
  aws-lc-rs before and after.
- Copies the compiler spills in unoptimised builds are out of reach. #30
  showed a stack scan cannot tell them apart, so don't add one; test only
  what is reliable.
