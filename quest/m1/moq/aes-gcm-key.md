# [XS] AesGcm refuses a bad key length

## Goal

`aead::AesGcm::new` returns `Result<Self, Error>` and refuses a key that is
not 16 or 32 bytes with `Error::WrongLength` instead of panicking, and it
marks its own key copy secret for ctgrind. A breaking change, before the
first release.

## Plan

Decided by the maintainer on 2026-10-29, from the follow-ups of
[kixelated/rind#39](https://github.com/kixelated/rind/pull/39).

- `Result`, matching `Aes::new` and aws-lc-rs's
  `UnboundKey::new(&AES_128_GCM, key)`. Separate constructors taking
  `&[u8; 16]` or `&[u8; 32]` were rejected for now: the adapters receive keys
  as slices. An algorithm-agnostic key type is for
  [Learn from aws-lc-rs's API](/quest/m2/aws-lc-api.md).
- Update every adapter caller to propagate the error.
