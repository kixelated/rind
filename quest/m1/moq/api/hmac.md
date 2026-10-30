# [S] Reusable HMAC keys

## Goal

`rind::hmac` separates the key from the computation: an `hmac::Key` is built
once from an algorithm constant, precomputing its padded blocks, and each
message runs through a `Context` started from it, or the one-shot `sign` and
`verify`. Today reuse depends on the caller knowing to clone an `Hmac<H>`.

## Plan

Part of [Learn from aws-lc-rs's API](/quest/m1/moq/api/README.md). Decided by
the maintainer on 2026-10-30 in
[moq-dev/rind#72](https://github.com/moq-dev/rind/pull/72): algorithm
constants and aws-lc-rs's module names.
A sketch following aws-lc-rs:

```rust
pub mod hmac {
    #[derive(Clone, Copy)]
    pub struct Algorithm { .. } // digest_algorithm(), tag_len()
    pub static HMAC_SHA1_FOR_LEGACY_USE_ONLY: Algorithm;
    pub static HMAC_SHA256: Algorithm;
    pub static HMAC_SHA384: Algorithm;
    pub static HMAC_SHA512: Algorithm;

    #[derive(Clone)]
    pub struct Key { .. } // new(algorithm, key: &[u8]), algorithm(); wiped on drop
    #[derive(Clone)]
    pub struct Context { .. } // with_key(&Key), update(&mut self, data), sign(self) -> Tag
    pub struct Tag { .. } // AsRef<[u8]>

    pub fn sign(key: &Key, data: &[u8]) -> Tag;
    pub fn verify(key: &Key, data: &[u8], tag: &[u8]) -> Result<(), Error>; // constant time
}
```

`verify` stays a free function as in aws-lc-rs: every consumer verifies one
contiguous message.

Migration: `Hmac::<Sha256>::new(key)` becomes `hmac::Key::new(HMAC_SHA256, key)`,
built once; each message takes `hmac::Context::with_key(&key)`, and `finish()`
becomes `sign()`. `Hmac::verify(tag)` becomes `hmac::verify(&key, data, tag)`.

Consumers: `rind-rustls` (`hmac.rs` keeps a `Key` and starts a `Context` per
`sign_concat`), `rind-jsonwebtoken`, `rind-object-store`, `rind-dimpl`, and
`rind-str0m` (HMAC-SHA1 for STUN and SRTP). MoQ: moq-e2ee, moq-quic's reset
key, moq-rtmp, moq-tokio's mDNS, and moq-rtc's HMAC-SHA1 port with a path
change.

## Required

- [Digest constants](/quest/m1/moq/api/digest.md) - `hmac::Algorithm` wraps a `digest::Algorithm`
