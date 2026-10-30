# [M] Learn from aws-lc-rs's API

## Goal

rind's public API takes what works from aws-lc-rs's: shapes that steer a
caller away from misuse and toward reusing expensive setup. Each module is
compared against its aws-lc-rs counterpart, and the changes worth a breaking
release land; the rest are recorded as rejected, with the reason.

## Plan

Decided by the maintainer on 2026-10-29, while planning
[the AesGcm key fix](/quest/m1/moq/aes-gcm-key.md): they like aws-lc-rs's
API because, while confusing at first, it avoids misuse and promotes reuse.
m2, after the first release, rather than delaying the release for it.

- Start with `aead`, the known case. aws-lc-rs builds one unbound key from an
  algorithm constant (`AES_128_GCM`, `CHACHA20_POLY1305`, ...) and key bytes,
  returning a `Result` on a bad length. It expands that key once, then wraps
  it by use: sealing and opening keys driven by a nonce sequence, a
  randomized-nonce key that picks and returns its nonce, TLS record keys,
  and `LessSafeKey`, whose name flags that the caller owns nonce
  uniqueness. The `rind-*` adapters sit on protocols that own their nonces,
  so they would use the caller-nonce layer.
- Then compare `agreement`, `signature`, `hkdf`, `hmac`, `digest`, and
  `rand`, such as ephemeral keys that can be used only once.
- List MoQ's direct callers first; a shape only ships with a consumer.
- Prefer one coordinated breaking release over a series of them, and split
  per module only if a module is independently landable.
