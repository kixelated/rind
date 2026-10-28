# [M] rind-str0m

## Goal

A new `rind-str0m` crate supplies str0m's crypto: SRTP AES-CM-HMAC-SHA1-80
and AEAD AES-128/256-GCM, SHA-256 fingerprints, and HMAC-SHA1, so moq-rtc
and moq-ice run WebRTC media on rind and a browser still connects.

## Plan

Settled (maintainer, 2026-10-26): adapters are separate crates named
`rind-<consumer>`. Browsers require SHA-1 and HMAC-SHA1 for STUN
MESSAGE-INTEGRITY and SRTP AES-CM-HMAC-SHA1-80.

Guidance:

- str0m's DTLS goes through dimpl; this crate covers str0m's own provider
  surface, and [rind-dimpl](/quest/m1/moq/dimpl.md) the DTLS one. If str0m's
  provider trait bundles both, decide in the PR whether one crate serves both.
- Test SRTP protect and unprotect against str0m's aws-lc-rs provider, and the
  RFC 3711 and RFC 7714 vectors.

Public API: the new crate.

## Required

- [Raw ciphers](/quest/m1/moq/cipher.md) - AES-CTR for SRTP AES-CM
