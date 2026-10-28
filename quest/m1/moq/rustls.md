# [L] rind-rustls covers MoQ

## Goal

`rind-rustls` (renamed from `rustls-graviola`) is a rustls `CryptoProvider`
covering what MoQ uses today: TLS 1.3 and 1.2 suites with AES-128/256-GCM and
ChaCha20-Poly1305, X25519MLKEM768 preferred, X25519, P-256, and P-384 key
exchange, verification of ECDSA P-256/P-384, Ed25519, and RSA PKCS#1/PSS,
signing-key loading for all three key types, and rustls's QUIC keys (packet
keys and header protection). No P-521, as with ring.

## Plan

Settled (maintainer, 2026-10-26), from MoQ's 2026-10-26 inventory. MoQ's
QUIC stack takes packet keys and header protection only through rustls's QUIC
traits, so this crate is the whole QUIC crypto surface for MoQ.

Guidance:

- [ctz/graviola#156](https://github.com/ctz/graviola/pull/156) implements
  rustls's QUIC traits over ctz's `jbp-quic` branch; reuse what fits, without
  its switch to `noq`, which MoQ does not use.
- Check which of these the crate already offers before adding: graviola's
  provider already covers most TLS suites and key exchange.
- Handshake tests: TLS 1.2 and 1.3 against rustls on aws-lc-rs for every suite,
  key exchange group, and key type, and a QUIC handshake through quinn or
  rustls's QUIC test harness.

Public API: additions to `rind-rustls` (QUIC support, any missing groups or
key types).
