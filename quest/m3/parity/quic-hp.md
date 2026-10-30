# [XS] QUIC header protection

## Goal

rind offers QUIC header-protection keys (AES-128, AES-256, and ChaCha20 masks, RFC 9001 §5.4) in its public API, as ring's `aead::quic` does, for QUIC implementations that use rind directly.

## Plan

Decided by the maintainer on 2026-10-30, planning ring and aws-lc-rs parity.

- rind-rustls already derives these internally; expose the shared code rather
  than duplicating it.
