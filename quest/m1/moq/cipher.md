# [M] Raw ciphers

## Goal

rind's graviola backend exposes the raw AES block cipher and ChaCha20 for QUIC
header protection and DTLS 1.3 record number protection, and AES-CTR for SRTP
AES-CM.

## Plan

Settled (maintainer, 2026-10-26): start from ctz's `jbp-quic` branch
([ctz/graviola#156](https://github.com/ctz/graviola/pull/156) adapts it),
whose ChaCha part is unfinished.

Guidance:

- Expose the narrowest shape each protocol needs: a single-block AES
  encryption and a ChaCha20 keystream from a counter and nonce cover header
  and record number masks; AES-CTR covers SRTP.
- Keep the existing AES-GCM and ChaCha20-Poly1305 code paths as the
  implementation, so the new API adds no second copy of either cipher.
- Test against RFC 9001's header protection samples, RFC 3711's AES-CM
  vectors, RFC 8439's ChaCha20 vectors, and Wycheproof where it covers them,
  plus differential tests against aws-lc-rs. Add benchmarks.

Public API: raw AES, ChaCha20, and AES-CTR types under a new module.
