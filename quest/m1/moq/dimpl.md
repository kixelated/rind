# [L] rind-dimpl

## Goal

A new `rind-dimpl` crate supplies dimpl's crypto: DTLS 1.2 and 1.3 with
AES-GCM and ChaCha20 suites, X25519, P-256, and P-384 key exchange, ECDSA
P-256/P-384, and record number protection, so moq-rtc completes DTLS with a
browser on rind.

## Plan

Settled (maintainer, 2026-10-26): adapters are separate crates named
`rind-<consumer>`. DTLS 1.3 record number protection uses the raw AES block
and ChaCha20.

Guidance: handshake tests for every suite and group against dimpl on its
aws-lc-rs provider, for both DTLS versions.

Public API: the new crate.
