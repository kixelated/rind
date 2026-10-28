# [S] rind-rcgen

## Goal

A new `rind-rcgen` crate implements rcgen's `SigningKey` with ECDSA P-256 key
generation, so MoQ generates self-signed and DTLS certificates on rind.

## Plan

Settled (maintainer, 2026-10-26): adapters are separate crates named
`rind-<consumer>`. MoQ uses rcgen for moq-tokio's self-signed certificates,
moq-rtc's DTLS certificates, and moq-relay's ACME keys and CSRs.

Guidance: test that a generated certificate verifies under `rind-rustls` and
under rustls on aws-lc-rs.

Public API: the new crate.
