# [S] rind-object-store

## Goal

A new `rind-object-store` crate implements object_store's `CryptoProvider`
(HMAC-SHA256, SHA-256, and RSA PKCS#1-SHA256 signing for GCS), so moq-cli's
S3, Azure, and GCS storage run on rind.

## Plan

Settled (maintainer, 2026-10-26): adapters are separate crates named
`rind-<consumer>`.

Guidance: test request signing against object_store's known-answer tests or
its aws-lc-rs provider for each of S3, Azure, and GCS.

Public API: the new crate.
