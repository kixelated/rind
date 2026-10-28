# [M] rind-jsonwebtoken

## Goal

A new `rind-jsonwebtoken` crate provides jsonwebtoken 11's `CryptoProvider`
for HS256/384/512, ES256/384, RS256/384/512, PS256/384/512, and EdDSA, signing
and verifying, so moq-auth issues and checks every token algorithm it accepts
today on rind.

## Plan

Settled (maintainer, 2026-10-26): adapters are separate crates named
`rind-<consumer>`, so jsonwebtoken's next major bump never forces a rind major
bump.

Guidance:

- The closed [moq-dev/moq#6861](https://github.com/moq-dev/moq/pull/6861) has a
  working graviola provider to start from.
- Install nothing globally; the consumer chooses when to install the provider.
- Test every algorithm by signing here and verifying with jsonwebtoken's
  aws-lc-rs provider, and the reverse.

Public API: the new crate.
