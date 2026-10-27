# [S] rind-instant-acme

## Goal

A new `rind-instant-acme` crate implements instant-acme 0.9's
`CryptoProvider` ([djc/instant-acme#268](https://github.com/djc/instant-acme/pull/268)),
so moq-relay's ACME client signs account requests and computes thumbprints on
rind.

## Plan

Settled (maintainer, 2026-10-26): adapters are separate crates named
`rind-<consumer>`; this one waits on the instant-acme 0.9 release.

Guidance: test against a local ACME server such as Pebble, issuing a
certificate end to end.

Public API: the new crate.

## Required

- [instant-acme 0.9 is released](/quest/m1/moq/instant-acme-release.md) - the release with the provider trait
