# [S] rind-instant-acme

## Goal

A new `rind-instant-acme` crate implements instant-acme's `CryptoProvider`
([djc/instant-acme#268](https://github.com/djc/instant-acme/pull/268)),
so moq-relay's ACME client signs account requests and computes thumbprints on
rind. It targets instant-acme's main branch until 0.9 is released.

## Plan

Settled (maintainer, 2026-10-26): adapters are separate crates named
`rind-<consumer>`. Decided 2026-10-30 (maintainer): don't block on the
release.

- Depend on a pinned instant-acme git revision with `publish = false`, as
  `rind-str0m` does with str0m, and allow it in `deny.toml`.
- Test against a local ACME server such as Pebble, issuing a certificate end
  to end.
- [Publish rind-instant-acme](/quest/m1/moq/instant-acme-publish.md) switches
  it to the release.

Public API: the new crate.
