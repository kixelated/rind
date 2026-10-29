# [S] dimpl checks signatures for every provider

## Goal

`rind-dimpl` no longer enables dimpl's internal `_crypto-common` feature,
because dimpl runs its RFC 8446 §4.4.3 check (a CertificateVerify's scheme
matches the certificate's curve) for every provider.

## Plan

Planned by the maintainer on 2026-10-28, from the follow-ups of the m1 PRs. Deferred to m3 (maintainer, 2026-10-28), until MoQ runs on rind.
[kixelated/rind#16](https://github.com/kixelated/rind/pull/16) enabled the
feature to keep the check, since dimpl ties it to its built-in providers.

- Ask the maintainer before asking dimpl upstream. Once asked, add a
  condition quest beside this one for the dimpl release that carries it.
- Then drop the feature from `rind-dimpl/Cargo.toml` and keep its test that a
  mismatched scheme is refused.

## Required

- [MoQ runs on rind](/quest/m3/moq-on-rind.md) - deferred until then
