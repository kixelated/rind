# [XS] Nameable key errors

## Goal

Every type reachable from `rind::Error` is one a caller can name. Today
`Error::Asn1Error` and `Error::KeyFormatError` carry `high::asn1::Error` and
`KeyFormatError`, which no public path exports, so a caller can print them but
not match them.

## Plan

Part of [Learn from aws-lc-rs's API](/quest/m1/moq/api/README.md). Decided by
the maintainer on 2026-10-30 in
[moq-dev/rind#72](https://github.com/moq-dev/rind/pull/72): keep `rind::Error`
as a matchable enum, and fold both variants
into one `Error::KeyRejected(KeyRejected)`, after aws-lc-rs's `KeyRejected`:
an exported opaque type whose `Display` keeps today's detail, so the ASN.1
parser's error enum never becomes public API.

Migration: match `Error::KeyRejected(_)` where code matched
`Error::Asn1Error(_)` or `Error::KeyFormatError(_)`. No adapter matches
either today.
