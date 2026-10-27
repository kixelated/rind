# [S] HKDF

## Goal

rind's public API derives keys with HKDF (RFC 5869) over SHA-256 and SHA-384,
for moq-quic's address-validation tokens and stateless-reset keys and for
moq-e2ee's credential derivation.

## Plan

graviola has HMAC but no HKDF in its API, and rustls-graviola builds HKDF from
rustls's own HMAC wrapper, which MoQ's direct callers cannot use. MoQ's
transport and e2ee quests call rind's HKDF directly, and the armv7 backend
lists HKDF among libcrux's primitives, so it must exist on every backend.

Guidance:

- Build it on rind's HMAC in `mid`, exposed under `hashing`; extract and
  expand separately, since QUIC and e2ee both reuse a pseudorandom key.
- Refuse an output length over 255 hash lengths with an error.
- Test with RFC 5869's vectors and Wycheproof's HKDF vectors, and
  differentially against aws-lc-rs.

Public API: new HKDF types under `hashing`.
