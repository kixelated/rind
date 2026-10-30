# [XS] Inherited wipes match aws-lc

## Goal

The zeroing that rind inherited from graviola, and the ECDH paths, follow the
`AGENTS.md` rule: each wipe matches what aws-lc clears for its equivalent.

## Plan

Decided by the maintainer on 2026-10-30, from the follow-ups of
[moq-dev/rind#60](https://github.com/moq-dev/rind/pull/60).

- Check, with aws-lc file and line as #58 and #60 did: the ECDSA nonce-seed
  key encoding, RSA's PKCS#1 buffer in `to_pkcs8_der`, Ed25519's generated
  seed, the RSA key-generation candidate buffer, and the mod-exp table in
  `low/posint.rs`. Keep, revert, or add to match.
- x86_64 and aarch64 P-256/P-384 ECDH wipe their shared point, as aws-lc
  does.
