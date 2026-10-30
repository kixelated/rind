# [XS] Ed25519 wipes match aws-lc

## Goal

Ed25519 clears what aws-lc clears: the hashed seed in
`SigningKey::from_seed`, and the hash and nonce made while signing.

## Plan

Decided by the maintainer on 2026-10-30, from the follow-ups of
[moq-dev/rind#73](https://github.com/moq-dev/rind/pull/73), which found
aws-lc cleanses them (`curve25519/curve25519.c:104`, `272`, `302-303` at
aws-lc@91c93a8) and rind does not. Follow the `AGENTS.md` zeroing rule and
#73's evidence format.
