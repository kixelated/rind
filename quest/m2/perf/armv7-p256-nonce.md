# [XS] armv7 P-256 signing

## Goal

On armv7, ECDSA P-256 signing computes the nonce point once per signature.

## Plan

From [kixelated/rind#8](https://github.com/kixelated/rind/pull/8): the armv7
P-256 signer computes the nonce point twice, because the libcrux API it builds
on does not return it. Find a libcrux entry point that does, or derive `r`
without the second scalar multiplication. MoQ signs once per DTLS handshake
or token, so measure first with the `bench` workflow's `armv7` job (see the
[epic](/quest/m2/perf/README.md)).
