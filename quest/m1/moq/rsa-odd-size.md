# [S] RSA keys of any bit length verify

## Goal

RSA public keys whose modulus is not a multiple of 64 bits (such as a
2056-bit key from OpenSSL) verify valid PKCS#1 v1.5 and PSS signatures, on
every backend, as aws-lc-rs does. Today every valid signature under such a
key fails to verify.

## Plan

Found by [moq-dev/rind#62](https://github.com/moq-dev/rind/pull/62) while
adding the verification tests; reproduced there, and present before it.
Planned on 2026-10-29 under the `AGENTS.md` rule to follow aws-lc-rs when in
doubt: aws-lc-rs supports these keys, so rind supports them rather than
refusing them at load.

- Reproduce first with an OpenSSL-generated odd-size key, then fix the length
  handling at its source.
- Cover it with aws-lc-rs cross-checks in `rind/tests/crosschecks.rs` and any
  Wycheproof vectors with such moduli; check signing at those sizes too.
