# [M] armv7 RSA on aws-lc's Montgomery multiplication

## Goal

armv7 RSA signing and verification run their fastest available Montgomery
multiplication. Today they run HACL*'s verified bignum, which
[moq-dev/rind#101](https://github.com/moq-dev/rind/pull/101) found costs about
twice aws-lc's armv4 assembly per operation, and no faster verified 32-bit
source exists. The cell would become ⚡.

## Plan

On the bench runner (Neoverse-N2 running the armv7 build), rind after #101
against aws-lc-rs (run 41139274206):

| | rind | aws-lc-rs | ratio |
|---|---|---|---|
| rsa2048-pkcs1-sha256-verify | 218 µs | 74.9 µs | 2.91 |
| rsa2048-pkcs1-sha256-verify-parsed | 155 µs | 60.8 µs | 2.55 |
| rsa2048-pkcs1-sha256-sign | 6.93 ms | 2.71 ms | 2.56 |

RustCrypto's pure-Rust `rsa` signs in 5.57 ms against rind's 6.91 ms, but
verifies in 285 µs against 215 µs (bench-tmp run 41151132431), so it is not
the candidate.

aws-lc's 32-bit ARM Montgomery multiplication is `bn_mul_mont` from
`armv4-mont`, with a NEON path. Import it with `admin/import-aws-lc`, then
decide how much of HACL*'s exponentiation and context code to keep around it.
Signing's exponentiation must stay constant time, so check what aws-lc's
constant-time exponentiation relies on before composing with it.

An RSA verify is once per certificate in a handshake, so weigh the saving
(at most about 140 µs per verify and 4 ms per signature) against the precedent in
[moq-dev/rind#99](https://github.com/moq-dev/rind/pull/99), which judged
0.24 ms per handshake not to matter. Delete this quest if it does not.
