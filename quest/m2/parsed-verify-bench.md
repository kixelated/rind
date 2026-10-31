# [XS] Benchmark ECDSA verify with a parsed key

## Goal

`rind-bench` measures ECDSA P-256 and P-384 verification with a key parsed
once, against aws-lc-rs's `ParsedPublicKey`, so a regression in the cached
verification table shows up.

## Plan

Decided by the maintainer on 2026-10-30, from the follow-ups of
[moq-dev/rind#108](https://github.com/moq-dev/rind/pull/108), where this case
decided the verification design but was benchmarked only on a throwaway
branch. Follow #101's `rsa2048-pkcs1-sha256-verify-parsed` benchmark.
