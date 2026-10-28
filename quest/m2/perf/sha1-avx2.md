# [S] SHA-1 without SHA-NI

## Goal

On x86_64 hosts without SHA extensions, rind's SHA-1 and HMAC-SHA1 run within
about 1.2x of aws-lc-rs, which matters for SRTP's per-packet HMAC-SHA1.

## Plan

From [kixelated/rind#7](https://github.com/kixelated/rind/pull/7): the
portable path runs at about 615 MiB/s on 64 KB, against RustCrypto's 726 MiB/s
and aws-lc-rs's 1.18 GiB/s. aws-lc computes the message schedule with AVX2,
which every CPU rind accepts has. Runtime selection between SHA-NI and the
other path is fine (maintainer, 2026-10-27, on #7): the one-backend rule is
about graviola vs libcrux, not per-instruction paths.

Measure at SRTP packet sizes first (see the [epic](/quest/m2/perf/README.md)).
