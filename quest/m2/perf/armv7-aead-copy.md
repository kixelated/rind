# [XS] armv7 AEAD copy

## Goal

On armv7, AES-GCM seals and opens in place, without copying the buffer once
per call.

## Plan

From [kixelated/rind#8](https://github.com/kixelated/rind/pull/8): libcrux's
AES-GCM API takes separate input and output buffers, so the armv7 backend
copies rind's in-place buffer once per call. The ChaCha AEADs already work in
place, over rind's ChaCha20 and HACL*'s Poly1305. Check whether libcrux exposes an
in-place entry point, or accepts aliased buffers soundly. armv7 is a phone or
small board publishing a few Mbps, so measure with the `bench` workflow's
`armv7` job before optimizing (see the [epic](/quest/m2/perf/README.md)).
