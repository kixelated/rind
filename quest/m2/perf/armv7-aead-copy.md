# [XS] armv7 AEAD copy

## Goal

On armv7, AES-GCM, ChaCha20-Poly1305, and XChaCha20-Poly1305 seal and open in
place, without copying the buffer once per call.

## Plan

From [kixelated/rind#8](https://github.com/kixelated/rind/pull/8): libcrux's
AEAD API takes separate input and output buffers, so the armv7 backend copies
rind's in-place buffer once per call. Check whether libcrux exposes an
in-place entry point, or accepts aliased buffers soundly. armv7 is a phone or
small board publishing a few Mbps, so measure on real armv7 hardware before
optimizing (see the [epic](/quest/m2/perf/README.md)).
