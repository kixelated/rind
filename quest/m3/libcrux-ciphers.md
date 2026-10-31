# [S] armv7 raw ciphers from libcrux

## Goal

armv7's `rind::cipher` calls libcrux's exported AES block and AES-CTR
instead of rind's copies of that code, so armv7 carries one AES core and
nothing to keep in step with libcrux by hand.

## Plan

Settled (maintainer, 2026-10-28): rind copied libcrux-aes 0.0.10's bitsliced
AES into `rind/src/low/arm/` to land the raw ciphers on armv7
([kixelated/rind#21](https://github.com/kixelated/rind/pull/21)), and
switches back once libcrux exports it. armv7's ChaCha20 is aws-lc's assembly,
which is faster than HACL*'s, so it stays; only HChaCha20's rounds remain
copied from HACL*.

Delete `rind/src/low/arm/{aes,aes_ctr}.rs`, and implement `low`'s `AesKey`
and `aes_ctr::apply_8` over the exported API, so `mid::aes` and its tests
stay shared. Update the armv7 epic's raw-cipher bullet if the epic still
exists.

## Required

- [libcrux exports its raw ciphers](/quest/m3/libcrux-ciphers-exported.md) - the release this switches to
