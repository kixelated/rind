# [S] armv7 raw ciphers from libcrux

## Goal

armv7's `rind::cipher` calls libcrux's exported AES block, AES-CTR, and
ChaCha20 instead of rind's copies of that code, so armv7 carries one AES core
and nothing to keep in step with libcrux by hand.

## Plan

Settled (maintainer, 2026-10-28): rind copied libcrux-aes 0.0.10's bitsliced
AES and HACL*'s ChaCha20 into `rind/src/low/arm/` to land the raw ciphers on
armv7 ([kixelated/rind#21](https://github.com/kixelated/rind/pull/21)), and
switches back once libcrux exports them.

Delete `rind/src/low/arm/{aes,aes_ctr,chacha20}.rs` and the `libcrux-macros`
dependency, and implement `low`'s `AesKey`, `aes_ctr::apply_8`, and
`chacha20::ChaCha20` over the exported API, so `mid::aes`, `mid::chacha20`,
and their tests stay shared. Update the armv7 epic's raw-cipher bullet if the
epic still exists.

## Required

- [libcrux exports its raw ciphers](/quest/m3/libcrux-ciphers-exported.md) - the release this switches to
