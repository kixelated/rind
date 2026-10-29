# m3: deferred

## Goal

Work that waits on something besides priority: an outside party, an upstream
release, or a consumer that does not exist yet.

## Plan

A quest gated on the outside world has a condition quest beside it, as the
[quest guide](https://github.com/kixelated/quest) describes: the condition
quest names how to check it and is deleted once it holds.

## Required

- [MoQ runs on rind](/quest/m3/moq-on-rind.md) - waiting on MoQ to finish its migration
- [Revisit upstreaming](/quest/m3/upstream.md) - decide what rind offers back to graviola once MoQ runs on it
- [dimpl checks signatures for every provider](/quest/m3/dimpl-crypto-common.md) - waiting on a dimpl release, then rind-dimpl drops dimpl's internal feature
- [armv7 raw ciphers from libcrux](/quest/m3/libcrux-ciphers.md) - drop rind's copies once libcrux exports its AES and ChaCha20
- [libcrux exports its raw ciphers](/quest/m3/libcrux-ciphers-exported.md) - waiting on a libcrux release that exports them
