# [S] HKDF expand speed

## Goal

`hkdf::Prk::expand` runs within about 1.2x of ring for a one-block expand,
and the pseudorandom key it holds is still wiped on drop.

## Plan

Decided by the maintainer on 2026-10-27, in
[kixelated/rind#13](https://github.com/kixelated/rind/pull/13): `Prk` stores
the key as bytes so it can be wiped, and rebuilds the HMAC key on each
`expand`, about 2x ring. The wipe stays; this quest wins the speed back
without giving it up.

The obvious route is to keep the pre-keyed HMAC state (inner and outer hash
states), which [Wipe HMAC and DRBG state](/quest/m1/moq/state-wipe.md) makes
wipe itself on drop. rind allows `unsafe` only in `low`, so the wipe
has to come from a safe zeroing of graviola's `Hmac` state, or from a
`low` helper. A hand-written `Clone` on `Hmac` was the other cost noted in
#13.

MoQ derives once per token or per track, not per packet, so measure the
callers first (see the [epic](/quest/m2/perf/README.md)).
