# [S] Wipe libcrux's secret stack copies on armv7

## Goal

armv7 leaves no secret copies behind in libcrux's stack frames once a rind
operation returns. libcrux's HACL* code copies keys and keyed state into
locals it never wipes, such as Poly1305's `digest`, and rind's own
`zeroise` cannot reach those frames.

## Plan

Settled (maintainer, 2026-10-29):

- Report the unwiped stack copies to libcrux as a bug. libcrux's
  `SECURITY.md` decides whether that report is private. Keep any exploit
  detail out of this quest.
- Scrub what rind can after the calls without waiting on upstream, for
  example by zeroing the stack region libcrux's calls used before rind's
  entry point returns. Measure the cost against aws-lc-rs.
- Once an upstream fix ships, bump to it and drop whatever scrubbing it makes
  redundant.
