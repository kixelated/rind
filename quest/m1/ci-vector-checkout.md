# [XS] CI checks out only the test vectors

## Goal

CI workflows check out the `thirdparty/cavp` and `thirdparty/wycheproof`
submodules they read, not every submodule, so no job clones s2n-bignum.

## Plan

Decided by the maintainer on 2026-10-29, from the follow-ups of
[kixelated/rind#29](https://github.com/kixelated/rind/pull/29), which found
that nothing `just ci` runs reads s2n-bignum; only the `admin/parse-asm`
generators do.

- Replace `submodules: true` in `.github/workflows/*.yml` with a checkout of
  the two vector submodules, or none for jobs that read neither.
