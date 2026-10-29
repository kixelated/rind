# [XS] CI checks out only the submodules it reads

## Goal

Each CI job checks out only the submodules it reads: `thirdparty/cavp` and
`thirdparty/wycheproof` for the tests, s2n-bignum only for the job that runs
the `admin/parse-asm` code generators, and none for jobs that read none.

## Plan

Decided by the maintainer on 2026-10-29, from the follow-ups of
[kixelated/rind#29](https://github.com/kixelated/rind/pull/29), which found
that nothing `just ci` runs reads s2n-bignum; only the `admin/parse-asm`
generators do.

- Replace `submodules: true` in `.github/workflows/*.yml` with a checkout of
  the submodules each job reads. The `checks` job in `lints.yml` runs
  `admin/parse-asm/all.sh`, so it keeps s2n-bignum.
