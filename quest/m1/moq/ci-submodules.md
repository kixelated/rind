# [XS] Fail fast without test vectors

## Goal

`just ci` and `just check` stop at the start with a message naming
`git submodule update --init` when the cavp, wycheproof, or s2n-bignum
submodules are not checked out, instead of failing tests partway through.

## Plan

Planned by the maintainer on 2026-10-28, from the follow-ups of the m1 PRs. Fresh agent worktrees kept failing the CAVP and Wycheproof tests until the
submodules were initialised.

- Check in `sh/dispatch.sh` (or the script it runs), once, before building.
