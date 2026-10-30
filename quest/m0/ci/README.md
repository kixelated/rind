# Hosted CI off the PR path

## Goal

rind stops filling GitHub's hosted runners. A PR is checked by the author's
local `just ci` and then by a landing gate on a self-hosted runner; the
platform matrix (macOS, Windows, arm64, armv7, Intel SDE CPUs, coverage,
Cranelift, fuzzing, CodSpeed) runs nightly, and a failure there alerts.

## Plan

Decided by the maintainer on 2026-10-29, when one rind push started about 24
hosted jobs and 140 runs sat queued:

- Platform jobs run nightly, not on push to `main` and not on PRs.
- PRs reach `main` through `quest land` on a self-hosted runner, the engine
  kixelated/quest already uses and moq-dev/moq is adopting
  (`quest/m0/ci/land.md` there), rather than GitHub's merge queue.
- rind moved to the moq-dev organization (2026-10-29), so it can share moq's
  queue runner and the organization's runner limits.

## Required

- [Land through quest land](/quest/m0/ci/land.md) - `just ci` on the organization's queue runner gates `main`
