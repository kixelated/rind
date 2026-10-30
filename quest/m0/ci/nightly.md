# [S] Platform CI nightly

## Goal

Only `Check` runs on a pull request. Every other workflow (asan, bench,
build, coverage, cranelift, ctgrind, fuzz, lints, x86-cpu) runs on the
nightly schedule and on `workflow_dispatch`, not on `pull_request` or on
push to `main`. A nightly failure alerts the maintainer. Every workflow
cancels a superseded run of the same ref.

## Plan

Decided by the maintainer on 2026-10-29: the platform matrix runs nightly,
not on `main`.

- Land this before [the gate](/quest/m0/ci/land.md); `Check` stays on PRs
  until the gate replaces it.
- `concurrency` with `cancel-in-progress` keyed on the workflow and ref.
- The alert opens or updates one issue, or uses whatever moq-dev/moq's
  `alert.yml` does, so a red nightly is not silent. Reuse moq's approach
  rather than inventing one.
- Fold lints' fast parts (msrv, license scan, structure, parse-asm) into
  `just ci` if they fit its time budget, since `just ci` is now the only
  per-PR gate; otherwise keep them nightly.
- Update `CONTRIBUTING.md` and `README.md` where they describe CI.
