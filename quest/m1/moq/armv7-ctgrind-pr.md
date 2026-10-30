# [XS] armv7 ctgrind on PRs

## Goal

If the `--release` armv7 ctgrind job is fast enough for the PR gate, it runs
on every PR and is required. The debug job stays nightly.

## Plan

Settled (maintainer, 2026-10-29): measure the `--release` job's time on the
nightly runs of `.github/workflows/ctgrind.yml`. If it fits the gate, run it
on PRs and add it to the required checks. Otherwise, make it faster at the
source, or leave it nightly and say why in the workflow.
