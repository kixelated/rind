# [XS] Coverage detects x86_64

## Goal

`admin/coverage` runs its x86_64-only passes (CPU features disabled, and
under Intel SDE) on every x86_64 host, including CI's.

## Plan

Planned by the maintainer on 2026-10-28, from the follow-ups of the m1 PRs. It gates them on `uname -p`, which prints `unknown` on many Linux
distributions, so they may never run; the aarch64 branch below it already uses
`uname -m`. Switch to `uname -m`, and confirm from the coverage workflow's log
that the passes run.
