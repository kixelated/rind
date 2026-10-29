# [S] armv7 benchmark host

## Goal

`rind-bench` runs on real 32-bit ARM hardware, with its numbers recorded in
the PR, so the armv7 speed quests measure before they optimize.

## Plan

Deferred by the maintainer (2026-10-28), host not chosen: emulation gives no
meaningful timing, and GitHub's hosted runners are not armv7 hardware. Ask the
maintainer for the host when this starts, such as a self-hosted Raspberry Pi 4
(its Cortex-A72 runs 32-bit code) running a nightly job, or a one-off run on a
board they own.
