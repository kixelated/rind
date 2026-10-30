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
- First measure armv7 SHA-512: [moq-dev/rind#41](https://github.com/moq-dev/rind/pull/41)
  moved it from libcrux's HACL code to rind's generic code, about 1.4x slower
  under qemu (SHA-256 got 1.9x faster). Close the gap only if real hardware
  shows it matters (maintainer, 2026-10-29). GitHub's arm64 runners run
  32-bit code natively, which may serve as the host.
