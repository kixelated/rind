# [M] ctgrind on armv7

## Goal

The ctgrind workflow also runs rind's ctgrind tests, and the adapters', for
`armv7-unknown-linux-gnueabihf`, and fails on any branch or memory index that
depends on a secret, so armv7's libcrux and fiat-crypto backends and the
operations rind adds over them get the same constant-time check as x86_64.

## Plan

Settled with the maintainer (2026-10-28), after
[kixelated/rind#8](https://github.com/kixelated/rind/pull/8) merged without
armv7 ctgrind:

- Run under emulation now; armv7 hardware is only needed for timing, which is
  [armv7 benchmark host](/quest/m2/perf/armv7-host.md). Memcheck's
  definedness tracking follows the instructions executed, not their speed, so
  emulated results are real.
- valgrind cannot run inside qemu's user mode, which the armv7 tests use.
  First check whether GitHub's hosted arm64 runner executes 32-bit ARM
  binaries natively; if it does, run an armhf valgrind there. Otherwise boot
  an armhf Debian guest under `qemu-system-arm` and run valgrind in it.
- If it is too slow for every PR, run it on the workflow's nightly schedule
  only.

Guidance:

- Extend `admin/ctgrind` with the armv7 runner rather than a second script.
- A finding inside libcrux is reported upstream, and rind works around it
  only if the fix is in rind's own code.
- Once it is stable and runs on every PR, mark the CI job required on `main`;
  a nightly-only job stays optional, since it never runs on a PR's head.
