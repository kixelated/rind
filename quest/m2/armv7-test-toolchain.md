# [XS] armv7 tests in the dev shell

## Goal

`nix develop` can lint, build, and run rind's armv7 tests locally, on both of
rind's armv7 paths, the way the nightly `armv7` job in `build.yml` does.
Today a local armv7 check covers only the library, so an ARM-only test can
break without a local signal.

## Plan

Decided by the maintainer on 2026-10-30, from the follow-ups of
[moq-dev/rind#89](https://github.com/moq-dev/rind/pull/89).

- rind itself builds without C on every target. Only the tests need an ARM C
  toolchain, because their aws-lc-rs oracle is C. Keep that toolchain out of
  anything rind ships, and say so where it is added.
- Add the armv7 Rust target, an `armv7-unknown-linux-gnueabihf` C cross
  toolchain, and qemu-user to the dev shell, pinned like the rest of it.
- Add one `just` recipe that runs armv7 `clippy --all-targets` and the tests
  under qemu with `QEMU_CPU=max` and the Cortex-A15, matching `build.yml`.
  Have `build.yml` call that recipe, so CI and local runs can't drift.
