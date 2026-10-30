# [XS] Vector registers match aws-lc

## Goal

rind stops clearing vector registers after secret operations, which graviola
does (`vzeroall` in `low/x86_64/cpu.rs`, NEON zeroing in `low/aarch64/cpu.rs`)
and aws-lc does not, unless a benchmark shows `vzeroall` is needed anyway.

## Plan

Decided by the maintainer on 2026-10-30, from the follow-ups of
[moq-dev/rind#73](https://github.com/moq-dev/rind/pull/73), under the
`AGENTS.md` zeroing rule.

- On x86_64, `vzeroall` (or `vzeroupper`) also avoids AVX-to-SSE transition
  stalls. Benchmark before removing it, and keep a `vzeroupper` if the
  stalls show; that would be for speed, not for wiping.
