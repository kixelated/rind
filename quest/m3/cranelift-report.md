# [XS] Report cranelift's aarch64 crash

## Goal

Cranelift's crash on aarch64 compiling a one-line `rind-rcgen` doc example is
reported upstream with a minimal reproduction, and the doc example stops being
compile-only once a fix ships.

## Plan

Planned by the maintainer on 2026-10-28, from the follow-ups of the m1 PRs. Deferred to m3 (maintainer, 2026-10-28), until MoQ runs on rind.
[kixelated/rind#10](https://github.com/kixelated/rind/pull/10) made the
example compile-only to avoid it.

- Reduce it to a reproduction without rind if possible, and check the
  rustc_codegen_cranelift issues for an existing report first.
- Ask the maintainer before filing.

## Required

- [MoQ runs on rind](/quest/m3/moq-on-rind.md) - deferred until then
