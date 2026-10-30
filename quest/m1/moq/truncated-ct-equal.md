# [XS] Truncated hash comparison never panics

## Goal

`HashOutput::truncated_ct_equal` never panics on caller input. Today it
asserts that `L` is non-zero and no longer than the digest; instead an `L` of 0
or past the digest length is refused, through the type system or a `Result`.

## Plan

Decided by the maintainer on 2026-10-29, from the review of
[kixelated/rind#39](https://github.com/kixelated/rind/pull/39): rind never
panics on caller input, it makes misuse unrepresentable in the types or
returns an error.

- Prefer a compile-time refusal if one reads cleanly at the call sites;
  otherwise return a `Result`.
- Breaking: a public signature change, so the PR title carries `!`.
