# [S] Check in-place kernels on every s2n-bignum bump

## Goal

A bump of `thirdparty/s2n-bignum` fails CI if an AES-GCM kernel rind runs in
place stops loading each input block before storing its output, reads outside
its buffers, or branches or addresses memory on anything but the length.

## Plan

Decided by the maintainer on 2026-10-30, from the follow-ups of
[moq-dev/rind#110](https://github.com/moq-dev/rind/pull/110) and
[moq-dev/rind#114](https://github.com/moq-dev/rind/pull/114). Both PRs ran
the aarch64 AES-GCM kernels in place, outside s2n-bignum's proofs, and
checked them with an instruction walker kept only in their PR bodies. Today a
bump re-runs only `aes_gcm_every_length`.

- Commit the walker beside `admin/parse-asm`, run it over every kernel rind
  runs in place, and run it in the lints workflow's codegen job.
- Keep its planted-fault self-test, so a walker that stops checking fails too.
