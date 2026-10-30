# [S] ctgrind on Keccak's SHA3 path

## Goal

ctgrind checks the aarch64 Keccak routine that uses the SHA3 instructions,
not only its scalar fallback.

## Plan

Decided by the maintainer on 2026-10-29, from the follow-ups of
[moq-dev/rind#44](https://github.com/moq-dev/rind/pull/44): valgrind 3.22
hides the SHA3 CPU feature (`AT_HWCAP 0x1fb`), so under ctgrind Keccak runs
its scalar code. m2: low risk, since the routine is verified straight-line
assembly.

- Check whether a newer valgrind supports the SHA3 instructions and exposes
  the feature, and use it in the aarch64 ctgrind job if so.
- If none does, record that and delete this quest.
