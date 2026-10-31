# [S] x86_64 AES-GCM tail after 256-byte chunks

## Goal

On x86_64's AVX-512 AES-GCM path, a 1200-byte QUIC packet costs no more per
byte than a 2 KB message.

## Plan

Decided by the maintainer on 2026-10-30, from the follow-ups of
[moq-dev/rind#109](https://github.com/moq-dev/rind/pull/109): the AVX-512
path encrypts what is left after its 256-byte chunks one block at a time, so
on Zen 4 a 1200 B seal (357 ns) is slower than a 2 KB one (316 ns).

- Handle the tail with narrower vectors rather than single blocks, and check
  the AVX2 path for the same pattern.
- Measure at 1200 B and the sizes around it on the hosted AVX-512 runners.
- If [the VAES kernel](/quest/m2/fastest/x86-aes-gcm-vaes.md) lands first and
  replaces this path, delete this quest instead.
