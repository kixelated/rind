# [M] x86_64 AES-GCM at aws-lc's speed

## Goal

x86_64 AES-GCM runs the fastest source available for it. Today that cell is
Graviola's by-8 AES-CTR and GHASH (plus an AVX-512 by-16 path), which
aws-lc's x86_64 AES-GCM beats by 1.3-1.5x from 2KB up on a CPU without VAES.

## Plan

Seal, criterion medians, rind against aws-lc-rs in the same run:

| | 32B | 2KB | 8KB | 16KB |
|---|---|---|---|---|
| i7-8700 (AVX2, no VAES or AVX-512), AES-128: rind / aws-lc-rs | 76 / 88 ns | 571 / 434 ns | 2.04 / 1.37 µs | 4.03 / 2.68 µs |
| i7-8700, AES-256 | 82 / 95 ns | 684 / 548 ns | 2.50 / 1.81 µs | 4.98 / 3.53 µs |
| EPYC 7763 (VAES, no AVX-512), AES-128 | 97 / 147 ns | 607 / 668 ns | 2.15 / 2.19 µs | 9.36 / 9.42 µs |
| EPYC 7763, AES-256 | 106 / 158 ns | 694 / 723 ns | 2.48 / 2.35 µs | 10.0 / 9.68 µs |

The i7-8700 numbers are from a local run, the EPYC ones from the bench
workflow (run 41147916836). So aws-lc wins where it runs its AES-NI/AVX code
and ties where it runs VAES; rind wins at 32B on both.

aws-lc's pre-AVX-512 x86_64 AES-GCM is also what
[aws-lc-verification](https://github.com/awslabs/aws-lc-verification) proves
with SAW, for AES-256 with 12-byte nonces and whole-block updates, not the
AAD. Find which routine that is, and whether it is the one aws-lc-rs ran on the
i7-8700: if so, adopting it would also make part of this cell verified.

Open questions:

- Which routines to import. `admin/import-aws-lc` already brings x86_64
  routines in as naked functions over aws-lc's pregenerated text, as it does
  SHA-512; check that AES-GCM's fit that shape, such as routines that call
  each other.
- Whether Graviola's AVX-512 path stays: measure it against aws-lc's on an
  AVX-512 host.
- Short messages, where rind leads: measure about 1200B (QUIC) before
  replacing the whole path.
