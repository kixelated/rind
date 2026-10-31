# [S] aarch64 AES-GCM without the stack copy

## Goal

aarch64 AES-GCM stops copying its input to a stack buffer, if that is the
fastest option, and the README's aarch64 AES-GCM cell marks s2n-bignum's
CTR and GHASH kernels ⚡ rather than ✓, since in place they run outside their
proof.

## Plan

The copy exists so the kernels run inside their proof, whose precondition
excludes in-place operation.
[moq-dev/rind#86](https://github.com/moq-dev/rind/pull/86) measured seal on
the bench runner (Neoverse-N2, run 41118157837), ns:

| | 32B | 2KB | 8KB | 16KB |
|---|---|---|---|---|
| AES-128: stack copy (today) | 100 | 647 | 2225 | 4344 |
| AES-128: kernels in place | 93 | 602 | 2035 | 3960 |
| AES-128: Graviola (before #86) | 78 | 624 | 2161 | 4233 |
| AES-256: stack copy (today) | 104 | 717 | 2562 | 5031 |
| AES-256: kernels in place | 96 | 677 | 2381 | 4657 |
| AES-256: Graviola (before #86) | 83 | 705 | 2539 | 4988 |

In place is 7-9% faster than today from 2KB up. At 32B, Graviola's old path
was faster still, by about 15 ns. Re-measure all three on one head, adding the
QUIC size (about 1200B), and decide whether in place alone wins or a short
message is worth a second path.

Before relying on the kernels in place, check from their source that each
block's input is loaded before its output is stored, and test in-place seal
and open around the kernels' 4-block stride: CAVP, Wycheproof, and the aws-lc-rs
cross-check only cover the lengths they happen to use.

The `_alt` AES-256 kernels (FEAT_SHA3, 8-way) are verified too and were never
measured; time them in the same run.

If s2n-bignum later proves the kernels with `out == in`, the cell returns to
✓ at no cost.
