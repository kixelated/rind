# [M] P-256 and P-384 scalar multiplication from s2n-bignum

## Goal

On x86_64 and aarch64, P-256 and P-384 scalar multiplication run
s2n-bignum's verified routines wherever they are as fast as Graviola's
windowed multiplication and table lookup, per `AGENTS.md`. The measurements
below say they are, except for P-384's generator, where rind's comb is about
4x faster.

## Plan

s2n-bignum ships verified, constant-time `p256_scalarmul` (affine in and out,
including the Montgomery conversions and final inversion),
`p256_scalarmulbase` (over a caller-built table, block size 4-6), and
`p256_montjscalarmul`/`p384_montjscalarmul` (Jacobian, Montgomery form), each
with an `_alt` variant without MULX/ADX-style instructions. rind imports none of
them. Times from s2n-bignum's own benchmark (`benchmarks/benchmark.c`, at rind's
pinned 9f2cd960) against rind's `rind-bench` on the same host; rind's variable
multiplication is its ECDH minus its key generation, so it also includes
decoding and validating the peer's point:

| host | P-256 variable: rind / s2n best | P-256 generator: rind keygen / s2n `scalarmulbase` best | P-384 variable: rind / s2n `montjscalarmul` best + inversion |
|---|---|---|---|
| i7-8700 (local) | 37.7 / 35.2 µs | 8.5 / 7.6 µs | 121.4 / 119.8 µs |
| EPYC 7763 (run 41147916836) | 52.2 / 48.8 µs | 12.1 / 10.8 µs | P384_EPYC |
| Neoverse-N2 (run 41147916836) | 47.7 / 45.1 µs | 12.8 / 10.4 µs | 156.9 / 153.4 µs |

rind's key generation also draws the scalar from the OS RNG, so the generator
column flatters s2n-bignum by that much. Both variable columns are within about
7%, s2n-bignum ahead on P-256 and level on P-384. Re-measure inside rind,
calling both through the same `mid` path, before switching: the subtraction
above is good enough to show they are as fast, not to rank them.

P-384's generator stays on rind's comb from
[moq-dev/rind#102](https://github.com/moq-dev/rind/pull/102): 30-40 µs
against about 120-155 µs for the only verified alternative, a variable
multiplication by G.

Things to settle:

- `p256_scalarmulbase` needs a table in its own layout; rind's 148 KB
  7-bit table may not fit it, so compare sizes and pick the block size.
- Which of the plain and `_alt` variants each backend runs (the `_alt` ones
  won on Neoverse-N2, the plain ones on x86_64), chosen once from CPU
  features.
- ECDSA verification multiplies public scalars, and Graviola specialises its
  table selection for that; s2n-bignum's routines are constant time
  throughout, so measure verification separately and keep Graviola's path
  there if it is faster (marking it ⚡).
- Then delete the Graviola scalar multiplication and table lookup this
  replaces, and update the README cells.
