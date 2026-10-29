# m1: MoQ coverage

## Goal

rind carries everything [MoQ](https://github.com/moq-dev/moq) needs to take
all its cryptography from rind, on every target MoQ releases, and publishes it.

## Required

- [rind covers MoQ](/quest/m1/moq/README.md) - the primitives, CPU check, armv7 backend, and `rind-*` adapters MoQ needs, verified and released
- [CI checks out only the test vectors](/quest/m1/ci-vector-checkout.md) - no job clones s2n-bignum
- [Merge quest link lists locally](/quest/m1/merge-driver.md) - `.gitattributes` uses quest's merge driver
