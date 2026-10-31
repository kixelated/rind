# [S] aarch64 AES-256-GCM on s2n-bignum's `_alt` kernels

## Goal

On aarch64 cores with the SHA3 extension, AES-256-GCM runs s2n-bignum's
`aes256_gcm_enc_alt` and `aes256_gcm_dec_alt` kernels in place, 7-11% faster
than the kernels it runs today.

## Plan

From the follow-ups of
[moq-dev/rind#110](https://github.com/moq-dev/rind/pull/110), which measured
the `_alt` kernels in place on Neoverse-N2 (bench run 41160351946): AES-256
seal at 87/434/640/2220/4330 ns for 32 B/1200 B/2 KB/8 KB/16 KB, against
98/471/693/2380/4650 ns for the current kernels.

- They need the SHA3 extension (`EOR3`). Decide the kernel once at key setup
  from detection, as #84 does on armv7, and keep the current kernels for cores
  without it. `cpu::check()` does not start requiring SHA3.
- They use a larger GHASH key table, and `admin/parse-asm` needs to handle
  kernels with several exit points.
- They run in place outside their proofs, like the current kernels, so repeat
  #110's mechanical load-before-store check for them and keep its
  every-length crosscheck.
- Re-measure on one head with the `bench` workflow before switching.
