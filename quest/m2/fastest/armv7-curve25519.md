# [M] armv7 X25519 ladder on NEON

## Goal

On an armv7 CPU with NEON, X25519's variable-base multiplication runs
BoringSSL's NEON assembly, or this quest records that the saving does not
matter and is deleted. Today armv7 X25519 runs curve25519-dalek's serial
32-bit backend for both the public key and the shared secret.

## Plan

On the bench runner (Neoverse-N2 running the armv7 build, run
[41162858124](https://github.com/moq-dev/rind/actions/runs/41162858124)),
x25519-ecdh (key generation plus agreement) took 185.9 µs on dalek and
161.4 µs on ring, which runs BoringSSL's `x25519-asm-arm.S` (SUPERCOP's
`neon2`, unverified) for both multiplications. aws-lc dropped that file, so
`admin/import-aws-lc-arm` has nothing to import; take it from BoringSSL or
ring instead, and add the source to README and LICENSE.

- Keep dalek's precomputed-table multiplication for the public key if it
  beats the NEON ladder there, and measure the split: dalek's Ed25519 key
  generation, mostly the same base multiplication, took 48.1 µs.
- Decide NEON once per process from `AT_HWCAP`, as the crypto extension is,
  with dalek as the path for CPUs without it.
- The ladder handles a secret scalar: cover it with a ctgrind test and the
  existing Wycheproof and aws-lc-rs X25519 tests on both paths.
