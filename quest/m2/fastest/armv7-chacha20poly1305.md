# [M] armv7 ChaCha20-Poly1305 from the fastest source

## Goal

armv7 ChaCha20-Poly1305 and XChaCha20-Poly1305 run the fastest source
available. Since [moq-dev/rind#92](https://github.com/moq-dev/rind/pull/92),
rind-rustls and rind-dimpl prefer ChaCha20-Poly1305 on armv7 cores without
AES hardware, so this is their bulk cipher there.

## Plan

Today the cell runs HACL*'s verified ChaCha20 block function and Poly1305
under rind's keystream loop and Graviola's AEAD composition. Seal on the bench
runner (Neoverse-N2 running the armv7 build; bench run 41141591842 and
bench-tmp runs 41147916836 and 41151132431):

| | 32B | 1200B | 2KB | 16KB |
|---|---|---|---|---|
| rind (today) | 0.65-0.72 µs | 5.68 µs | 9.38 µs | 70.8 µs |
| libcrux's HACL\* AEAD, whole | 0.45 µs | 4.25 µs | | 53.4 µs |
| RustCrypto `chacha20poly1305` | 0.40 µs | | 7.27 µs | 55.9 µs |
| aws-lc-rs (aws-lc's NEON `chacha-armv4` and `poly1305-armv4`) | 0.63 µs | | 3.46 µs | 23.9 µs |

aws-lc's NEON assembly is unverified and about 3x faster from 2KB up; the cell
would become ⚡. RustCrypto's pure Rust leads at 32B, so check short messages
too. Most armv7 cores without the crypto extension (Pi 4, CM4,
Zero 2 W) have NEON, but check the target cores do before relying on it, and
keep the portable path for any that do not.

`rind::cipher::ChaCha20` shares the keystream loop, so it moves with the AEAD.

`admin/import-aws-lc` already imports aws-lc's AArch32 assembly the same
way, so this extends it with `chacha-armv4` and `poly1305-armv4`.

If aws-lc's code is ruled out, HACL*'s own `chacha20_encrypt` is about 1.3x
faster than rind's keystream loop over its block function; libcrux keeps it
private (see [libcrux exports its raw ciphers](/quest/m3/libcrux-ciphers-exported.md)).
libcrux's whole AEAD was dropped in
[moq-dev/rind#36](https://github.com/moq-dev/rind/pull/36) for a non-constant-time
tag comparison, so it is not a candidate as is.
