<h1 align="center">rind</h1>
<img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/picture.png">

> **rind** is a compendium of **high quality**,
> **fast** and **easy to build** cryptography for Rust, aimed
> at use with [rustls](https://github.com/rustls/rustls) and
> [MoQ](https://github.com/moq-dev/moq).

rind began as a fork of [Graviola](https://github.com/ctz/graviola) by Joe
Birr-Pixton, and no longer tracks it. It adds what MoQ needs to drop C
cryptography entirely; the plan lives in [`quest/`](quest/README.md).

*High quality*: rind incorporates assembler routines
from the [s2n-bignum] project.  These have been formally proven
to correctly implement the desired mathematical operation.

*Fast*: rind beats or is competitive with other cryptography
libraries for Rust.  See [performance comparison][performance].

*Easy and fast to build*: no C compiler, assembler or other tooling
needed: just the Rust compiler.  Compiles in less than one second.

## Status

This project is very new, so exercise due caution.  The overriding
goal of this crate is for use with `rustls` via [rind-rustls][],
but there is also a public API for general-purpose use.

[![Build Status](https://img.shields.io/github/actions/workflow/status/moq-dev/rind/build.yml)](https://github.com/moq-dev/rind/actions/workflows/build.yml?query=branch%3Amain)
[![Latest release](https://img.shields.io/crates/v/rind)](https://crates.io/crates/rind)
[![Documentation](https://img.shields.io/docsrs/rind)](https://docs.rs/rind/)

## Goals

- [x] Fast and simple compilation
    - [x] `cargo build` takes less than one second, and requires only rustc
- [x] Competitive performance (with *ring*, aws-lc-rs, and rustcrypto)
- [x] Uses formally-verified assembler from other projects (where available)
- [x] Intended to provide algorithms in wide use on web
- [x] Intended for use as a rustls `CryptoProvider`, via [rind-rustls][].

## Limitations

`aarch64`, `x86_64`, and 32-bit `arm` architectures only.

- `aarch64` requires `aes`, `sha2`, `pmull`, and `neon` CPU features.
  (This notably excludes Raspberry PI 4 and earlier, which can run the 32-bit
  `arm` build, but covers Raspberry Pi 5.)
- `x86_64` requires `aes`, `ssse3`, `popcnt`, `avx`, `avx2`, `adx`, `bmi2`, and `pclmulqdq` CPU features.
  (This is most x86_64 CPUs made since around ~2014.)
- 32-bit `arm` (tested on `armv7-unknown-linux-gnueabihf`, and built for
  `armv7-linux-androideabi`) runs portable Rust instead, mostly from
  [libcrux] (see [Algorithms](#algorithms)), and needs no CPU features. Where
  the CPU has the ARMv8 crypto extension, as most 32-bit Android devices do,
  AES, GHASH, SHA1, and SHA256 run [aws-lc]'s assembly for it instead.
  Without it, `rind::cpu::has_aes_hardware()` is false, and rind-rustls and
  rind-dimpl prefer ChaCha20-Poly1305, which is faster there. An
  Ed25519 public key that is not a curve point is refused when verifying
  rather than when decoding.

Every operation panics on a CPU missing one of these. Call `rind::cpu::check()`
at startup to get an error naming the missing feature instead.

## Building and Testing

Compile:
```shell
cargo build --release
```

Run tests:
```shell
git submodule update --init thirdparty/cavp
git submodule update --init thirdparty/wycheproof
cargo test
```

Run performance benchmarks:
```shell
cargo bench
```

With [Nix](https://nixos.org), `nix develop` (or direnv) provides CI's
toolchain, and `just check` runs CI's gate over what the branch changed.

## Algorithms

Each cell names whose code runs for that algorithm on that backend: the
[sources](#sources) below, rind's own code, or Graviola's own Rust and
intrinsics. A ✓ marks code its source formally verifies, to the extent
[Sources](#sources) states; everything else is unverified. The table
describes `main`, and changes alongside the code it describes.

| Algorithm | x86_64 | aarch64 | armv7 |
|---|---|---|---|
| AES-128-GCM, AES-256-GCM | Graviola | Graviola | crypto extension: [aws-lc] AES and GHASH (copied), rind GCM; otherwise: [libcrux-aes] |
| AES block (header protection), AES-CTR (SRTP) | Graviola block, rind CTR | Graviola block, rind CTR | crypto extension: [aws-lc] block and CTR (copied); otherwise: [libcrux-aes] block (copied), rind CTR |
| ChaCha20 (header protection) | Graviola | Graviola | [HACL\*] block function ✓ (copied), rind keystream |
| ChaCha20-Poly1305, XChaCha20-Poly1305 | Graviola | Graviola | [HACL\*] ChaCha20 block function and Poly1305 ✓; Graviola AEAD; rind HChaCha20 |
| SHA-1 (legacy only) | rind | rind | crypto extension: [aws-lc] (copied); otherwise: rind |
| SHA-256, SHA-384, SHA-512 | Graviola | Graviola | crypto extension: [aws-lc] SHA-256 (copied); otherwise: Graviola SHA-256; Graviola SHA-384 and SHA-512 |
| HMAC | Graviola | Graviola | Graviola |
| HKDF | rind | rind | rind |
| X25519 | [s2n-bignum] ✓ | [s2n-bignum] ✓ | [HACL\*] ✓ |
| Ed25519 | [s2n-bignum] point and scalar arithmetic ✓; Graviola EdDSA and SHA-512 | [s2n-bignum] point and scalar arithmetic ✓; Graviola EdDSA and SHA-512 | [HACL\*] ✓ |
| P-256 ECDH, ECDSA | [s2n-bignum] field and point arithmetic ✓; Graviola scalar multiplication, table lookup, and ECDSA | [s2n-bignum] field and point arithmetic ✓; Graviola scalar multiplication, table lookup, and ECDSA | [HACL\*] ✓; Graviola ECDSA nonce |
| P-384 ECDH, ECDSA | [s2n-bignum] field and point arithmetic ✓; Graviola scalar multiplication, table lookup, and ECDSA | [s2n-bignum] field and point arithmetic ✓; Graviola scalar multiplication, table lookup, and ECDSA | [fiat-crypto] field and scalar arithmetic ✓; rind point formulas, inversion, and table lookup; Graviola scalar multiplication and ECDSA |
| ML-KEM-768 | [s2n-bignum] polynomial arithmetic and Keccak-f ✓; Graviola FIPS 203 and AVX-512 sampling | [s2n-bignum] polynomial arithmetic and Keccak-f ✓; Graviola FIPS 203 | [libcrux-ml-kem] ✓, except its SHA-3 |
| RSA PKCS#1 v1.5 and PSS signatures, key generation | [s2n-bignum] bignum arithmetic ✓; Graviola exponentiation, CRT, padding, and key generation | [s2n-bignum] bignum arithmetic ✓; Graviola exponentiation, CRT, padding, and key generation | [HACL\*] bignum arithmetic and exponentiation ✓; rind CRT and key generation; Graviola padding |

The tests use [Wycheproof]'s vectors.

### Sources

| Source | How rind uses it | License | What is verified |
|---|---|---|---|
| [Graviola] | copied: rind began as a copy of it, and rind-rustls of its rustls-graviola; its aarch64 ChaCha20 and its Poly1305 began as [cifra], CC0-1.0 | Apache-2.0 OR ISC OR MIT-0 | nothing |
| rind | its own code | Apache-2.0 OR ISC OR MIT-0 | nothing |
| [s2n-bignum] | copied: its assembly, transliterated into Rust `asm!` by `admin/parse-asm` | Apache-2.0 OR ISC OR MIT-0; its ML-KEM and aarch64 Keccak-f routines (from mlkem-native) Apache-2.0 OR ISC OR MIT; its x86_64 Keccak-f (from OpenSSL) Apache-2.0 | HOL Light proofs ([x86_64](https://github.com/awslabs/s2n-bignum/tree/main/x86/proofs), [aarch64](https://github.com/awslabs/s2n-bignum/tree/main/arm/proofs)) that each routine's object code computes its specified result for all inputs. They check s2n-bignum's own build, not rind's transliteration, and do not cover memory safety. |
| [HACL\*] | dependency, through libcrux-hacl-rs, libcrux-p256, libcrux-ed25519, and libcrux-poly1305; copied: the ChaCha20 block function, from libcrux-chacha20poly1305 | Apache-2.0 | [F\* proofs](https://github.com/hacl-star/hacl-star) of memory safety, functional correctness, and secret independence of the F\* source. libcrux's Rust is compiled mechanically from HACL\*'s verified C, and that step is not itself verified. |
| [libcrux-ml-kem] | dependency | Apache-2.0 | [hax and F\* proofs](https://github.com/cryspen/libcrux/blob/main/libcrux-ml-kem/proofs/verification_status.md) of panic freedom and functional correctness for its portable arithmetic, NTT, serialization, and high-level code. Its SHA-3, from libcrux-sha3, is unverified. |
| [libcrux-aes] | dependency for AES-GCM; copied: the block cipher | Apache-2.0 | nothing: libcrux marks it pre-verification |
| [aws-lc] | copied: its 32-bit ARM assembly for the ARMv8 crypto extension (AES, GHASH, SHA-1, SHA-256), which aws-lc takes from OpenSSL, imported into Rust `global_asm!` by `admin/import-aws-lc-arm` | Apache-2.0 | nothing: aws-lc's proofs cover its x86_64 and aarch64 code, not this |
| [fiat-crypto] | dependency | MIT OR Apache-2.0 OR BSD-1-Clause | [Coq proofs](https://github.com/mit-plv/fiat-crypto) that each generated field operation is correct. rind's point formulas, inversion, and table lookup over them are not covered. |

rind's own code is licensed under Apache-2.0 OR ISC OR MIT-0. Copied code
keeps its source's copyright and license, which [LICENSE] lists with the
texts they require; dependencies ship their own. Every file under
`rind/src` names its license in a `SPDX-License-Identifier` comment, and
files Graviola wrote keep their `Written for Graviola by ...` header. The
`rind` crate as a whole is therefore `(Apache-2.0 OR ISC OR MIT-0) AND
(Apache-2.0 OR ISC OR MIT) AND Apache-2.0`. The adapter crates copy
nothing under another license, so they stay `Apache-2.0 OR ISC OR MIT-0`.

A change that copies code from a new source, or moves an algorithm to a
different one, updates this table and [LICENSE] in the same PR.

[Graviola]: https://github.com/ctz/graviola
[cifra]: https://github.com/ctz/cifra
[s2n-bignum]: https://github.com/awslabs/s2n-bignum
[HACL\*]: https://github.com/hacl-star/hacl-star
[libcrux-ml-kem]: https://github.com/cryspen/libcrux/tree/main/libcrux-ml-kem
[libcrux-aes]: https://github.com/cryspen/libcrux/tree/main/crates/algorithms/aes
[libcrux]: https://github.com/cryspen/libcrux
[aws-lc]: https://github.com/aws/aws-lc
[fiat-crypto]: https://github.com/mit-plv/fiat-crypto
[Wycheproof]: https://github.com/C2SP/wycheproof
[LICENSE]: https://github.com/moq-dev/rind/blob/main/LICENSE
[performance]: https://jbp.io/rind/
[rind-rustls]: https://crates.io/crates/rind-rustls

## Assorted technical details

### RSA
On x86_64 and aarch64, all the arithmetic is provided by s2n-bignum, under the
exponentiation described below; armv7 uses HACL\*'s arithmetic and
exponentiation instead.

The RSA private operation always uses the CRT optimisation.

Modular exponentiation uses 4-bit fixed exponent window, and the term is selected by
the exponent bits from the table of base powers in a side-channel-free way.
The private operation is always followed by the public operation to verify the result
(and the result compared in a side-channel-free way).

Only RSA signing and verification are provided.  Our policy on RSA encryption is:
"These are not made. They should never be made. We will not make them. We will not help make them."

RSA key generation is supported for five fixed key sizes between 2048-8192-bits.
All generated keys have e = 0x10001.  Unlike other private key operations in rind,
RSA key generation is currently not side-channel safe.  Avoid doing it in untrusted multi-tenant or
physical environments.

### ECC
On x86_64 and aarch64, all ECC field and scalar arithmetic are provided by
s2n-bignum, and the rest of this section describes those backends.

P256 base point multiplication uses a 7-bit exponent window with Booth encoding
(this costs a 148KB constant table).
Variable point multiplication uses a 5-bit exponent window with Booth encoding.

P384 base and variable point multiplication both use a 5-bit exponent window with Booth encoding.
(This means we're leaving a some P384 base point performance on the table, in exchange for code space.
P384 performance seems to be less important than P256.)

Both use the same exponent representations for "public" and "secret" exponents --
however the table selection for "public" exponents is specialized at compile-time.

ECDSA follows RFC6979 for generation of `k`, but adds additional non-critical random input.
We do this to avoid the theoretical fragility of RFC6979 under fault conditions.
This is allowed for by RFC6979, and the HMAC-DRBG that it builds on.
The code is structured such that we pass the RFC6979 test vectors.

The code which selects a term from a table of points is non-verified,
and is written in AVX2/Neon intrinsics.

X25519 directly uses the s2n-bignum implementation.

### ML-KEM-768
On x86_64 and aarch64, the core polynomial arithmetic -- the NTT, inverse NTT, base multiplication
and reduction -- is provided by s2n-bignum (contributed by the mlkem-native
developers).  The surrounding FIPS-203 construction (key generation,
encapsulation and decapsulation) is written in Rust.

Compression and decompression are division-free, avoiding the variable-time
division behind the KyberSlash attacks.

For sampling, which is a significant factor in ML-KEM performance, we
have some different options depending on CPU features:

- We have a `SampleNTT()` which does 8-wide Keccak-f permutation followed by
  rejection sampling using AVX-512 (F, BW, VBMI, VBMI2) on x86-64.
- We have a 4-wide Keccak-f using AVX2 on x86-64.
- We have a 2-wide Keccak-f using Neon+SHA3 on aarch64.
- We have a basic Keccak-f using scalar instructions on aarch64.

### Symmetric cryptography
SHA1 and SHA256 have straightforward implementations using hashing intrinsics
(aka "SHA-NI" on x86_64, "sha" extension on aarch64). Without SHA-NI, x86_64
selects at runtime an AVX2 message schedule with scalar rounds for SHA1 and
SHA256, as aws-lc does. 32-bit `arm` runs aws-lc's SHA1 and SHA256 assembly
where the CPU has the crypto extension, and the pure Rust SHA1 and SHA256
otherwise: libcrux has no SHA1, and the pure Rust SHA256 is faster than
libcrux's. Its SHA512 is always the pure Rust one.

SHA384/SHA512 on x86_64 has an AVX2 by-4 implementation, plus an AVX2 interleaved
single block implementation.

On x86_64 and aarch64, AES and GHASH always use intrinsics (there are no fallbacks).

On x86_64, we have a stitched by-8 AES-CTR and a by-8 GHASH (they are not currently
interleaved; this is future work.)  There is also an optional AVX-512 by-16 AES-CTR
and GHASH.  It uses dynamic CPU feature detection, so AVX-512 is not required at runtime.

On aarch64 we have a stitched by-8 AES-CTR and by-8 GHASH (not currently interleaved).

32-bit `arm` decides once per process from `AT_HWCAP2`: with the crypto
extension, AES and AES-GCM keys use aws-lc's `aesv8-armx` and `ghashv8-armx`
assembly, composed as aws-lc does on that architecture; without it, libcrux's
bitsliced AES and AES-GCM.

## Architecture

We have broadly three module layers:

- `low`: low level primitives. private. platform-specific. unsafe allowed. minimal std and alloc.
- `mid`: constructions, protocols and encodings. private. platform agnostic. no unsafe. minimal std and alloc.
- `high`: high level encodings and operations. public. platform agnostic. no unsafe.

`low` code should not refer to `mid`, nor `mid` to `high`.

`low` must present the same interface irrespective of platform.  To this end,
`low::generic` contains pure-rust polyfills for items we don't have assembler-
or intrinsic-based implementations for a certain platform.
