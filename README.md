<h1 align="center">rind</h1>
<img width="40%" align="right" src="https://raw.githubusercontent.com/moq-dev/rind/main/admin/picture.png">

> **rind** is a compendium of **high quality**,
> **fast** and **easy to build** cryptography for Rust, aimed
> at use with [rustls](https://github.com/rustls/rustls) and
> [MoQ](https://github.com/moq-dev/moq).

rind is a fork of [Graviola](https://github.com/ctz/graviola) by Joe
Birr-Pixton. It keeps Graviola's history so changes can be rebased or offered
upstream, and adds what MoQ needs to drop C cryptography entirely; the plan
lives in [`quest/`](quest/README.md).

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
  `armv7-linux-androideabi`) runs [libcrux]'s verified portable Rust instead,
  with P-384 over [fiat-crypto]'s, and needs no CPU features. An Ed25519
  public key that is not a curve point is refused when verifying rather than
  when decoding.

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

## Acknowledgements and Thanks

rind incorporates significant code from other open source projects.
We are grateful to:

- [s2n-bignum]: formally verified assembler for
    - P256, P384, P521 field arithmetic and group operations
    - x25519
    - ML-KEM-768 underlying arithmetic
    - SHA-3 Keccak-f
    - Big integer arithmetic
- [wycheproof]: collated test vectors for all algorithms.
- [libcrux]: formally verified portable Rust (from HACL\*) for the 32-bit
  `arm` backend.
- [fiat-crypto]: formally verified P-384 field arithmetic for the 32-bit `arm`
  backend.

[s2n-bignum]: https://github.com/awslabs/s2n-bignum
[wycheproof]: https://github.com/C2SP/wycheproof
[libcrux]: https://github.com/cryspen/libcrux
[fiat-crypto]: https://github.com/mit-plv/fiat-crypto
[SLOTHY]: https://github.com/slothy-optimizer/slothy
[performance]: https://jbp.io/rind/
[rind-rustls]: https://crates.io/crates/rind-rustls

## Algorithms

### Public key signatures

- [x] RSA-PSS signature verification
- [x] RSA-PKCS#1 signature verification
- [x] RSA-PSS signing
- [x] RSA-PKCS#1 signing
- [x] ECDSA on P256 w/ SHA2
- [x] ECDSA on P384 w/ SHA2
- [x] Ed25519

### Hashing

- [x] SHA1, for legacy protocols only (not usable for signatures)
- [x] SHA256
- [x] SHA384 & SHA512
- [x] HMAC
- [x] HKDF
- [x] HMAC-DRBG

### Key exchange

- [x] X25519
- [x] P256
- [x] P384
- [x] ML-KEM-768

### AEADs

- [x] AES-GCM
- [x] chacha20-poly1305 and xchacha20-poly1305

### Unauthenticated ciphers

- [x] AES block encryption, for QUIC header protection and DTLS 1.3 record number protection
- [x] AES-CTR, for SRTP
- [x] ChaCha20, for QUIC header protection and DTLS 1.3 record number protection

## Assorted technical details

### RSA
All the arithmetic is provided by s2n-bignum.

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
All ECC field and scalar arithmetic are provided by s2n-bignum.

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
The core polynomial arithmetic -- the NTT, inverse NTT, base multiplication
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
SHA256, as aws-lc does. 32-bit `arm` always runs the pure
Rust SHA1, SHA256, and SHA512: libcrux has no SHA1, and the pure Rust SHA256
is faster than libcrux's.

SHA384/SHA512 on x86_64 has an AVX2 by-4 implementation, plus an AVX2 interleaved
single block implementation.

AES and GHASH always use intrinsics (there are no fallbacks).

On x86_64, we have a stitched by-8 AES-CTR and a by-8 GHASH (they are not currently
interleaved; this is future work.)  There is also an optional AVX-512 by-16 AES-CTR
and GHASH.  It uses dynamic CPU feature detection, so AVX-512 is not required at runtime.

On aarch64 we have a stitched by-8 AES-CTR and by-8 GHASH (not currently interleaved).

## Architecture

We have broadly three module layers:

- `low`: low level primitives. private. platform-specific. unsafe allowed. minimal std and alloc.
- `mid`: constructions, protocols and encodings. private. platform agnostic. no unsafe. minimal std and alloc.
- `high`: high level encodings and operations. public. platform agnostic. no unsafe.

`low` code should not refer to `mid`, nor `mid` to `high`.

`low` must present the same interface irrespective of platform.  To this end,
`low::generic` contains pure-rust polyfills for items we don't have assembler-
or intrinsic-based implementations for a certain platform.

## License

rind incorporates and redistributes code from:

- [Graviola](https://github.com/ctz/graviola): Apache-2.0 OR ISC OR MIT-0
- [s2n-bignum]: Apache-2.0 OR ISC OR MIT-0

New code written for rind is licensed under
Apache-2.0 OR ISC OR MIT-0.

Every file has a `SPDX-License-Identifier` comment.
