# rind covers MoQ

## Goal

A rind release on crates.io carries everything
[MoQ](https://github.com/moq-dev/moq) needs to take all its cryptography from
rind, so no MoQ build compiles C crypto: the new primitives, the CPU check, the
armv7 backend, and every `rind-*` adapter. Each adapter's operations pass
rind's tests on x86_64, aarch64, and armv7 alike; an operation missing on one
arch does not count as covered.

MoQ's side waits on this epic:
[moq-dev/moq `quest/m2/rind/covered.md`](https://github.com/moq-dev/moq/blob/main/quest/m2/rind/covered.md)
checks this directory for remaining quests and crates.io for the release.

## Plan

Decided with the maintainer on 2026-10-26 and 2026-10-27, in MoQ's planning
interview and its rind bootstrap. These are settled; don't ask them again.

Why rind exists: MoQ moves every crate off aws-lc-rs, ring, and the RustCrypto
`hmac`/`sha1`/`sha2`/`p256`/`p384` crates so no build compiles C, including
armv7 Android. Upstream graviola lacks primitives MoQ needs and runs only on
x86_64 and aarch64, so rind owns those gaps. MoQ uses rind's own API plus its
adapter crates, never a ring facade through `[patch.crates-io]`, so a published
crate built with `cargo install` also compiles no C.

Repo:

- A GitHub fork, keeping graviola's history for a later rebase or upstreaming.
  Fork only: no upstream PRs until rind carries MoQ, then revisit
  ([Revisit upstreaming](/quest/m3/upstream.md)).
- Adapters are separate crates named `rind-<consumer>`, so a third-party major
  bump never forces a rind major bump. The prefix keeps them grouped under
  rind's own name rather than borrowing the consumer's.

Targets, refused rather than falling back:

- Exactly one backend compiles per arch, never both in one binary
  (maintainer, 2026-10-26).
- x86_64 and aarch64 run graviola's backend. x86_64 needs aes, ssse3, popcnt,
  avx, avx2, adx, bmi2, and pclmulqdq; aarch64 needs aes, sha2, pmull, and neon.
- `rind::cpu::check()` names the missing feature, so MoQ fails at startup
  instead of panicking on its first handshake. Hosts missing a feature are refused, as are
  aarch64 boards without crypto extensions (Raspberry Pi 4, CM4, Zero 2 W),
  which run the armv7 build instead.
- armv7 (Android and Linux gnueabihf) runs libcrux's verified portable Rust,
  with P-384 over fiat-crypto's arithmetic. armv7 is a phone client or a small
  board publishing a few Mbps, so portable AEAD speed is enough; importing
  aws-lc's armv7 assembly and porting its C was rejected as far more
  unverified code for throughput the role does not need.
- armv7 runs every operation the `rind-*` adapters and MoQ use, behind the
  same API, so no adapter or MoQ feature carries a per-target exclusion.
  Operations with no consumer, SHA-3 and SHAKE, are not built there
  (maintainer, 2026-10-27).
- Every other target fails to compile. wasm32 does not build rind; nothing in
  MoQ needs native crypto there.

Each quest lands the tests for what it adds: Wycheproof vectors where they
exist, differential tests against aws-lc-rs as a dev-dependency, and a
benchmark against aws-lc-rs.

These quests cover every gap MoQ's 2026-10-26 inventory found. If a MoQ area
quest turns up another, add a quest here rather than letting MoQ keep a C or
RustCrypto dependency.

## Required

- [str0m releases its dimpl 0.9 provider interface](/quest/m1/moq/str0m-release.md) - waiting on the release `rind-str0m` targets
- [rind-str0m on a str0m release](/quest/m1/moq/str0m.md) - publishable once it depends on that release
- [instant-acme 0.9 is released](/quest/m1/moq/instant-acme-release.md) - waiting on the release with a pluggable `CryptoProvider`
- [Publish rind-instant-acme](/quest/m1/moq/instant-acme-publish.md) - switch to the 0.9 release and publish
- [ctgrind on armv7](/quest/m1/moq/armv7-ctgrind.md) - the constant-time check runs on the armv7 build
- [SHA-1 AVX2 rounds in Rust](/quest/m1/moq/sha1-rust.md) - no new inline assembly in the SHA-1 path
- [Ed25519 wipes match aws-lc](/quest/m1/moq/ed25519-wipes.md) - the hashed seed, hash, and nonce are cleared as aws-lc does
- [Vector registers match aws-lc](/quest/m1/moq/vector-clear.md) - no register clearing beyond aws-lc, unless needed for speed
- [Learn from aws-lc-rs's API](/quest/m1/moq/api/README.md) - aws-lc-rs-shaped `aead`, `agreement`, `kem`, `signature`, `digest`, `hmac`, `hkdf`, and `rand` before the first release
- [Release](/quest/m1/moq/release.md) - publish the rind release MoQ switches to
