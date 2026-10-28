# [L] libcrux backend

## Goal

`cargo build` and `cargo test` of rind succeed for
`armv7-unknown-linux-gnueabihf` (run under emulation in CI) and
`cargo build` for `armv7-linux-androideabi`, on a backend made of libcrux's
verified portable Rust: AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, SHA-2,
HMAC, HKDF, X25519, Ed25519, ECDSA P-256, RSA-PSS, and ML-KEM-768. Every other
target still fails to compile.

## Plan

Settled (maintainer, 2026-10-26): exactly one backend compiles per arch, never
both in one binary. libcrux is 0.0.x and only armv7 depends on it, so it is a
target-specific dependency that x86_64 and aarch64 graphs never contain.
Importing aws-lc's armv7 assembly and porting its C was rejected as far more
unverified code for throughput the role does not need.

Guidance:

- Swap the backend at graviola's `low` layer where possible, so `mid` and
  `high` stay shared and every operation armv7 builds keeps the other arches'
  API. Where libcrux's boundary sits higher (a whole AEAD or signature rather
  than a field operation), choose the lowest layer that keeps that API, and
  say why in the PR.
- No C: check `cargo tree -e normal,build -i cc --target <armv7 target>` holds
  nothing from rind's graph, since some libcrux crates have optional C or
  intrinsics features.
- Add armv7 to CI: the full test suite for gnueabihf under qemu, including the
  Wycheproof and CAVP vectors and the adapter crates, and a build for the
  Android target.
- Operations libcrux lacks land in the sibling quests; until they do, they fail
  to compile on armv7 rather than panic at runtime.
- Revisit the `proc-macro-error2` advisory ignore in `deny.toml` (pulled by
  libcrux's hax macros) once libcrux becomes a real dependency.

Public API: none beyond armv7 becoming a supported target.
