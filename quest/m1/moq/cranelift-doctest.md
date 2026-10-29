# [XS] Run doctests under Cranelift

## Goal

The `cranelift` workflow builds doctests with Cranelift too, and the
`rind-rcgen` crate example runs again instead of being `no_run`.

## Plan

Planned by the maintainer on 2026-10-28.
[kixelated/rind#10](https://github.com/kixelated/rind/pull/10) made the
example `no_run` after it crashed on aarch64. The crash is a `uint64x1_t` ABI
mismatch between LLVM-built and Cranelift-built code
([rust-lang/rustc_codegen_cranelift#1718](https://github.com/rust-lang/rustc_codegen_cranelift/issues/1718)):
cargo does not pass `profile.*.codegen-backend` to rustdoc
([rust-lang/cargo#17659](https://github.com/rust-lang/cargo/issues/17659)), so
doctests link LLVM code against Cranelift-built rind.

- Set `RUSTDOCFLAGS="-Zcodegen-backend=cranelift"` in
  `.github/workflows/cranelift.yml`, with a comment linking cargo#17659.
- Drop `no_run` from `rind-rcgen/src/lib.rs`.
