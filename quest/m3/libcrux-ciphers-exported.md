# [XS] libcrux exports its raw ciphers

## Goal

A published libcrux release exports the AES block cipher and AES-CTR from
libcrux-aes, which 0.0.10 keeps `pub(crate)`. Check the crate's latest `src/lib.rs` on crates.io. This
quest only waits; delete it once that holds.

## Plan

Asking libcrux (cryspen/libcrux) for the exports is outward-facing: ask the
maintainer before filing an issue or PR there.
