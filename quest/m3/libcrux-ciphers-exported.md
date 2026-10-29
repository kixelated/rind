# [XS] libcrux exports its raw ciphers

## Goal

A published libcrux release exports the AES block cipher and AES-CTR from
libcrux-aes and HACL*'s ChaCha20 from libcrux-chacha20poly1305, which 0.0.10
keeps `pub(crate)`. Check each crate's latest `src/lib.rs` on crates.io. This
quest only waits; delete it once that holds.

## Plan

Asking libcrux (cryspen/libcrux) for the exports is outward-facing: ask the
maintainer before filing an issue or PR there.
