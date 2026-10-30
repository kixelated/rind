# [S] Attribute every algorithm's source

## Goal

The README lists every algorithm rind offers, per backend (x86_64, aarch64,
armv7), with the source of its code (s2n-bignum, graviola, libcrux or
HACL*, fiat-crypto, aws-lc, or rind's own), that source's license, and a ✓
where the code is formally verified, linking each proof's project.

## Plan

Decided by the maintainer on 2026-10-30, alongside leaving graviola's fork
network.

- Derive the table from the code (`low/` per arch, `mid/arm/`, and the
  dependencies), not from memory; say what "verified" covers for each source
  (for example, s2n-bignum's proofs cover its assembly, and libcrux-aes is
  pre-verification).
- Replace the README's existing attribution and license list with the table
  rather than duplicating it, and keep each `Written for Graviola by ...`
  header.
