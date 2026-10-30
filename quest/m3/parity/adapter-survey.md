# [S] Adapter survey

## Goal

A report in the migration guide lists the widely used crates whose crypto backend is pluggable or tied to ring or aws-lc-rs (such as quinn, reqwest, jsonwebtoken, rcgen, instant-acme, object_store, webpki, and hickory), and for each, whether rind-rustls already covers it, a `rind-*` adapter would, or it cannot be supported.

## Plan

Decided by the maintainer on 2026-10-30, planning ring and aws-lc-rs parity.

- A report, not code: each adapter it recommends becomes its own quest
  through `/quest-plan`.
