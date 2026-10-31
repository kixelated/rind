# [M] armv7 X25519 and Ed25519 from the fastest source

## Goal

armv7 X25519 and Ed25519 run the fastest source available, or this quest
records that the saving does not matter and is deleted. Today both run
HACL*'s verified Curve25519_51 and Ed25519, which keep 64-bit limbs on a
32-bit core.

## Plan

On the bench runner (Neoverse-N2 running the armv7 build, bench-tmp run
41151132431), criterion medians:

| | rind (HACL\* ✓) | curve25519-dalek / ed25519-dalek | aws-lc-rs |
|---|---|---|---|
| x25519-ecdh | 245.3 µs | 185.8 µs | 259.9 µs |
| ed25519-keygen | 84.5 µs | 48.2 µs | 68.2 µs |
| ed25519-sign | 167.1 µs | 49.3 µs | 69.2 µs |
| ed25519-verify | 191.6 µs | 130.6 µs | 222.0 µs |

dalek is pure Rust and unverified with its default 32-bit backend, so taking
it would mark these cells ⚡. Its `fiat` backend puts fiat-crypto's verified
32-bit field arithmetic under dalek's curve code: measure that too, since it
would keep the field arithmetic ✓. Ed25519 signing's gap is mostly the
fixed-base multiplication, where dalek uses a precomputed table.

Weigh it against [moq-dev/rind#99](https://github.com/moq-dev/rind/pull/99),
which judged 0.24 ms per handshake not to matter: X25519 saves about 60 µs
per handshake, and Ed25519 signing about 0.12 ms per signature.
