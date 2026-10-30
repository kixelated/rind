# [XS] rind-rustls prefers ChaCha20-Poly1305 without AES

## Goal

On armv7 cores without the crypto extension (Raspberry Pi 4, CM4, Zero 2 W),
rind-rustls orders its ChaCha20-Poly1305 suites first, as rustls's
aws-lc-rs provider does on CPUs without AES hardware, so TLS and QUIC pick
the fast cipher there.

## Plan

Decided by the maintainer on 2026-10-30, from the follow-ups of
[moq-dev/rind#84](https://github.com/moq-dev/rind/pull/84).

- Decide the order once from the detection #84 adds, at provider setup,
  not per connection.
- Check how aws-lc-rs's rustls provider makes the same choice and match it.

## Required

- [armv7 crypto instructions](/quest/m2/armv7-crypto-ext.md) - the detection this reads
