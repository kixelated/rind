# [XS] instant-acme 0.9 is released

## Goal

instant-acme 0.9 is on crates.io with the pluggable `CryptoProvider` from
[djc/instant-acme#268](https://github.com/djc/instant-acme/pull/268) (merged
2026-03-30; 0.8.5 was the newest release on 2026-10-27). Check with
`cargo search instant-acme` or crates.io. This quest only waits; delete it
once a 0.9 release holds that API.

## Plan

moq-relay replaces rustls-acme with instant-acme because rustls-acme
hard-wires ring or aws-lc-rs with no provider hook
([FlorianUekermann/rustls-acme#62](https://github.com/FlorianUekermann/rustls-acme/issues/62)).
To advance it, ask upstream about a release date or what still blocks one.
