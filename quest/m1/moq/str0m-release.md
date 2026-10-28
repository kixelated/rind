# [XS] str0m releases its dimpl 0.9 provider interface

## Goal

A str0m release on crates.io depends on dimpl 0.9 and carries the provider
interface `rind-str0m` pins from str0m's main branch: the `Sha1Provider`
field and `send_application_data` returning a byte count. str0m 0.24.1, the
newest release on 2026-10-28, still uses dimpl 0.7. Check with
`cargo search str0m` and the release's `str0m-proto` dependency on dimpl.
This quest only waits; delete it once such a release exists.

## Plan

str0m has released about monthly. To advance it, ask upstream about the next
release date.
