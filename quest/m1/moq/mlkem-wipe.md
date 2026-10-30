# [S] Wipe ML-KEM intermediates

## Goal

ML-KEM-768 erases every intermediate secret before it is freed, on both the
x86_64/aarch64 backend (`mid::mlkem768`) and armv7's libcrux backend
(`mid::arm::mlkem768`): the `kr` hash output, `KpkeRandomness`, and secret
`Coeffs` such as `s`, `e`, `y`, and the decrypted message polynomial. The
SHA-3 and SHAKE contexts that hash those secrets wipe themselves on drop,
as SHA-1 and SHA-2's do since
[moq-dev/rind#42](https://github.com/moq-dev/rind/pull/42).
`rind/tests/zeroing.rs` covers `DecapKey` on both.

## Plan

Decided by the maintainer on 2026-10-29, from the review of
[kixelated/rind#39](https://github.com/kixelated/rind/pull/39), which added
ML-KEM's ctgrind marks: wiping is a different problem from those marks and
touches many functions on both backends, so it is its own quest.

- Wipe the way rind's other key types do (`low::zeroise` in a `Drop`), and
  prefer a `Drop` on the secret types over a call at each use site.
- Check what libcrux already erases on armv7 before adding wipes around it.
- SHA-3 context wiping joined this quest on 2026-10-29 (maintainer), from
  #42's follow-ups, since ML-KEM is its main secret-hashing user.
