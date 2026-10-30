# [S] Zeroing matches aws-lc

## Goal

rind wipes what aws-lc wipes and no more: types that own a key or keyed
state zeroise it on drop, and the wipes of stack temporaries, scratch, and
in-call copies that rind added beyond aws-lc are gone, with their cost won
back.

## Plan

Decided by the maintainer on 2026-10-29: safe Rust cannot read stale stack
or freed memory, so residue only reaches core dumps, swap, or another
process, briefly. Owned keys are worth a cheap `Drop` wipe there; scratch
is not. The rule is in `AGENTS.md`.

- Revert the extras, checking each against aws-lc's source first:
  - The compress functions' message-schedule wipes from
    [moq-dev/rind#41](https://github.com/moq-dev/rind/pull/41). Keep armv7
    on the generic SHA-2, which was faster.
  - The hash contexts' wipe on drop from
    [moq-dev/rind#42](https://github.com/moq-dev/rind/pull/42) (SHA-1, SHA-2)
    and [moq-dev/rind#52](https://github.com/moq-dev/rind/pull/52) (SHA-3,
    SHAKE). `Hmac` and `HmacDrbg` keep wiping their keyed state themselves.
  - In-call temporaries wiped in #39, #42, and #52 (ECDSA candidates and
    encodings, padded blocks, ML-KEM intermediates) where aws-lc does not
    clear them. aws-lc's ML-KEM follows FIPS 203's rule to destroy
    intermediate values; keep whatever it keeps.
- Keep the copy `expand_key` marks for ctgrind; that is about marking, not
  wiping.
- Trim `rind/tests/zeroing.rs` to owned key types, and benchmark the hashes,
  HMAC, and ML-KEM against aws-lc-rs before and after.
- The m2 zeroing quests (stack scrub, assembly stack frames, faster short
  zeroing) and the armv7 ML-KEM remainder were deleted with this decision.
