# [S] Verified AES-GCM setup on aarch64

## Goal

aarch64 AES-GCM runs verified code end to end: the AES key schedule and the
GHASH H-power table that s2n-bignum's proven kernels assume correct come from
a verified source, or the README records that none exists.

## Plan

Decided by the maintainer on 2026-10-30, from the follow-ups of
[moq-dev/rind#86](https://github.com/moq-dev/rind/pull/86), which moved
aarch64's CTR and whole-block GHASH onto s2n-bignum's proven kernels but kept
Graviola's unverified key schedule, H powers, and GHASH of the AAD, final
partial block, and lengths.

- s2n-bignum has no key schedule or H-power routine today. Survey other
  verified sources before writing anything: aws-lc's SAW proofs
  (aws-lc-verification), HACL\* and Vale, and libcrux.
- A source qualifies only if its proof covers the aarch64 code rind would run,
  or code rind can import mechanically as with `admin/parse-asm`.
- If nothing qualifies, close the quest with the survey in the PR and the
  README's AES-GCM cell unchanged. Don't hand-write a replacement.
- Keep the speed bar of #86: no loss against aws-lc-rs from 2 KB up, measured
  on the hosted arm runner.
