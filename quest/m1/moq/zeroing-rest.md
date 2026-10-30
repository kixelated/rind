# [XS] Remaining wipes match aws-lc

## Goal

The wipes [moq-dev/rind#58](https://github.com/moq-dev/rind/pull/58) did not
check meet the same rule: each matches what aws-lc clears for its
equivalent, or is reverted.

## Plan

Decided by the maintainer on 2026-10-29, from #58's follow-ups, so the
`AGENTS.md` zeroing rule holds everywhere before release.

- Check, with aws-lc file and line as #58 did: the AES-CTR tail keystream
  buffer, HKDF's block and key copies, and the armv7 backend's copies and
  scratch (libcrux scalar and point copies, AEAD `plain` buffers, RSA
  scratch).
- Owned keys and keyed state keep their wipes.
