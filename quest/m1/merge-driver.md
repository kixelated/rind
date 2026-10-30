# [XS] Merge quest link lists locally

## Goal

`.gitattributes` routes `quest/**` through quest's merge driver, so a local
merge of main resolves conflicting edits to quest link lists itself.

## Plan

Decided by the maintainer on 2026-10-29, from the follow-ups of
[kixelated/rind#31](https://github.com/kixelated/rind/pull/31), where
`quest init` proposed the line and it was left out as off-topic.

- Add `quest/** merge=quest`, and check that `quest init` (or the dev shell)
  registers the driver for a fresh clone.
