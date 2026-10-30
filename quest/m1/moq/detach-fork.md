# [XS] Leave graviola's fork network

## Goal

moq-dev/rind is no longer a GitHub fork of ctz/graviola:
`gh repo view moq-dev/rind --json isFork` reports `false`. graviola stays
credited in the README and LICENSE.

## Plan

Decided by the maintainer on 2026-10-30: rind no longer tracks graviola.
Detaching is a repository setting, so this quest only waits for the
maintainer, who uses the repository's settings if they offer it, otherwise
GitHub Support. Delete this quest once it reports `false`.
