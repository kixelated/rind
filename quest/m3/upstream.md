# [S] Revisit upstreaming

## Goal

Decide, with the maintainer, which of rind's changes to offer
[ctz/graviola](https://github.com/ctz/graviola) and whether rind should keep
tracking it, and record that decision here or in the quests it creates.

## Plan

Settled (maintainer, 2026-10-26): rind is a GitHub fork keeping graviola's
history for a later rebase or upstreaming. Fork only: no upstream PRs until
rind carries MoQ, then revisit.

Candidates: the CPU check
([ctz/graviola#227](https://github.com/ctz/graviola/issues/227)), the raw
ciphers ([ctz/graviola#156](https://github.com/ctz/graviola/pull/156)), HKDF,
and SHA-1. The armv7 libcrux backend is the hardest fit, since graviola's
design is formally verified assembly per arch.

## Required

- [MoQ runs on rind](/quest/m3/moq-on-rind.md) - the point at which upstreaming is revisited
