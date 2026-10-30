# [M] Land through quest land

## Goal

`main` changes only through `quest land`: queued PRs are squashed into a
chain on top of `main`, `just ci` runs once on the chain's tip on the
moq-dev organization's self-hosted queue runner, and `main` fast-forwards to
the longest passing prefix. PRs run no hosted CI.

## Plan

Decided by the maintainer on 2026-10-29: `quest land`, not GitHub's merge
queue, so rind matches kixelated/quest and moq-dev/moq's planned gate
instead of moving twice.

- Copy kixelated/quest's `land.yml`, running its check on the queue runner
  (label `moq-queue`, moq-dev/moq's `vars.MOQ_QUEUE_RUNNER`) rather than a
  hosted one. The runner's group must admit rind, which is the maintainer's
  setting; ask if it does not. Follow
  moq-dev/moq's `quest/m0/ci/land.md` for the push credential (a bot in an
  Environment limited to `main`), the ruleset, and ejection on failure.
- The `main` ruleset requires a check PR heads never carry, so only the
  gate lands. Ruleset and runner-group writes are the maintainer's; agents
  only read them and ask.
- Remove `Check`'s `pull_request` trigger and update `CONTRIBUTING.md`'s
  landing steps (`quest merge --land`).

## Required

- [Follow the move to moq-dev](/quest/m0/ci/transfer.md) - secrets and apps the gate needs live on the organization
