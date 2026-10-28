# [S] Adopt local reviews

## Goal

PRs here are reviewed locally by the other vendor's model through
`/quest-review` before they are pushed for review, and merging never waits
on an online reviewer. Start once `quest review` is on kixelated/quest's
`main`, where it is planned as `quest/m0/local-review.md`.

## Plan

Decided 2026-10-28 (maintainer, /quest-plan in kixelated/quest):

- Bump the `quest` flake input to a kixelated/quest rev with `quest review`.
- Rewrite the review policy: the PR body's `## Review` record counts as the
  required review when it names the head being merged, and so does a
  recorded skip of a change the author judged too trivial to review.
  Online reviewers' findings already posted on the head are addressed at
  merge, never waited for or requested.
- Replace "a review by someone other than the PR's author" and "ask the
  maintainer to arrange one" in `CONTRIBUTING.md`. Ask the maintainer
  whether to add a `REVIEW.md`, which sets the reviewer's stance (such as
  adversarial) and review-only rules.
