# Getting oriented

The [README](README.md) covers the layering, CPU requirements, and tests.
Agents should also read [AGENTS.md](AGENTS.md) and the instructions nested
under the files they change.

# Commits

PRs land on `main` as squash commits, so the PR title becomes the commit subject in `git log`; the body keeps the PR's commit messages and co-author trailers, not the PR description.

- Use conventional-commit subjects (`feat(rustls): ...`, `fix: ...`, `chore: ...`, `docs: ...`)
- AI commit attribution goes in a `Co-Authored-By:` trailer, not the commit body.
- Never commit binaries or build artifacts.

# PRs

Keep the body short and structured, not narrated.
Have at least these sections:

- **Problem**: a summary of the problem and why this PR is needed.
- **Approach**: a summary of the approach taken to solve the problem.
- **Impact**: a bullet point for every public API change made. A breaking one says how to migrate, and the PR title marks it with `!` (`feat!: ...`).
- **Alternatives**: any alternative approaches considered.
- **Follow-ups**: any issues encountered or quests created.

When pushing additional commits to an existing PR, update the title and description if needed.
Never rebase or force-push a pushed branch; merge the base branch in instead.
Check that the PR is still open before pushing to its branch, since a push after merge recreates the deleted branch.

Open a draft PR while working, without asking once the scope is settled.
Run `just ci` before every push, and mark the PR ready with `/quest-review` when the work is done.
Keep it a draft only while its description lists a decision the maintainer still owns.
Fix any merge conflicts and failing CI checks.

Every PR runs the platform workflows inherited from graviola: the OS and toolchain matrix, ASAN, cranelift, ctgrind, fuzz smoke tests, and Intel SDE CPU models.
PRs land only through `quest land`: once the review is clean and the maintainer has approved merging, queue the PR with `quest merge <pr> <token> --land <head>`.
The Land workflow squashes the queue onto `main`, runs `just ci` once on the organization's queue runner, and fast-forwards `main` to the longest passing prefix, ejecting with a comment a PR that conflicts or fails alone.
The admin bypass of `main`'s ruleset is for emergencies.

# AI

AI-assisted issues, pull requests, reviews, and comments are welcome.
Prefer a quest for work needing durable scope or coordination.

# Reviews

Before a PR is marked ready, and before each push to one that is, the other vendor's model reviews the committed branch locally through `/quest-review`.
On a PR whose author has write access, the PR body's `## Review` record of that review is the required review when it names the head being merged, with every finding fixed or refuted.
So is a recorded skip of a change the author judged too trivial to review.
A release-plz PR, which only bumps versions and changelogs, needs no review beyond the maintainer's approval to merge it.

Online reviewers are optional: never wait for or request one.
Address their findings already posted on the head when merging:

- If you don't agree with a finding, reply to it and move on.
- If it's a relatively easy improvement, fix it, review the new head locally, and push. Update the summary if needed.

# Follow-ups

Record out-of-scope findings as follow-up quests with `/quest-plan`, not GitHub issues.

# Upstream

rind is a GitHub fork of [ctz/graviola](https://github.com/ctz/graviola) and keeps its history, so upstream changes merge in and rind's can be offered back.
Merge upstream with a merge commit, never a rebase.
The gate squashes, so an upstream merge lands through the admin bypass once `just ci` passes on it.
Open no PRs against graviola until rind carries MoQ; then revisit.
Each `Written for Graviola by ...` header is attribution; keep it on files that carry one.

# Releases

release-plz opens a release PR from `main`, and publishing happens only when that PR merges.
release-plz owns crate versions; bump one only when asked.
