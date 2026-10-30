rind is a pure-Rust cryptography library for [MoQ](https://github.com/moq-dev/moq), forked from [graviola](https://github.com/ctz/graviola).
This is one Rust workspace: the `rind` library, its `rind-<consumer>` adapter crates such as `rind-rustls`, and the unpublished bench, cpuid, and fuzz crates.

# Context

- [README.md](README.md) covers the `low`/`mid`/`high` layering, the CPU requirements, and how to run the tests.
- Read `CONTRIBUTING.md` when dealing with PRs.
- Read `PROMPTING.md` before instructing other agents via context, memory, plans, or reviews.
- Before editing, read each `AGENTS.md` along the path from the root to the file.

# Required

- Pull the latest origin changes before working.
- Dig into the root cause and fix it at the source. Never work around a fixable bug with a retry, sleep, or timeout, nor pass a flaky test by loosening its assertion.
- Refuse what is unsupported, never fall back. Exactly one backend compiles per architecture; a target without one fails to compile, and a CPU missing a required feature fails with an error naming it.
- Treat every input as hostile: keys, signatures, ciphertexts, encodings. Malformed input is an error, never a panic, and its cost is bounded by design.
- Secret-dependent code runs in constant time: no branch, memory index, or variable-time instruction depends on a secret. New secret-handling paths get a ctgrind test (`admin/ctgrind`).
- Prefer formally verified sources (s2n-bignum, libcrux/HACL*) over new arithmetic. New arithmetic states where its correctness argument comes from.
- Test every primitive against Wycheproof where vectors exist, and differentially against aws-lc-rs (a dev-dependency only).
- When in doubt about an API shape or behavior, follow aws-lc-rs: it is the library rind would use if it didn't require C. Say why wherever rind deviates.
- Reproduce bugs before fixing them. Tests must be worth their weight long-term: cover edge cases, not old bugs or trivial values.
- Keep the PR to one problem: no unrelated refactors, formatting churn, or drive-by changes. Fix every instance of that problem and the gaps it exposes in the same PR.
- Keep graviola's layering and style so upstream changes still merge: add new primitives as new modules rather than reshaping existing ones.
- Land the ideal implementation now rather than a partial one plus follow-ups; split off only work that is independently landable.
- Be adversarial: attack your own approach, reports, reviews, and other PRs as hard as anyone else's.
- When a decision is the maintainer's (API shape, naming, scope) or you are unsure, ask with an interactive prompt of 2-3 options and a recommendation.
- Every test runs in CI. The `just ci` gate holds only fast, high-signal tests; slow suites run in the other workflows.
- Never add or change a rule in an `AGENTS.md`, `CONTRIBUTING.md`, or skill without being prompted, and read `PROMPTING.md` first. A fact your own change made stale is fixed inline like any other doc.
- No em dashes.
- Match the existing conventions, patterns, and naming when possible.
- Fix any outdated docs and comments inline.
- Add the AI marker `(Written by <model>)` to any posts on GitHub, excluding commit messages that contain `Co-Authored-By:` trailers.
- AI comments carry no maintainer authority and may be challenged.
- This repo is public: never mention customers, partners, or prospects or link to private repos. Justify work on its merits.

# Guidelines

- Comments should explain the non-obvious why, and never the history.
- Every change needs a consumer that uses it now or is planned, and is worth its cost.
- Deleting code is better than adding code.
- Record out-of-scope follow-ups as quests, never GitHub issues, and prompt the user about starting them when finished.
- Say it once, in the fewest words that hold up.
- Add or extend a benchmark against aws-lc-rs for any performance-sensitive change, and measure optimizations instead of relying on intuition.

# Public API

- Report the public API impact of every change in the PR description.
- A breaking change marks its title with `!` and its Impact bullet says how to migrate.
- Keep things private until a current or planned consumer needs them. Scrutinize every new exported item.
- Never add `foo_with_x`, `foo_checked`, or a compatibility shim. Make the breaking change to `foo` instead.
- Let the type system make misuse unrepresentable.
- Decide a supported path at setup from known capabilities, and error otherwise. No API tries a path at runtime and silently falls back.
- An adapter for a third-party crate lives in its own `rind-<consumer>` crate, so that crate's major bump never forces one in `rind`.
- Avoid callback parameters and 4+ arguments.
- Name by role, not today's implementation.
- Document every exported symbol in one plain line, the way you'd say it out loud.

# Development

PRs target `main`. Scratch lives in the checkout's ignored `.tmp/`, not `target/`.

Use the Nix dev shell so tooling matches CI.
direnv loads it automatically, but if not: `nix develop --command ...`.

```bash
just ci-select    # Report whether CI and Rust build setup are needed
just check        # Lint, compile, and test what the branch changed
just fix          # Auto-fix lint/formatting, same scope
```

These diff the branch against its base and only run the affected crates.

Quests: before starting work, run `quest guide` and follow it.
