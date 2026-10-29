# [XS] One workspace MSRV

## Goal

The workspace declares one `rust-version`, which rind and every `rind-*`
crate inherit, and CI builds the workspace on it.

## Plan

Planned by the maintainer on 2026-10-28, from the follow-ups of the m1 PRs. `rind-rustls` declares 1.85 but depends on rind, which needs 1.89, so its
declared MSRV is false. Decided (maintainer, 2026-10-28): one
`[workspace.package] rust-version` with `rust-version.workspace = true` in
each crate, rather than bumping `rind-rustls` alone.

- If no CI job builds on the MSRV today, add one to the existing build
  workflow.
