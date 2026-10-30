# m0: immediate priorities

## Goal

The work that cannot wait: security advisories against rind or its
dependencies, a failing `main`, and anything that breaks MoQ on a published
rind release, and hosted CI that blocks every PR. Otherwise empty while
nothing is urgent.

## Required

- [Hosted CI off the PR path](/quest/m0/ci/README.md) - local `just ci`, then a self-hosted landing gate; the platform matrix runs nightly
