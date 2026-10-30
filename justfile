#!/usr/bin/env just --justfile
# Using Just: https://github.com/casey/just?tab=readme-ov-file#installation
#
# Every recipe is a menu entry: one line that runs a tool, or a script under
# sh/. Logic belongs in the script.

# List the recipes.
default:
    just --list

# Lints, compiles, and tests only the crates the branch changed plus
# everything depending on them; `check --all` is the unscoped suite. BASE
# defaults to the PR base, then a main upstream, then origin/main.

# Lint, compile, and test what the branch changed since BASE, plus its dependents.
check $BASE="":
    sh/dispatch.sh check "$BASE"

# Run CI's gate over the branch diff against BASE; missing tools fail.
ci $BASE="":
    CI_STRICT=1 sh/dispatch.sh ci "$BASE"

# Run CI's gate over every crate.
gate:
    just ci --all

# Report what CI selects before installing the dev shell or build caches.
ci-select $BASE="":
    sh/dispatch.sh ci "$BASE" --query

# Auto-fix lint and formatting for what the branch changed since BASE.
fix $BASE="":
    sh/dispatch.sh fix "$BASE"

# Check dependencies against advisories, licenses, and sources in deny.toml.
audit:
    cargo deny check

# Open or update the release PR, then publish a release PR landed since BEFORE.
release $BEFORE="":
    sh/release.sh "$BEFORE"
