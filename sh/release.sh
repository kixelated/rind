#!/usr/bin/env bash
# Open or update the release PR, then publish a release PR that landed since
# BEFORE.
#
# Usage: sh/release.sh [BEFORE]
# release-plz publishes only when HEAD is a release PR's commit (release_always
# = false), but `quest land` lands a batch in one push, so other PRs can follow
# the release PR onto `main`. Each commit `main` gained since BEFORE gets its
# own `release-plz release`, which publishes from that commit only when it is
# the release PR's, keeping later PRs out of the release. Without BEFORE, only
# HEAD is considered.
set -euo pipefail

before=${1:-}
: "${GITHUB_TOKEN:?GITHUB_TOKEN is required}"

release-plz release-pr --git-token "$GITHUB_TOKEN"

range=(--max-count=1 HEAD)
[[ -z "$before" ]] || range=("$before..HEAD")
# First parents only: an upstream merge is one commit of `main`, not every
# graviola commit it brings in.
commits=$(git rev-list --first-parent --reverse "${range[@]}")

start=$(git symbolic-ref --quiet --short HEAD || git rev-parse HEAD)
trap 'git checkout --quiet "$start"' EXIT
for commit in $commits; do
    git checkout --quiet --detach "$commit"
    release-plz release --git-token "$GITHUB_TOKEN"
done
