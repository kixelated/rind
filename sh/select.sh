#!/usr/bin/env bash
# Print the Cargo package arguments for the crates a diff touches, plus every
# workspace crate depending on them, one argument per line.
#
# Usage: sh/select.sh CHANGED_FILE [ALL]
# A change outside any crate's directory (the root manifest, the lockfile,
# thirdparty/ test vectors) can reach every crate, so it selects --workspace,
# as does a non-empty ALL.
set -euo pipefail

changed=${1:?usage: sh/select.sh CHANGED_FILE [ALL]}
all=${2:-}

if [[ -n "$all" ]]; then
    echo --workspace
    exit
fi

root=$(git rev-parse --show-toplevel)
metadata=$(cargo metadata --format-version 1 --no-deps --locked)

# Each member's directory, relative to the root, and its name.
declare -A dirs=()
while IFS=$'\t' read -r dir name; do
    dirs[$dir]=$name
done < <(jq -r --arg root "$root/" '.packages[] | [(.manifest_path | ltrimstr($root) | rtrimstr("/Cargo.toml")), .name] | @tsv' <<<"$metadata")

declare -A selected=()
while IFS= read -r path; do
    dir=${path%%/*}
    if [[ "$path" == */* && -n "${dirs[$dir]:-}" ]]; then
        selected[${dirs[$dir]}]=1
    elif grep -qE '^(thirdparty/|Cargo\.(toml|lock)$|\.rustfmt\.toml$)' <<<"$path"; then
        echo --workspace
        exit
    fi
done <"$changed"

# Add workspace dependents until nothing new appears.
edges=$(jq -r '.packages[] | .name as $n | .dependencies[] | select(.path != null) | [.name, $n] | @tsv' <<<"$metadata")
grew=1
while [[ -n "$grew" ]]; do
    grew=
    while IFS=$'\t' read -r dep dependent; do
        if [[ -n "${selected[$dep]:-}" && -z "${selected[$dependent]:-}" ]]; then
            selected[$dependent]=1
            grew=1
        fi
    done <<<"$edges"
done

for name in "${!selected[@]}"; do
    printf -- '-p\n%s\n' "$name"
done
