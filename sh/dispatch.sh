#!/usr/bin/env bash
# Run `just check`, `just fix`, or `just ci` over one resolved branch diff.
# `--query` prints the selection before CI installs its toolchain and caches.
set -euo pipefail

usage="usage: sh/dispatch.sh check|fix|ci [BASE|--all] [--query]"
action=${1:?$usage}
base=${2:-}
query=${3:-}
if [[ $# -gt 3 || (-n "$query" && "$query" != --query) ]]; then
    echo "$usage" >&2
    exit 2
fi
case "$action" in
    check | fix | ci) ;;
    *)
        echo "$usage" >&2
        exit 2
        ;;
esac

# A host toolchain may differ from CI's pinned one. This flake's dev shell sets
# IN_RIND_DEV_SHELL.
if [[ -z "$query" && -z "${IN_RIND_DEV_SHELL:-}" && -z "${ALLOW_HOST_TOOLCHAIN:-}" ]]; then
    echo "error: run inside the Nix dev shell ('nix develop' or direnv) so tools match CI" >&2
    echo "       or set ALLOW_HOST_TOOLCHAIN=1 to use the host toolchain anyway" >&2
    exit 1
fi

cd "$(git rev-parse --show-toplevel)"

changed=$(mktemp)
trap 'rm -f "$changed"' EXIT

all=
if [[ "$base" == --all ]]; then
    all=1
else
    sh/changed.sh "$base" >"$changed"

    # These files hold the map and the recipes that call it, and match no
    # module, so a change to them would otherwise validate none of it.
    if grep -qE '^(justfile|sh/(dispatch|changed|select)\.sh)$' "$changed"; then
        echo "$action: root orchestration changed; running everything." >&2
        all=1
    fi
fi

# The impact map: a module is in scope when a changed path matches its
# pattern. An empty pattern is a repository-wide lint that runs on every diff.
declare -A scope=(
    # sh/select.sh narrows this to the changed crates and their dependents.
    [rs]='^(rind[^/]*/|fuzz/|thirdparty/|Cargo\.(toml|lock)$|\.rustfmt\.toml$)'
    # Advisories, licenses, and sources move with any manifest or the policy.
    [deny]='(^|/)Cargo\.(toml|lock)$|^deny\.toml$'
    # Quest documents form one graph, so any change validates the whole tree,
    # as does a bump of the flake-pinned validator.
    [quest]='^(quest/|flake\.lock$)'
    [gh]='^\.github/'
    # The agent session hooks and their regression suite.
    [hooks]='^\.(claude|codex)/hooks/'
    [shell]=''
    [nix]=''
)

# The tools each module needs. A module missing one is skipped locally; under
# CI_STRICT (CI) it is an error, since there a skip is indistinguishable from
# a pass.
declare -A tools=(
    [rs]='cargo jq'
    [deny]='cargo-deny'
    [quest]='quest'
    [gh]='actionlint'
    [hooks]='shellcheck'
    [shell]='shellcheck'
    [nix]='nixfmt'
)

verb=$action
[[ "$verb" != ci ]] || verb=check

case "$verb" in
    check) modules=(rs deny quest gh hooks shell nix) ;;
    fix) modules=(rs nix) ;;
esac

selected=()
missing=()
for module in "${modules[@]}"; do
    pattern=${scope[$module]}
    if [[ -z "$all" && -n "$pattern" ]] && ! grep -qE "$pattern" "$changed"; then
        continue
    fi
    # Selection must not depend on the tools setup has yet to install.
    if [[ -n "$query" ]]; then
        selected+=("$module")
        continue
    fi
    absent=()
    for tool in ${tools[$module]}; do
        command -v "$tool" >/dev/null 2>&1 || absent+=("$tool")
    done
    if ((${#absent[@]} == 0)); then
        selected+=("$module")
    elif [[ -n "${CI_STRICT:-}" ]]; then
        missing+=("${absent[@]}")
    else
        echo "$action: skipping $module; missing ${absent[*]}" >&2
    fi
done

# A query runs on the host before Nix is installed.
if [[ -n "$query" ]]; then
    needed=false
    rust=false
    for module in "${selected[@]}"; do
        needed=true
        [[ "$module" != rs ]] || rust=true
    done
    echo "needed=$needed"
    echo "rust=$rust"
    exit
fi

if ((${#missing[@]} > 0)); then
    echo "error: missing tools under CI_STRICT: ${missing[*]}" >&2
    exit 1
fi

# Tracked files matching a pathspec, NUL-separated.
files() {
    git ls-files -z -- "$@"
}

for module in "${selected[@]}"; do
    echo "==> $action $module" >&2
    case "$verb:$module" in
        check:rs)
            # The tests read these vectors, and otherwise fail partway through.
            # s2n-bignum only feeds admin/parse-asm, so it is not required.
            unfetched=$(git submodule status -- thirdparty/cavp thirdparty/wycheproof | sed -n 's/^-[0-9a-f]* //p')
            if [[ -n "$unfetched" ]]; then
                echo "error: test vectors not checked out; run: git submodule update --init ${unfetched//$'\n'/ }" >&2
                exit 1
            fi
            mapfile -t packages < <(sh/select.sh "$changed" "$all")
            cargo fmt --all --check
            cargo clippy "${packages[@]}" --all-targets --locked -- --deny warnings
            cargo test "${packages[@]}" --locked
            ;;
        fix:rs)
            mapfile -t packages < <(sh/select.sh "$changed" "$all")
            cargo fmt --all
            cargo clippy "${packages[@]}" --all-targets --fix --allow-dirty --allow-staged
            ;;
        check:deny) cargo deny --locked check ;;
        check:quest) quest check ;;
        check:gh) actionlint ;;
        check:hooks)
            files '.claude/hooks/*.sh' '.codex/hooks/*.sh' | xargs -0 shellcheck
            bash .claude/hooks/direnv.test.sh
            ;;
        check:shell) files 'sh/*.sh' | xargs -0 shellcheck ;;
        check:nix) files '*.nix' | xargs -0 nixfmt --check ;;
        fix:nix) files '*.nix' | xargs -0 nixfmt ;;
    esac
done
