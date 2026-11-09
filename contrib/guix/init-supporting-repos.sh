#!/usr/bin/env bash
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
#
# Initialize the qbit supporting repositories used by the release process:
# - qbit-guix.sigs
# - qbit-detached-sigs (optional)

export LC_ALL=C

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
TEMPLATE_DIR="${SCRIPT_DIR}/repo-templates"
readonly TEMPLATE_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT
# The release key policy has one source of truth: contrib/keys/operator-keys
# in this repository, read at the release's trusted ref. qbit-guix.sigs only
# carries a derived copy, seeded from it here.
CANONICAL_KEYS_DIR="${REPO_ROOT}/contrib/keys/operator-keys"
readonly CANONICAL_KEYS_DIR

usage() {
    cat <<'EOF'
Usage:
  ./contrib/guix/init-supporting-repos.sh <path-to-qbit-guix.sigs> [path-to-qbit-detached-sigs]
  ./contrib/guix/init-supporting-repos.sh --resync-operator-keys <trusted-ref> <path-to-qbit-guix.sigs>

The first form creates local git repositories seeded with qbit-specific README
files and layout scaffolding for the supporting repositories described in the
release process.

--resync-operator-keys rebuilds an existing qbit-guix.sigs checkout's
operator-keys/ as exactly the file set the release publisher checks, from
contrib/keys/operator-keys at <trusted-ref> (a full commit SHA in this
repository), and verifies it as the publisher does. Stale files are removed.
Review and commit the result in qbit-guix.sigs.
EOF
}

if [[ "${1:-}" != "--resync-operator-keys" ]] && [[ $# -lt 1 || $# -gt 2 ]]; then
    usage >&2
    exit 1
fi

init_git_repo() {
    local repo_dir="$1"
    mkdir -p "${repo_dir}"
    if [[ ! -d "${repo_dir}/.git" ]]; then
        git -C "${repo_dir}" init --initial-branch=main >/dev/null
    fi
}

copy_if_missing() {
    local src="$1"
    local dst="$2"
    mkdir -p "$(dirname "${dst}")"
    if [[ ! -e "${dst}" ]]; then
        cp "${src}" "${dst}"
    fi
}

write_detached_sigs_readme_if_missing() {
    local dst="$1"
    mkdir -p "$(dirname "${dst}")"
    if [[ ! -e "${dst}" ]]; then
        cat >"${dst}" <<'EOF'
# qbit-detached-sigs

This optional repository stores detached macOS and Windows signatures for qbit
release artifacts.

Use one orphan branch per release version. Each release branch should contain
only the detached signature material for that release.
EOF
    fi
}

# Print the operator-keys files the release publisher requires in the
# qbit-guix.sigs mirror for the canonical policy: keys.json, every referenced
# signer certificate, and the current policy's approval material. This is the
# file set ci/release/validate_builder_attestations.py checks byte for byte.
operator_keys_mirror_files() {
    local keys_dir="${1:-${CANONICAL_KEYS_DIR}}"
    local validator_dir="${2:-${REPO_ROOT}/ci/release}"
    PYTHONPATH="${validator_dir}" python3 - "${keys_dir}" <<'PY'
import json
import sys
from pathlib import Path

from validate_builder_attestations import (
    BuilderValidationError,
    expected_operator_key_files,
    load_builder_policy,
)

keys_dir = Path(sys.argv[1])
policy_path = keys_dir / "keys.json"
try:
    release_lines = json.loads(policy_path.read_text(encoding="utf8"))["release_lines"]
    files = set()
    for release_line in sorted(release_lines):
        policy = load_builder_policy(policy_path, keys_dir, release_line)
        files |= expected_operator_key_files(keys_dir, policy)
except (BuilderValidationError, OSError, KeyError, TypeError, ValueError) as exc:
    sys.exit(f"ERR: canonical operator key policy is not mirrorable: {exc}")
for relative in sorted(files):
    print(relative)
PY
}

init_guix_sigs_repo() {
    local repo_dir="$1"
    local mirror_files
    local relative
    init_git_repo "${repo_dir}"
    copy_if_missing "${TEMPLATE_DIR}/qbit-guix.sigs/README.md" "${repo_dir}/README.md"
    mirror_files="$(operator_keys_mirror_files)"
    while IFS= read -r relative; do
        [[ -n "${relative}" ]] || continue
        copy_if_missing "${CANONICAL_KEYS_DIR}/${relative}" "${repo_dir}/operator-keys/${relative}"
    done <<< "${mirror_files}"
}

# Rebuild <qbit-guix.sigs>/operator-keys from contrib/keys/operator-keys at the
# trusted ref, with that ref's own validators choosing and checking the files.
resync_operator_keys() {
    local trusted_ref="$1"
    local repo_dir="$2"
    local work mirror_files relative staging target
    [[ "${trusted_ref}" =~ ^[0-9a-f]{40}$ ]] \
        || { echo "error: <trusted-ref> must be a full commit SHA, got: ${trusted_ref}" >&2; exit 1; }
    git -C "${REPO_ROOT}" cat-file -e "${trusted_ref}^{commit}" 2>/dev/null \
        || { echo "error: this repository has no commit ${trusted_ref}; fetch it first" >&2; exit 1; }
    [[ -d "${repo_dir}" ]] && [[ "$(git -C "${repo_dir}" rev-parse --show-toplevel 2>/dev/null)" == "$(cd "${repo_dir}" && pwd -P)" ]] \
        || { echo "error: not the top of a qbit-guix.sigs git checkout: ${repo_dir}" >&2; exit 1; }
    target="${repo_dir}/operator-keys"
    [[ ! -L "${target}" ]] || { echo "error: ${target} must not be a symlink" >&2; exit 1; }

    work="$(mktemp -d)"
    trap 'rm -rf "${work}"' RETURN
    git -C "${REPO_ROOT}" archive "${trusted_ref}" \
        contrib/keys/operator-keys \
        ci/release/validate_builder_attestations.py \
        ci/release/validate_key_metadata.py | tar -x -C "${work}"
    mirror_files="$(operator_keys_mirror_files "${work}/contrib/keys/operator-keys" "${work}/ci/release")"

    staging="${repo_dir}/.operator-keys.resync"
    rm -rf "${staging}"
    while IFS= read -r relative; do
        [[ -n "${relative}" ]] || continue
        mkdir -p "$(dirname "${staging}/${relative}")"
        cp "${work}/contrib/keys/operator-keys/${relative}" "${staging}/${relative}"
    done <<< "${mirror_files}"
    rm -rf "${target}"
    mv "${staging}" "${target}"

    # The publisher's two checks of the mirror, with the trusted ref's validators.
    python3 "${work}/ci/release/validate_key_metadata.py" \
        --operator-policy "${work}/contrib/keys/operator-keys/keys.json" \
        --operator-keys-dir "${work}/contrib/keys/operator-keys" \
        --operator-policy-mirror "${target}/keys.json" \
        --operator-keys-dir-mirror "${target}" \
        --skip-policy-transition-validation \
        --require-public-key-files >/dev/null
    PYTHONPATH="${work}/ci/release" python3 - "${work}/contrib/keys/operator-keys" "${target}" <<'PY'
import json
import sys
from pathlib import Path

from validate_builder_attestations import load_builder_policy, validate_builder_mirror

canonical, mirror = (Path(arg) for arg in sys.argv[1:])
for release_line in sorted(json.loads((canonical / "keys.json").read_text(encoding="utf8"))["release_lines"]):
    policy = load_builder_policy(canonical / "keys.json", canonical, release_line)
    validate_builder_mirror(policy, canonical, mirror / "keys.json", mirror, release_line)
PY
    cat <<EOF
Rebuilt ${target} from contrib/keys/operator-keys at ${trusted_ref}; it passes
the release publisher's mirror checks. Review and commit it:
  git -C ${repo_dir} status --short operator-keys
EOF
}

init_detached_sigs_repo() {
    local repo_dir="$1"
    local readme_template="${TEMPLATE_DIR}/qbit-detached-sigs/README.md"
    init_git_repo "${repo_dir}"
    if [[ -f "${readme_template}" ]]; then
        copy_if_missing "${readme_template}" "${repo_dir}/README.md"
    else
        write_detached_sigs_readme_if_missing "${repo_dir}/README.md"
    fi
}

if [[ "$1" == "--resync-operator-keys" ]]; then
    [[ $# -eq 3 ]] || { usage >&2; exit 1; }
    resync_operator_keys "$2" "$3"
    exit 0
fi

GUIX_SIGS_DIR="$1"
init_guix_sigs_repo "${GUIX_SIGS_DIR}"

if [[ $# -eq 2 ]]; then
    DETACHED_SIGS_DIR="$2"
    init_detached_sigs_repo "${DETACHED_SIGS_DIR}"
fi

cat <<EOF
Initialized supporting repository scaffolding:
- qbit-guix.sigs: ${GUIX_SIGS_DIR}
EOF

if [[ $# -eq 2 ]]; then
    cat <<EOF
- qbit-detached-sigs: ${DETACHED_SIGS_DIR}
EOF
fi

cat <<'EOF'

Next steps:
1. Review and customize the generated repository README.
2. operator-keys/ was seeded from this checkout's contrib/keys/operator-keys.
   It is a derived copy, never a trust source: before each release, rebuild it
   from the release's trusted ref with
     ./contrib/guix/init-supporting-repos.sh --resync-operator-keys <trusted-ref> <qbit-guix.sigs>
   The release publisher refuses a qbit-guix.sigs commit whose copy differs.
3. Add the GitHub remotes and push the initialized repositories.
4. For detached signatures, create per-release orphan branches when the first
   codesigned release is produced.
EOF
