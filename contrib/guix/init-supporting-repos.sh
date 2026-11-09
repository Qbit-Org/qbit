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

This creates local git repositories seeded with qbit-specific README files and
layout scaffolding for the supporting repositories described in the release
process.
EOF
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
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
    PYTHONPATH="${REPO_ROOT}/ci/release" python3 - "${CANONICAL_KEYS_DIR}" <<'PY'
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
   It is a derived copy, never a trust source: before each release, re-sync it
   from contrib/keys/operator-keys at the release's trusted ref. The release
   publisher refuses a qbit-guix.sigs commit whose copy differs.
3. Add the GitHub remotes and push the initialized repositories.
4. For detached signatures, create per-release orphan branches when the first
   codesigned release is produced.
EOF
