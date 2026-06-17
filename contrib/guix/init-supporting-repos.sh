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

init_guix_sigs_repo() {
    local repo_dir="$1"
    local public_key
    init_git_repo "${repo_dir}"
    copy_if_missing "${TEMPLATE_DIR}/qbit-guix.sigs/README.md" "${repo_dir}/README.md"
    copy_if_missing "${TEMPLATE_DIR}/qbit-guix.sigs/operator-keys/keys.json" "${repo_dir}/operator-keys/keys.json"
    mkdir -p "${repo_dir}/operator-keys/public-keys"
    if [[ -d "${TEMPLATE_DIR}/qbit-guix.sigs/operator-keys/public-keys" ]]; then
        for public_key in "${TEMPLATE_DIR}/qbit-guix.sigs/operator-keys/public-keys"/*.asc; do
            [[ -e "${public_key}" ]] || continue
            copy_if_missing "${public_key}" "${repo_dir}/operator-keys/public-keys/$(basename "${public_key}")"
        done
    fi
    mkdir -p "${repo_dir}/operator-keys/approvals"
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
2. Replace operator-keys/keys.json with the canonical release signer policy.
3. Mirror the referenced signer public certificates under
   operator-keys/public-keys/ and policy approval material under
   operator-keys/approvals/.
4. Add the GitHub remotes and push the initialized repositories.
5. For detached signatures, create per-release orphan branches when the first
   codesigned release is produced.
EOF
