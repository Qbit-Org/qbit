#!/usr/bin/env bash
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

export LC_ALL=C
set -euo pipefail

PREFIX="${LIBBITCOINPQC_PATH:-src/libbitcoinpqc}"
REMOTE_URL="${LIBBITCOINPQC_REMOTE_URL:-https://github.com/Qbit-Org/qbit-libbitcoinpqc.git}"
REMOTE_REF="${LIBBITCOINPQC_REMOTE_REF:-v0.3.0}"
APPROVED_RUSTSEC_CROSSBEAM_PATCH="RUSTSEC-2026-0204-crossbeam-epoch-0.9.20"
APPROVED_RUSTSEC_CROSSBEAM_DIFF_LINES=$'-version = "0.9.18"\n+version = "0.9.20"\n-checksum = "5b82ac4a3c2ca9c3460964f020e1402edd5753411d7737aa39c3714ad1b5420e"\n+checksum = "2d6914041f254d6e9176c01941b21115dcfb7089e55135a35411081bd106ef3f"'

usage() {
  cat <<EOF
Usage: $(basename "$0")

Verify that $PREFIX matches the tagged upstream libbitcoinpqc tree.

Environment overrides:
  LIBBITCOINPQC_PATH        default: src/libbitcoinpqc
  LIBBITCOINPQC_REMOTE_URL  default: https://github.com/Qbit-Org/qbit-libbitcoinpqc.git
  LIBBITCOINPQC_REMOTE_REF  default: v0.3.0
EOF
}

resolve_remote_commit() {
  local remote_url="$1"
  local remote_ref="$2"
  local ls_remote_output

  if ls_remote_output="$(git ls-remote --exit-code "${remote_url}" "${remote_ref}^{}" 2>/dev/null)"; then
    printf '%s\n' "${ls_remote_output}" | awk 'NR==1 {print $1}'
    return
  fi

  if ls_remote_output="$(git ls-remote --exit-code "${remote_url}" "${remote_ref}" 2>/dev/null)"; then
    printf '%s\n' "${ls_remote_output}" | awk 'NR==1 {print $1}'
  fi
}

approved_downstream_patch() {
  local base_tree="$1"
  local current_tree="$2"
  local changed_paths
  local changed_lines

  changed_paths="$(git diff --name-only "${base_tree}" "${current_tree}")"
  if [[ "${changed_paths}" != "Cargo.lock" ]]; then
    return 1
  fi

  changed_lines="$(
    git diff --unified=0 --no-ext-diff "${base_tree}" "${current_tree}" -- Cargo.lock |
    awk '/^[-+]/ && $0 !~ /^(---|\+\+\+)/ {print}'
  )"
  [[ "${changed_lines}" == "${APPROVED_RUSTSEC_CROSSBEAM_DIFF_LINES}" ]]
}

verify_tree_match_or_approved_patch() {
  local base_tree="$1"
  local current_tree="$2"
  local failure_message="$3"

  if [[ "${current_tree}" == "${base_tree}" ]]; then
    return 0
  fi

  if approved_downstream_patch "${base_tree}" "${current_tree}"; then
    echo "GOOD: approved downstream libbitcoinpqc patch ${APPROVED_RUSTSEC_CROSSBEAM_PATCH}"
    return 0
  fi

  git diff --stat "${base_tree}" "${current_tree}" >&2 || true
  echo "FAIL: ${failure_message}" >&2
  exit 1
}

if [[ "${1-}" == "--help" || "${1-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 0 ]]; then
  usage >&2
  exit 2
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "FAIL: must run inside a git worktree" >&2
  exit 1
fi

current_tree="$(git rev-parse "HEAD:${PREFIX}" 2>/dev/null || true)"
if [[ -z "${current_tree}" ]]; then
  echo "FAIL: subtree directory ${PREFIX} not found in HEAD" >&2
  exit 1
fi

upstream_commit="$(resolve_remote_commit "${REMOTE_URL}" "${REMOTE_REF}")"
if [[ -z "${upstream_commit}" ]]; then
  echo "FAIL: unable to resolve ${REMOTE_URL} ${REMOTE_REF}" >&2
  exit 1
fi

if ! git cat-file -e "${upstream_commit}^{commit}" 2>/dev/null; then
  git fetch --depth=1 "${REMOTE_URL}" "${REMOTE_REF}" >/dev/null
fi

if ! git cat-file -e "${upstream_commit}^{commit}" 2>/dev/null; then
  echo "FAIL: upstream commit ${upstream_commit} unavailable after fetch" >&2
  exit 1
fi

upstream_commit="$(git rev-parse "${upstream_commit}^{commit}")"
upstream_tree="$(git show -s --format=%T "${upstream_commit}")"
metadata_commit="$(
  git log \
    --grep="^git-subtree-dir: ${PREFIX}/*$" \
    --format=%H \
    -n 1 \
    HEAD
)"
metadata_split=""
metadata_tree=""
if [[ -n "${metadata_commit}" ]]; then
  metadata_split="$(
    git show -s --format=%B "${metadata_commit}" |
    awk '/^git-subtree-split: / {print $2; exit}'
  )"
  metadata_tree="$(git rev-parse "${metadata_commit}:${PREFIX}" 2>/dev/null || true)"
fi

echo "${PREFIX} in HEAD currently refers to tree ${current_tree}"
echo "${REMOTE_URL} ${REMOTE_REF} resolves to commit ${upstream_commit} tree ${upstream_tree}"

if [[ -z "${metadata_commit}" ]]; then
  echo "FAIL: subtree metadata missing: no git-subtree-dir entry found for ${PREFIX}" >&2
  exit 1
fi

if [[ -z "${metadata_split}" ]]; then
  echo "FAIL: subtree metadata missing: no git-subtree-split entry found for ${PREFIX}" >&2
  exit 1
fi

if [[ -z "${metadata_tree}" ]]; then
  echo "FAIL: subtree import commit ${metadata_commit} lacks ${PREFIX}" >&2
  exit 1
fi

echo "${PREFIX} latest git-subtree import commit is ${metadata_commit} tree ${metadata_tree}"
echo "${PREFIX} latest git-subtree-split is ${metadata_split}"
if [[ "${metadata_split}" != "${upstream_commit}" ]]; then
  echo "FAIL: subtree split ${metadata_split} does not match upstream tag commit ${upstream_commit}" >&2
  exit 1
fi

verify_tree_match_or_approved_patch \
  "${metadata_tree}" \
  "${current_tree}" \
  "${PREFIX} tree differs from latest subtree import commit ${metadata_commit}"

verify_tree_match_or_approved_patch \
  "${upstream_tree}" \
  "${current_tree}" \
  "${PREFIX} tree differs from upstream tag ${REMOTE_REF}"

echo "GOOD"
