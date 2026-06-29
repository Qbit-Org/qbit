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
metadata_split="$(
  git log \
    --grep="^git-subtree-dir: ${PREFIX}/*$" \
    --pretty=format:%B \
    HEAD |
  awk '/^git-subtree-split: / {print $2; exit}'
)"

echo "${PREFIX} in HEAD currently refers to tree ${current_tree}"
echo "${REMOTE_URL} ${REMOTE_REF} resolves to commit ${upstream_commit} tree ${upstream_tree}"

if [[ -z "${metadata_split}" ]]; then
  echo "FAIL: subtree metadata missing: no git-subtree-split entry found for ${PREFIX}" >&2
  exit 1
fi

echo "${PREFIX} latest git-subtree-split is ${metadata_split}"
if [[ "${metadata_split}" != "${upstream_commit}" ]]; then
  echo "FAIL: subtree split ${metadata_split} does not match upstream tag commit ${upstream_commit}" >&2
  exit 1
fi

if [[ "${current_tree}" != "${upstream_tree}" ]]; then
  git diff --stat "${upstream_tree}" "${current_tree}" >&2 || true
  echo "FAIL: ${PREFIX} tree differs from upstream tag ${REMOTE_REF}" >&2
  exit 1
fi

echo "GOOD"
