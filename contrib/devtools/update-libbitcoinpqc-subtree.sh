#!/usr/bin/env bash
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

export LC_ALL=C
set -euo pipefail

derive_default_remote_url() {
  local origin_url owner
  origin_url="$(git config --get remote.origin.url 2>/dev/null || true)"
  owner="$(printf '%s\n' "${origin_url}" | sed -E -n 's#.*github.com[:/]([^/]+)/qbit(\.git)?$#\1#p')"
  if [[ -n "${owner}" ]]; then
    printf 'git@github.com:%s/libbitcoinpqc-qbit.git' "${owner}"
  else
    printf 'git@github.com:<owner>/libbitcoinpqc-qbit.git'
  fi
}

readonly PREFIX="src/libbitcoinpqc"
DEFAULT_REMOTE_URL="$(derive_default_remote_url)"
readonly DEFAULT_REMOTE_URL
readonly DEFAULT_REMOTE_REF="qbit-subtree"

REMOTE_URL="${LIBBITCOINPQC_REMOTE_URL:-$DEFAULT_REMOTE_URL}"
REMOTE_REF="${LIBBITCOINPQC_REMOTE_REF:-$DEFAULT_REMOTE_REF}"

if [[ "${1-}" == "--help" ]]; then
  cat <<EOF
Usage: $(basename "$0") [REF]

Update the $PREFIX subtree from the curated upstream branch.
See doc/subtrees/libbitcoinpqc.md for the full two-repo workflow.
qbit does not keep a local prune helper; use
libbitcoinpqc-qbit:develop:scripts/prune-for-qbit-subtree.sh when refreshing
the upstream curated branch.

Environment overrides:
  LIBBITCOINPQC_REMOTE_URL   default: git@github.com:<owner>/libbitcoinpqc-qbit.git
                             (<owner> is inferred from local origin remote)
  LIBBITCOINPQC_REMOTE_REF   default: $DEFAULT_REMOTE_REF

Argument:
  REF  Optional branch/tag/commit to pull from REMOTE_URL.
EOF
  exit 0
fi

if [[ $# -gt 1 ]]; then
  echo "error: expected at most 1 argument (REF)" >&2
  exit 1
fi

if [[ $# -eq 1 ]]; then
  REMOTE_REF="$1"
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "error: must run inside a git worktree" >&2
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "error: working tree must be clean before subtree update" >&2
  exit 1
fi

echo "Subtree source:"
echo "  remote: ${REMOTE_URL}"
echo "  ref:    ${REMOTE_REF}"

EXPECTED_UPSTREAM_COMMIT=""
if LS_REMOTE_OUTPUT="$(git ls-remote --exit-code "${REMOTE_URL}" "${REMOTE_REF}" 2>/dev/null)"; then
  EXPECTED_UPSTREAM_COMMIT="$(printf '%s\n' "${LS_REMOTE_OUTPUT}" | awk 'NR==1 {print $1}')"
fi

if [[ -n "${EXPECTED_UPSTREAM_COMMIT}" ]]; then
  echo "Expected upstream commit: ${EXPECTED_UPSTREAM_COMMIT}"
else
  echo "Expected upstream commit: unavailable (git ls-remote failed)"
  echo "Proceeding with local subtree checks only."
fi

if git rev-parse --verify "HEAD:${PREFIX}" >/dev/null 2>&1; then
  echo "Running subtree pull for ${PREFIX} from ${REMOTE_URL} ${REMOTE_REF}"
  git subtree pull --prefix="${PREFIX}" "${REMOTE_URL}" "${REMOTE_REF}" --squash
else
  echo "Running subtree add for ${PREFIX} from ${REMOTE_URL} ${REMOTE_REF}"
  git subtree add --prefix="${PREFIX}" "${REMOTE_URL}" "${REMOTE_REF}" --squash
fi

if [[ -n "${EXPECTED_UPSTREAM_COMMIT}" ]]; then
  test/lint/git-subtree-check.sh -r "${PREFIX}"
else
  test/lint/git-subtree-check.sh "${PREFIX}"
fi

echo "Subtree update and integrity check completed for ${PREFIX}."
