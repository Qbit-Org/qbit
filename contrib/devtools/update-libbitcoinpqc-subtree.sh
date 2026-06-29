#!/usr/bin/env bash
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

export LC_ALL=C
set -euo pipefail

derive_default_remote_url() {
  printf 'https://github.com/Qbit-Org/qbit-libbitcoinpqc.git'
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

readonly PREFIX="src/libbitcoinpqc"
DEFAULT_REMOTE_URL="$(derive_default_remote_url)"
readonly DEFAULT_REMOTE_URL
readonly DEFAULT_REMOTE_REF="v0.3.0"

REMOTE_URL="${LIBBITCOINPQC_REMOTE_URL:-$DEFAULT_REMOTE_URL}"
REMOTE_REF="${LIBBITCOINPQC_REMOTE_REF:-$DEFAULT_REMOTE_REF}"

if [[ "${1-}" == "--help" ]]; then
  cat <<EOF
Usage: $(basename "$0") [REF]

Update the $PREFIX subtree from the pinned upstream release tag.
See doc/subtrees/libbitcoinpqc.md for the full two-repo workflow.

Environment overrides:
  LIBBITCOINPQC_REMOTE_URL   default: $DEFAULT_REMOTE_URL
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
EXPECTED_UPSTREAM_COMMIT="$(resolve_remote_commit "${REMOTE_URL}" "${REMOTE_REF}")"

if [[ -n "${EXPECTED_UPSTREAM_COMMIT}" ]]; then
  echo "Expected upstream commit: ${EXPECTED_UPSTREAM_COMMIT}"
else
  echo "error: expected upstream commit unavailable (git ls-remote failed)" >&2
  exit 1
fi

if git rev-parse --verify "HEAD:${PREFIX}" >/dev/null 2>&1; then
  echo "Running subtree pull for ${PREFIX} from ${REMOTE_URL} ${REMOTE_REF}"
  git subtree pull --prefix="${PREFIX}" "${REMOTE_URL}" "${REMOTE_REF}" --squash
else
  echo "Running subtree add for ${PREFIX} from ${REMOTE_URL} ${REMOTE_REF}"
  git subtree add --prefix="${PREFIX}" "${REMOTE_URL}" "${REMOTE_REF}" --squash
fi

LIBBITCOINPQC_REMOTE_URL="${REMOTE_URL}" \
LIBBITCOINPQC_REMOTE_REF="${REMOTE_REF}" \
  test/lint/libbitcoinpqc-subtree-check.sh

echo "Subtree update and integrity check completed for ${PREFIX}."
