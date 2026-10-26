#!/usr/bin/env bash
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

export LC_ALL=C
set -euo pipefail

readonly PREFIX="src/mlkem-native"
readonly PIN_FILE="contrib/devtools/mlkem-native.pin"

usage() {
  cat <<EOF
Usage: $(basename "$0")

Verify offline that ${PREFIX} is byte-identical to the mlkem-native release
pinned in ${PIN_FILE}: the git tree id of ${PREFIX}/mlkem and the blob id of
${PREFIX}/LICENSE in HEAD must equal the pinned ids, ${PREFIX} must hold
nothing else, and the work tree must have no edits under ${PREFIX}.

See doc/subtrees/mlkem-native.md.
EOF
}

fail() {
  local signature="$1"
  local cause="$2"
  local fix="$3"
  echo "FAIL: ${signature}" >&2
  echo "  Cause: ${cause}" >&2
  echo "  Fix: ${fix}" >&2
  exit 1
}

pin_value() {
  local key="$1"
  local value
  value="$(awk -F= -v key="${key}" '$1 == key { print substr($0, length(key) + 2); exit }' "${PIN_FILE}")"
  if [[ -z "${value}" ]]; then
    fail "${PIN_FILE} has no ${key}= entry" \
      "the pin file was edited by hand or truncated" \
      "restore ${PIN_FILE} from git, or regenerate it with contrib/devtools/update-mlkem-native.sh"
  fi
  printf '%s\n' "${value}"
}

require_object_id() {
  local key="$1"
  local value="$2"
  if [[ ! "${value}" =~ ^[0-9a-f]{40}$ ]]; then
    fail "${PIN_FILE} ${key}=${value} is not a 40-digit object id" \
      "the pin file was edited by hand" \
      "restore ${PIN_FILE} from git, or regenerate it with contrib/devtools/update-mlkem-native.sh"
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
  fail "not inside a git work tree" \
    "the check compares git object ids" \
    "run it from the root of a qbit checkout"
fi
cd "$(git rev-parse --show-toplevel)"

if [[ ! -f "${PIN_FILE}" ]]; then
  fail "${PIN_FILE} not found" \
    "the pin file was deleted or the check runs outside the repository root" \
    "restore ${PIN_FILE} from git"
fi

pinned_tag="$(pin_value tag)"
pinned_commit="$(pin_value commit)"
pinned_tree="$(pin_value mlkem_tree)"
pinned_license="$(pin_value license_blob)"
require_object_id commit "${pinned_commit}"
require_object_id mlkem_tree "${pinned_tree}"
require_object_id license_blob "${pinned_license}"

echo "${PIN_FILE} pins mlkem-native ${pinned_tag} commit ${pinned_commit}"

top_entries="$(git ls-tree --name-only "HEAD:${PREFIX}" 2>/dev/null || true)"
if [[ -z "${top_entries}" ]]; then
  fail "${PREFIX} not found in HEAD" \
    "the vendored tree was removed or never committed" \
    "run contrib/devtools/update-mlkem-native.sh and commit the result"
fi
if [[ "${top_entries}" != $'LICENSE\nmlkem' ]]; then
  fail "${PREFIX} in HEAD holds entries other than LICENSE and mlkem: $(printf '%s' "${top_entries}" | tr '\n' ' ')" \
    "a file was added next to the vendored tree" \
    "move qbit-owned files out of ${PREFIX} (ML-KEM glue lives in src/crypto/mlkem*)"
fi

current_tree="$(git rev-parse "HEAD:${PREFIX}/mlkem")"
echo "${PREFIX}/mlkem in HEAD is tree ${current_tree}"
if [[ "${current_tree}" != "${pinned_tree}" ]]; then
  git diff --stat "${pinned_tree}" "${current_tree}" >&2 2>/dev/null || true
  fail "${PREFIX}/mlkem tree ${current_tree} differs from pinned tree ${pinned_tree}" \
    "a vendored file was edited, added, removed or changed mode, or the pin was changed without re-vendoring" \
    "never edit ${PREFIX}; restore it with contrib/devtools/update-mlkem-native.sh"
fi

current_license="$(git rev-parse "HEAD:${PREFIX}/LICENSE")"
echo "${PREFIX}/LICENSE in HEAD is blob ${current_license}"
if [[ "${current_license}" != "${pinned_license}" ]]; then
  fail "${PREFIX}/LICENSE blob ${current_license} differs from pinned blob ${pinned_license}" \
    "the vendored LICENSE was edited, or the pin was changed without re-vendoring" \
    "never edit ${PREFIX}; restore it with contrib/devtools/update-mlkem-native.sh"
fi

dirty="$(git status --porcelain --untracked-files=all -- "${PREFIX}")"
if [[ -n "${dirty}" ]]; then
  printf '%s\n' "${dirty}" >&2
  fail "uncommitted changes under ${PREFIX}" \
    "a vendored file was edited, added or removed in the work tree or index" \
    "discard them with: git checkout HEAD -- ${PREFIX} && git clean -fdx -- ${PREFIX}"
fi

echo "GOOD"
