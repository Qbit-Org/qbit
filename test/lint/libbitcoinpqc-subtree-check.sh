#!/usr/bin/env bash
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

export LC_ALL=C
set -euo pipefail

# shellcheck source=libbitcoinpqc-release-tag.sh
source "$(dirname "${BASH_SOURCE[0]}")/libbitcoinpqc-release-tag.sh"

# The prefix is fixed, so no inherited variable can point the check elsewhere.
readonly PREFIX="${LIBBITCOINPQC_PREFIX}"
REMOTE_URL="${LIBBITCOINPQC_REMOTE_URL:-${LIBBITCOINPQC_UPSTREAM_URL}}"
REMOTE_REF="${LIBBITCOINPQC_REMOTE_REF:-v0.3.2}"
# The fetched tag object is held here while the check runs.
readonly TAG_REF="refs/libbitcoinpqc-subtree-check/tag"

usage() {
  cat <<EOF
Usage: $(basename "$0") [--test-signer-cert <path> --test-signer-fingerprint <fpr>]

Verify that the upstream libbitcoinpqc release tag has a good signature from
the pinned signer, and that $PREFIX matches its tree.

Environment overrides:
  LIBBITCOINPQC_REMOTE_URL  default: ${LIBBITCOINPQC_UPSTREAM_URL}
  LIBBITCOINPQC_REMOTE_REF  default: v0.3.2

Test-only options, accepted only when the remote is a local repository:
  --test-signer-cert <path>          Replace the pinned signer certificate,
                                     ${LIBBITCOINPQC_SIGNER_CERT}.
  --test-signer-fingerprint <fpr>    Replace the pinned signing fingerprint,
                                     ${LIBBITCOINPQC_SIGNER_FINGERPRINT}.
EOF
}

verify_tree_match() {
  local base_tree="$1"
  local current_tree="$2"
  local failure_message="$3"

  if [[ "${current_tree}" == "${base_tree}" ]]; then
    return 0
  fi

  git diff --stat "${base_tree}" "${current_tree}" >&2 || true
  echo "FAIL: ${failure_message}" >&2
  exit 1
}

signer_cert="${LIBBITCOINPQC_SIGNER_CERT}"
signer_fingerprint="${LIBBITCOINPQC_SIGNER_FINGERPRINT}"
test_signer_cert=""
test_signer_fingerprint=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --test-signer-cert | --test-signer-fingerprint)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "FAIL: $1 requires a value" >&2
        exit 2
      fi
      if [[ "$1" == --test-signer-cert ]]; then
        test_signer_cert="$2"
      else
        test_signer_fingerprint="$2"
      fi
      shift
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "FAIL: must run inside a git worktree" >&2
  exit 1
fi

if [[ -n "${test_signer_cert}${test_signer_fingerprint}" ]]; then
  if [[ -z "${test_signer_cert}" || -z "${test_signer_fingerprint}" ]]; then
    echo "FAIL: --test-signer-cert and --test-signer-fingerprint must be given together" >&2
    exit 2
  fi
  if ! libbitcoinpqc_is_local_remote "${REMOTE_URL}"; then
    echo "FAIL: test signer options are accepted only for a local repository, not ${REMOTE_URL}" >&2
    exit 1
  fi
  [[ "${test_signer_cert}" == /* ]] || test_signer_cert="${PWD}/${test_signer_cert}"
  signer_cert="${test_signer_cert}"
  signer_fingerprint="${test_signer_fingerprint}"
  echo "warning: TEST SIGNER IN USE (${signer_fingerprint})" >&2
else
  signer_cert="$(git rev-parse --show-toplevel)/${signer_cert}"
fi
if [[ ! -f "${signer_cert}" ]]; then
  echo "FAIL: signer certificate not found: ${signer_cert}" >&2
  exit 1
fi

# Verify the release tag before any split or tree check: fetch the tag object
# itself into a private ref, removed on every exit, and require the pinned
# signer. The whole upstream history is small; a --depth fetch would mark this
# repository shallow.
trap 'git update-ref -d "${TAG_REF}" >/dev/null 2>&1 || true' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if ! tag_object="$(libbitcoinpqc_fetch_tag "${REMOTE_URL}" "${REMOTE_REF}" "${TAG_REF}")"; then
  echo "FAIL: unable to fetch refs/tags/${REMOTE_REF} from ${REMOTE_URL}" >&2
  exit 1
fi
if ! libbitcoinpqc_verify_tag "${tag_object}" "${REMOTE_REF}" "${signer_cert}" "${signer_fingerprint}"; then
  echo "FAIL: ${REMOTE_URL} ${REMOTE_REF} is not a release tag signed by ${signer_fingerprint}" >&2
  exit 1
fi
upstream_commit="$(git rev-parse --verify "${tag_object}^{commit}")"
upstream_tree="$(git rev-parse --verify "${upstream_commit}^{tree}")"
echo "${REMOTE_REF} tag object ${tag_object} has a good signature from ${signer_fingerprint}"

current_tree="$(git rev-parse "HEAD:${PREFIX}" 2>/dev/null || true)"
if [[ -z "${current_tree}" ]]; then
  echo "FAIL: subtree directory ${PREFIX} not found in HEAD" >&2
  exit 1
fi

# Search only non-merge commits, so a merge commit whose pull request title
# quotes the trailer cannot be picked. No pathspec: an import commit that only
# moves git-subtree-split leaves the prefix unchanged and must still be found.
# A later non-merge commit that quotes the trailer can only make this check
# fail closed, never pass.
metadata_commit="$(libbitcoinpqc_latest_import)"
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

verify_tree_match \
  "${metadata_tree}" \
  "${current_tree}" \
  "${PREFIX} tree differs from latest subtree import commit ${metadata_commit}"

verify_tree_match \
  "${upstream_tree}" \
  "${current_tree}" \
  "${PREFIX} tree differs from upstream tag ${REMOTE_REF}"

echo "GOOD"
