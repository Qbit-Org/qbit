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
Usage: $(basename "$0") [<commit>]

Replace ${PREFIX} with the upstream mlkem/ directory and LICENSE of an
mlkem-native release, unmodified, rewrite ${PIN_FILE} from the fetched
upstream object ids, and stage both.

  <commit>    tag or commit to vendor (default: REMOTE_REF, else the pinned tag)

Environment overrides:
  REMOTE_URL  default: the url= entry of ${PIN_FILE}
  REMOTE_REF  default: the tag= entry of ${PIN_FILE}

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
  awk -F= -v key="$1" '$1 == key { print substr($0, length(key) + 2); exit }' "${PIN_FILE}"
}

if [[ "${1-}" == "--help" || "${1-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ $# -gt 1 ]]; then
  usage >&2
  exit 2
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  fail "not inside a git work tree" \
    "the update stages the vendored tree with git" \
    "run it from the root of a qbit checkout"
fi
cd "$(git rev-parse --show-toplevel)"

pinned_url="$(pin_value url)"
pinned_tag="$(pin_value tag)"
pinned_commit="$(pin_value commit)"

REMOTE_URL="${REMOTE_URL:-${pinned_url}}"
REMOTE_REF="${1:-${REMOTE_REF:-${pinned_tag}}}"
if [[ -z "${REMOTE_URL}" || -z "${REMOTE_REF}" ]]; then
  fail "no upstream url or ref" \
    "${PIN_FILE} lacks url= or tag= and no override was given" \
    "restore ${PIN_FILE} from git, or set REMOTE_URL and pass a tag"
fi

echo "Fetching mlkem-native ${REMOTE_REF} from ${REMOTE_URL}"
if ! git fetch --quiet --depth=1 --no-tags "${REMOTE_URL}" "${REMOTE_REF}"; then
  fail "git fetch ${REMOTE_URL} ${REMOTE_REF} failed" \
    "the ref does not exist upstream, or the network is unavailable" \
    "check the tag name at ${REMOTE_URL}, or retry with network access"
fi
commit="$(git rev-parse "FETCH_HEAD^{commit}")"

# A tag that resolves to a different commit than the pin means upstream moved
# it; never follow that silently.
if [[ "${REMOTE_REF}" == "${pinned_tag}" && "${commit}" != "${pinned_commit}" ]]; then
  fail "${REMOTE_REF} resolves to ${commit}, but ${PIN_FILE} pins ${pinned_commit}" \
    "the upstream tag was moved or ${REMOTE_URL} is not the pinned repository" \
    "stop and investigate upstream; to vendor a different commit deliberately, pass it explicitly"
fi

tag="${REMOTE_REF}"
if [[ "${REMOTE_REF}" =~ ^[0-9a-f]{40}$ ]]; then
  tag="$(git ls-remote --tags "${REMOTE_URL}" |
    awk -v c="${commit}" '$1 == c { sub("^refs/tags/", "", $2); sub("\\^\\{\\}$", "", $2); print $2; exit }')"
  if [[ -z "${tag}" ]]; then
    echo "warning: ${commit} has no upstream tag; releases must vendor a tagged commit" >&2
    tag="untagged"
  fi
fi

upstream_tree="$(git rev-parse "${commit}:mlkem")"
upstream_license="$(git rev-parse "${commit}:LICENSE")"

echo "Replacing ${PREFIX} with ${commit}:mlkem and ${commit}:LICENSE"
rm -rf -- "${PREFIX}"
mkdir -p -- "${PREFIX}"
git archive --format=tar "${commit}" mlkem LICENSE | tar -xf - -C "${PREFIX}"

cat > "${PIN_FILE}" <<EOF
# mlkem-native vendored into src/mlkem-native. Written by
# contrib/devtools/update-mlkem-native.sh; checked by
# test/lint/mlkem-native-check.sh. See doc/subtrees/mlkem-native.md.
url=${REMOTE_URL}
tag=${tag}
commit=${commit}
mlkem_tree=${upstream_tree}
license_blob=${upstream_license}
EOF

# Stage with --force so that no qbit ignore rule can drop an upstream file, then
# prove the staged bytes are exactly upstream's.
git add --all --force -- "${PREFIX}" "${PIN_FILE}"
staged_tree="$(git write-tree --prefix="${PREFIX}/mlkem/")"
staged_license="$(git rev-parse ":${PREFIX}/LICENSE")"
if [[ "${staged_tree}" != "${upstream_tree}" || "${staged_license}" != "${upstream_license}" ]]; then
  fail "staged ${PREFIX} (tree ${staged_tree}, LICENSE ${staged_license}) differs from upstream (tree ${upstream_tree}, LICENSE ${upstream_license})" \
    "a git attribute, filter or line-ending setting rewrote vendored bytes" \
    "remove the attribute or core.autocrlf/core.eol setting that applies to ${PREFIX} and re-run"
fi

echo "Staged mlkem-native ${tag} (${commit}): mlkem tree ${upstream_tree}, LICENSE blob ${upstream_license}"
if git diff --cached --quiet HEAD -- "${PREFIX}" "${PIN_FILE}"; then
  echo "${PREFIX} already matches; nothing to commit."
  exit 0
fi
cat <<EOF

${PREFIX} changed. Before committing, follow the PR checklist in
doc/subtrees/mlkem-native.md, in particular:
  - qbit's src/crypto/mlkem_config.h, mlkem_arith_backend.h and
    mlkem_fips202_backend.h include upstream paths and config macros; check
    them against the new upstream tree and its release notes;
  - rebuild and run: test_qbit --run_test=mlkem_tests (native and with
    MLKEM_FORCE_PORTABLE=1), the mlkem and mlkem_backend_diff fuzz targets,
    bench_qbit -filter='MLKEM.*', and ci/checks/test_mlkem_build_policy.py;
  - repeat the readelf GNU property comparison and the Guix build;
  - after committing, run test/lint/mlkem-native-check.sh.
EOF
