#!/usr/bin/env bash
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

export LC_ALL=C
set -euo pipefail

# The release-tag check, shared with test/lint/libbitcoinpqc-subtree-check.sh.
# shellcheck source=../../test/lint/libbitcoinpqc-release-tag.sh
source "$(dirname "${BASH_SOURCE[0]}")/../../test/lint/libbitcoinpqc-release-tag.sh"

readonly PREFIX="${LIBBITCOINPQC_PREFIX}"
readonly DEFAULT_REMOTE_REF="v0.3.0"
# The fetched tag object is held here while the helper runs.
readonly TAG_REF="refs/libbitcoinpqc-import/tag"

REMOTE_URL="${LIBBITCOINPQC_REMOTE_URL:-$LIBBITCOINPQC_UPSTREAM_URL}"
REMOTE_REF="${LIBBITCOINPQC_REMOTE_REF:-$DEFAULT_REMOTE_REF}"
# The signer is pinned. Only explicit test flags can replace it, and only for a
# local repository; no environment variable can.
SIGNER_CERT="${LIBBITCOINPQC_SIGNER_CERT}"
SIGNER_FINGERPRINT="${LIBBITCOINPQC_SIGNER_FINGERPRINT}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [--allow-downgrade] [--accept-upstream <path>]... [<tag>]

Refresh an existing $PREFIX import to a signed qbit-libbitcoinpqc release tag,
as one main-line commit that carries git-subtree-dir and git-subtree-split
trailers, then run test/lint/libbitcoinpqc-subtree-check.sh. Every check runs
before the tree changes; a failed subtree check undoes the import commit.
A first import is a maintainer task outside this helper.
See doc/subtrees/libbitcoinpqc.md for the checks and the delta review.

Options:
  --allow-downgrade          Import a tag that does not descend from the
                             current git-subtree-split.
  --accept-upstream <path>   Take the release's version of <path> (relative to
                             $PREFIX) although the qbit subtree differs there.
                             Name each path the helper lists, once per path.

Argument:
  <tag>  Release tag to import. Default: LIBBITCOINPQC_REMOTE_REF, else $DEFAULT_REMOTE_REF.

Environment overrides:
  LIBBITCOINPQC_REMOTE_URL   default: $LIBBITCOINPQC_UPSTREAM_URL
  LIBBITCOINPQC_REMOTE_REF   default: $DEFAULT_REMOTE_REF

Test-only options (for the helper's tests, never for a real import):
  --test-signer-cert <path>          Replace the pinned signer certificate,
                                     $LIBBITCOINPQC_SIGNER_CERT.
  --test-signer-fingerprint <fpr>    Replace the pinned signing fingerprint,
                                     $LIBBITCOINPQC_SIGNER_FINGERPRINT.
  Both must be given together, they are refused unless the remote is a local
  repository, and the helper warns loudly when they are used.
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

contains() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    [[ "${item}" == "${needle}" ]] && return 0
  done
  return 1
}

# merge-tree names a conflicted entry it had to move aside path~<object id>.
# Map such names back to the real path.
real_path() {
  local path="$1"
  if [[ "${path}" == *~* && "${path##*~}" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]; then
    path="${path%~*}"
  fi
  printf '%s' "${path}"
}

allow_downgrade=0
accept_upstream=()
tag=""
test_signer_cert=""
test_signer_fingerprint=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --allow-downgrade)
      allow_downgrade=1
      ;;
    --accept-upstream)
      [[ $# -ge 2 && -n "$2" ]] || die "--accept-upstream requires a path"
      accept_upstream+=("$2")
      shift
      ;;
    --test-signer-cert)
      [[ $# -ge 2 && -n "$2" ]] || die "--test-signer-cert requires a path"
      test_signer_cert="$2"
      shift
      ;;
    --test-signer-fingerprint)
      [[ $# -ge 2 && -n "$2" ]] || die "--test-signer-fingerprint requires a fingerprint"
      test_signer_fingerprint="$2"
      shift
      ;;
    -*)
      die "unknown option: $1 (see --help)"
      ;;
    *)
      [[ -z "${tag}" ]] || die "expected at most one tag (see --help)"
      tag="$1"
      ;;
  esac
  shift
done
tag="${tag:-$REMOTE_REF}"
test_signer=0
if [[ -n "${test_signer_cert}${test_signer_fingerprint}" ]]; then
  [[ -n "${test_signer_cert}" && -n "${test_signer_fingerprint}" ]] \
    || die "--test-signer-cert and --test-signer-fingerprint must be given together"
  [[ "${test_signer_cert}" == /* ]] || test_signer_cert="${PWD}/${test_signer_cert}"
  SIGNER_CERT="${test_signer_cert}"
  SIGNER_FINGERPRINT="${test_signer_fingerprint}"
  test_signer=1
fi

git check-ref-format "refs/tags/${tag}" || die "not a valid tag name: ${tag}"
[[ "${SIGNER_FINGERPRINT}" =~ ^[0-9A-F]{40}$ ]] \
  || die "signer fingerprint must be 40 upper-case hex digits: ${SIGNER_FINGERPRINT}"

# The downstream-delta check passes trees, not commits, to git merge-tree.
git_version="$(git version)"
git_major_minor="$(
  printf '%s\n' "${git_version}" \
    | sed -n 's/^git version \([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2/p'
)"
[[ -n "${git_major_minor}" ]] || die "cannot parse '${git_version}'; Git 2.45 or later is required"
read -r git_major git_minor <<<"${git_major_minor}"
if (( git_major < 2 || (git_major == 2 && git_minor < 45) )); then
  die "Git 2.45 or later is required; found '${git_version}'"
fi

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "must run inside a git worktree"
# A relative path names a repository relative to where the helper started, so
# make it absolute before changing to the top-level directory. A URL, an
# scp-like host:path or the name of a configured remote is left as it is.
if [[ "${REMOTE_URL}" != /* && "${REMOTE_URL}" != *://* ]] \
  && [[ "${REMOTE_URL}" != *:* || "${REMOTE_URL%%:*}" == */* ]] \
  && ! git remote get-url "${REMOTE_URL}" >/dev/null 2>&1; then
  REMOTE_URL="${PWD}/${REMOTE_URL}"
fi
if [[ "${test_signer}" -eq 1 ]]; then
  libbitcoinpqc_is_local_remote "${REMOTE_URL}" \
    || die "--test-signer-cert and --test-signer-fingerprint are accepted only for a local repository, not ${REMOTE_URL}"
  echo "warning: TEST SIGNER IN USE: not for real imports (${SIGNER_FINGERPRINT})" >&2
fi
cd "$(git rev-parse --show-toplevel)"
[[ -f "${SIGNER_CERT}" ]] || die "signer certificate not found: ${SIGNER_CERT}"

# Nothing but the import may land in the import commit.
git diff --quiet HEAD -- || die "the worktree has changes; commit or stash them first"
git diff --cached --quiet -- || die "the index has staged changes; commit or unstage them first"
[[ -z "$(git ls-files --others --exclude-standard -- "${PREFIX}")" ]] \
  || die "untracked files under ${PREFIX}; remove them first"
[[ -z "$(git ls-files --others -- "${PREFIX}")" ]] \
  || die "ignored files under ${PREFIX}; list them with git clean -ndX ${PREFIX} and remove them first"

# One EXIT trap removes the private tag ref and the scratch files, and undoes
# an import whose checks have not all passed: it resets an import commit away,
# or restores a prefix changed before the commit; the prefix was clean,
# including ignored files, before the import started. INT, TERM and HUP exit
# through it too, so an interrupt still leaves a verified state.
work_dir=""
pre_import_head=""
import_started=0
import_verified=0
undo_reason="the import stopped before the subtree check passed"
cleanup() {
  trap '' INT TERM HUP
  if [[ "${import_started}" -eq 1 && "${import_verified}" -ne 1 ]]; then
    if [[ "$(git rev-parse -q --verify HEAD)" == "${pre_import_head}" ]]; then
      git reset -q -- "${PREFIX}" || true
      git checkout -q -- "${PREFIX}" || true
      git clean -q -fdx -- "${PREFIX}" || true
    elif [[ "$(git rev-parse -q --verify HEAD~1)" == "${pre_import_head}" ]] \
      && git reset -q --keep "${pre_import_head}"; then
      echo "error: ${undo_reason}; the import commit was undone" >&2
    else
      echo "error: ${undo_reason}; the import commit could not be undone; run git reset --hard ${pre_import_head}" >&2
    fi
  fi
  git update-ref -d "${TAG_REF}" >/dev/null 2>&1 || true
  if [[ -n "${work_dir}" ]]; then
    rm -rf "${work_dir}"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
work_dir="$(mktemp -d)"

# The current split is read the way test/lint/libbitcoinpqc-subtree-check.sh
# finds it: the newest non-merge commit with the trailer, in topological order
# and with no pathspec, so an import commit that only moved the split is found
# too.
import_commit="$(libbitcoinpqc_latest_import)"
[[ -n "${import_commit}" ]] || die "no git-subtree-dir commit for ${PREFIX}; this helper refreshes an existing import"
old_split="$(
  git show -s --format=%B "${import_commit}" \
    | awk '/^git-subtree-split: / && !found { found = $2 } END { print found }'
)"
[[ "${old_split}" =~ ^[0-9a-f]{40}$ ]] \
  || die "import commit ${import_commit} has no valid git-subtree-split"

echo "Fetching ${tag} from ${REMOTE_URL}"
tag_object="$(libbitcoinpqc_fetch_tag "${REMOTE_URL}" "${tag}" "${TAG_REF}")" \
  || die "could not fetch refs/tags/${tag} from ${REMOTE_URL}"
libbitcoinpqc_verify_tag "${tag_object}" "${tag}" "${SIGNER_CERT}" "${SIGNER_FINGERPRINT}" \
  || die "${tag} is not a release tag signed by ${SIGNER_FINGERPRINT}; not importing"

# Run the subtree check for the tag, with the same signer, and set lint_commit
# to the commit the check says the tag resolves to.
lint_args=()
if [[ "${test_signer}" -eq 1 ]]; then
  lint_args+=(--test-signer-cert "${SIGNER_CERT}" --test-signer-fingerprint "${SIGNER_FINGERPRINT}")
fi
lint_commit=""
run_subtree_check() {
  local status=0
  LIBBITCOINPQC_REMOTE_URL="${REMOTE_URL}" LIBBITCOINPQC_REMOTE_REF="${tag}" \
    test/lint/libbitcoinpqc-subtree-check.sh ${lint_args[@]+"${lint_args[@]}"} >"${work_dir}/lint" \
    || status=$?
  cat "${work_dir}/lint"
  lint_commit="$(
    awk '/ resolves to commit / { for (i = 1; i < NF; i++) if ($i == "commit") { print $(i + 1); exit } }' \
      "${work_dir}/lint"
  )"
  return "${status}"
}

upstream_commit="$(git rev-parse --verify "${tag_object}^{commit}")"
if [[ "${upstream_commit}" == "${old_split}" ]]; then
  echo "${PREFIX} already imports ${tag} (${upstream_commit}); checking it."
  run_subtree_check || die "${PREFIX} already imports ${tag}, but the subtree check failed"
  [[ "${lint_commit}" == "${upstream_commit}" ]] \
    || die "the subtree check verified ${lint_commit:-no commit}, not ${tag} (${upstream_commit})"
  exit 0
fi
if ! git cat-file -e "${old_split}^{commit}" 2>/dev/null; then
  git fetch --quiet --no-tags "${REMOTE_URL}" "${old_split}"
fi
if [[ "${allow_downgrade}" -ne 1 ]] \
  && ! git merge-base --is-ancestor "${old_split}" "${upstream_commit}"; then
  die "${tag} (${upstream_commit}) does not descend from the current split ${old_split}; pass --allow-downgrade to import it anyway"
fi

old_upstream_tree="$(git rev-parse --verify "${old_split}^{tree}")"
qbit_tree="$(git rev-parse --verify "HEAD:${PREFIX}")"
new_upstream_tree="$(git rev-parse --verify "${upstream_commit}^{tree}")"

# Merge the qbit subtree into the release, with the old release as the base.
# Where the result differs from the release, the import would drop a qbit
# change or override a conflicting one. Paths are read with plumbing and NUL
# separators, so quoting and rename detection cannot hide or mangle them.
merge_status=0
git merge-tree --write-tree -z --name-only --merge-base="${old_upstream_tree}" \
  "${qbit_tree}" "${new_upstream_tree}" >"${work_dir}/merge" || merge_status=$?
[[ "${merge_status}" -le 1 ]] || die "git merge-tree failed (status ${merge_status})"
merged_tree=""
conflicted_paths=()
{
  IFS= read -r -d '' merged_tree || true
  if [[ "${merge_status}" -eq 1 ]]; then
    # On a conflict, the merged tree is followed by the conflicted paths and an
    # empty field.
    while IFS= read -r -d '' path && [[ -n "${path}" ]]; do
      path="$(real_path "${path}")"
      contains "${path}" ${conflicted_paths[@]+"${conflicted_paths[@]}"} \
        || conflicted_paths+=("${path}")
    done
  fi
} <"${work_dir}/merge"
[[ "${merged_tree}" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || die "git merge-tree returned no tree"
git diff-tree -r -z --no-renames --name-only "${new_upstream_tree}" "${merged_tree}" \
  >"${work_dir}/differing" || die "git diff-tree failed"
differing_paths=()
while IFS= read -r -d '' path; do
  path="$(real_path "${path}")"
  contains "${path}" ${conflicted_paths[@]+"${conflicted_paths[@]}"} && continue
  contains "${path}" ${differing_paths[@]+"${differing_paths[@]}"} \
    || differing_paths+=("${path}")
done <"${work_dir}/differing"

for path in ${accept_upstream[@]+"${accept_upstream[@]}"}; do
  contains "${path}" ${conflicted_paths[@]+"${conflicted_paths[@]}"} \
    ${differing_paths[@]+"${differing_paths[@]}"} \
    || die "--accept-upstream ${path} does not name a path that differs from ${tag}"
done
unaccepted_conflicts=()
for path in ${conflicted_paths[@]+"${conflicted_paths[@]}"}; do
  contains "${path}" ${accept_upstream[@]+"${accept_upstream[@]}"} \
    || unaccepted_conflicts+=("${path}")
done
unaccepted_paths=()
for path in ${differing_paths[@]+"${differing_paths[@]}"}; do
  contains "${path}" ${accept_upstream[@]+"${accept_upstream[@]}"} \
    || unaccepted_paths+=("${path}")
done
if [[ -n "${unaccepted_conflicts[*]+x}${unaccepted_paths[*]+x}" ]]; then
  echo "error: importing ${tag} would drop or override qbit changes under ${PREFIX}" >&2
  echo "(new split ${upstream_commit}; current split ${old_split})." >&2
  if [[ -n "${unaccepted_conflicts[*]+x}" ]]; then
    echo "Paths where the qbit subtree conflicts with how ${tag} changed them:" >&2
    printf '  %s\n' "${unaccepted_conflicts[@]}" >&2
  fi
  if [[ -n "${unaccepted_paths[*]+x}" ]]; then
    echo "Paths with qbit changes that ${tag} lacks:" >&2
    printf '  %s\n' "${unaccepted_paths[@]}" >&2
  fi
  echo "Review them, then rerun with --accept-upstream <path> for each path to take ${tag}'s version." >&2
  exit 1
fi

# Import with the caller's own GnuPG environment, so a maintainer whose commits
# are signed gets a signed import commit. When the release tree equals the
# vendored tree, as when a release upstreams qbit's downstream delta, the import
# commit only moves git-subtree-split and changes no file.
pre_import_head="$(git rev-parse --verify HEAD)"
import_started=1
commit_args=()
if [[ "${new_upstream_tree}" == "${qbit_tree}" ]]; then
  echo "The release tree equals the vendored tree; the import commit only moves the split."
  commit_args+=(--allow-empty)
else
  git rm -r -q -- "${PREFIX}"
  git read-tree --prefix="${PREFIX}/" -u "${new_upstream_tree}"
fi
git commit -q ${commit_args[@]+"${commit_args[@]}"} \
  -m "Squashed '${PREFIX}/' changes from ${old_split:0:10}..${upstream_commit:0:10}" \
  -m "git-subtree-dir: ${PREFIX}
git-subtree-split: ${upstream_commit}"

# The import is done only when the subtree check passes and verified this tag's
# commit; until then, any exit, an interrupt included, undoes the commit.
lint_status=0
run_subtree_check || lint_status=$?
if [[ "${lint_status}" -ne 0 ]]; then
  undo_reason="the subtree check failed"
  exit 1
fi
if [[ "${lint_commit}" != "${upstream_commit}" ]]; then
  undo_reason="the subtree check verified ${lint_commit:-no commit}, not ${tag} (${upstream_commit})"
  exit 1
fi
import_verified=1

echo "Imported ${tag} (${upstream_commit}) into ${PREFIX}."
