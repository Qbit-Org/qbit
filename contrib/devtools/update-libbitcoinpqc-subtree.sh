#!/usr/bin/env bash
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

export LC_ALL=C
set -euo pipefail

readonly PREFIX="src/libbitcoinpqc"
readonly DEFAULT_REMOTE_URL="https://github.com/Qbit-Org/qbit-libbitcoinpqc.git"
readonly DEFAULT_REMOTE_REF="v0.3.0"
readonly DEFAULT_SIGNER_CERT="contrib/keys/operator-keys/public-keys/operator-01-release.asc"
readonly DEFAULT_SIGNER_FINGERPRINT="289EA3EC2F1939A24984840ED26CFC05586D371E"

REMOTE_URL="${LIBBITCOINPQC_REMOTE_URL:-$DEFAULT_REMOTE_URL}"
REMOTE_REF="${LIBBITCOINPQC_REMOTE_REF:-$DEFAULT_REMOTE_REF}"
# The signer is pinned. Only explicit test flags can replace it; no environment
# variable can.
SIGNER_CERT="${DEFAULT_SIGNER_CERT}"
SIGNER_FINGERPRINT="${DEFAULT_SIGNER_FINGERPRINT}"

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
  LIBBITCOINPQC_REMOTE_URL   default: $DEFAULT_REMOTE_URL
  LIBBITCOINPQC_REMOTE_REF   default: $DEFAULT_REMOTE_REF

Test-only options (for the helper's tests, never for a real import):
  --test-signer-cert <path>          Replace the pinned signer certificate,
                                     $DEFAULT_SIGNER_CERT.
  --test-signer-fingerprint <fpr>    Replace the pinned signing fingerprint,
                                     $DEFAULT_SIGNER_FINGERPRINT.
  Both must be given together, and the helper warns loudly when they are used.
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
if [[ -n "${test_signer_cert}${test_signer_fingerprint}" ]]; then
  [[ -n "${test_signer_cert}" && -n "${test_signer_fingerprint}" ]] \
    || die "--test-signer-cert and --test-signer-fingerprint must be given together"
  [[ "${test_signer_cert}" == /* ]] || test_signer_cert="${PWD}/${test_signer_cert}"
  SIGNER_CERT="${test_signer_cert}"
  SIGNER_FINGERPRINT="${test_signer_fingerprint}"
  echo "warning: TEST SIGNER IN USE: not for real imports (${SIGNER_FINGERPRINT})" >&2
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
cd "$(git rev-parse --show-toplevel)"
[[ -f "${SIGNER_CERT}" ]] || die "signer certificate not found: ${SIGNER_CERT}"

# Nothing but the import may land in the import commit.
git diff --quiet HEAD -- || die "the worktree has changes; commit or stash them first"
git diff --cached --quiet -- || die "the index has staged changes; commit or unstage them first"
[[ -z "$(git ls-files --others --exclude-standard -- "${PREFIX}")" ]] \
  || die "untracked files under ${PREFIX}; remove them first"
[[ -z "$(git ls-files --others -- "${PREFIX}")" ]] \
  || die "ignored files under ${PREFIX}; list them with git clean -ndX ${PREFIX} and remove them first"

# The current split is read the way test/lint/libbitcoinpqc-subtree-check.sh
# finds it: the newest non-merge commit with the trailer, with no pathspec, so
# an import commit that only moved the split is found too.
import_commit="$(
  git log --no-merges --grep="^git-subtree-dir: ${PREFIX}/*$" --format=%H -n 1 HEAD
)"
[[ -n "${import_commit}" ]] || die "no git-subtree-dir commit for ${PREFIX}; this helper refreshes an existing import"
old_split="$(
  git show -s --format=%B "${import_commit}" \
    | awk '/^git-subtree-split: / && !found { found = $2 } END { print found }'
)"
[[ "${old_split}" =~ ^[0-9a-f]{40}$ ]] \
  || die "import commit ${import_commit} has no valid git-subtree-split"

echo "Fetching ${tag} from ${REMOTE_URL}"
git fetch --quiet --no-tags "${REMOTE_URL}" "refs/tags/${tag}"
tag_object="$(git rev-parse --verify FETCH_HEAD)"

# Check the tag against a throwaway keyring that holds only the signer's
# certificate; the trap removes it on every exit and cannot fail itself. Like
# status_fingerprints in ci/release/validate_release_artifacts.py, this pins
# the first VALIDSIG field, the signing (sub)key's fingerprint.
(
  GNUPGHOME="$(mktemp -d)"
  export GNUPGHOME
  trap 'gpgconf --kill all >/dev/null 2>&1 || true; gpgconf --remove-socketdir >/dev/null 2>&1 || true; rm -rf "${GNUPGHOME:?}"' EXIT
  gpg --batch --quiet --import "${SIGNER_CERT}"
  if ! verify_status="$(git -c gpg.openpgp.program=gpg verify-tag --raw "${tag_object}" 2>&1)" \
    || ! grep -q "^\[GNUPG:\] VALIDSIG ${SIGNER_FINGERPRINT} " <<<"${verify_status}"; then
    printf '%s\n' "${verify_status}" >&2
    die "${tag} has no good signature from ${SIGNER_FINGERPRINT}; not importing"
  fi
  # The signed tag object must name this tag and point at a commit, so an
  # older signed tag published under a new name is refused.
  tag_header="$(git cat-file tag "${tag_object}" | sed -n '1,/^$/p')"
  if ! grep -qxF "tag ${tag}" <<<"${tag_header}" \
    || ! grep -qxF "type commit" <<<"${tag_header}"; then
    printf '%s\n' "${tag_header}" >&2
    die "the fetched tag object is not ${tag} pointing at a commit"
  fi
)

# One EXIT trap removes the scratch files and, if the import started but did
# not commit, restores the prefix, which was clean (including ignored files)
# before the import started.
work_dir=""
import_started=0
import_committed=0
cleanup() {
  if [[ "${import_started}" -eq 1 && "${import_committed}" -ne 1 ]]; then
    git reset -q -- "${PREFIX}" || true
    git checkout -q -- "${PREFIX}" || true
    git clean -q -fdx -- "${PREFIX}" || true
  fi
  if [[ -n "${work_dir}" ]]; then
    rm -rf "${work_dir}"
  fi
}
trap cleanup EXIT
work_dir="$(mktemp -d)"

# Run the subtree check for the tag, and set lint_commit to the commit the
# check says the tag resolves to.
lint_commit=""
run_subtree_check() {
  local status=0
  LIBBITCOINPQC_REMOTE_URL="${REMOTE_URL}" LIBBITCOINPQC_REMOTE_REF="${tag}" \
    test/lint/libbitcoinpqc-subtree-check.sh >"${work_dir}/lint" || status=$?
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
import_committed=1

lint_status=0
run_subtree_check || lint_status=$?
if [[ "${lint_status}" -ne 0 || "${lint_commit}" != "${upstream_commit}" ]]; then
  if [[ "${lint_status}" -ne 0 ]]; then
    reason="the subtree check failed"
  else
    reason="the subtree check verified ${lint_commit:-no commit}, not ${tag} (${upstream_commit})"
  fi
  git reset -q --keep HEAD~1 \
    || die "${reason}; the import commit failed the lint and could not be undone; run git reset --hard HEAD~1"
  die "${reason}; the import commit was undone"
fi

echo "Imported ${tag} (${upstream_commit}) into ${PREFIX}."
