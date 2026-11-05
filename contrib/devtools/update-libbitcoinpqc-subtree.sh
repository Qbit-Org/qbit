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
SIGNER_CERT="${LIBBITCOINPQC_TEST_SIGNER_CERT:-$DEFAULT_SIGNER_CERT}"
SIGNER_FINGERPRINT="${LIBBITCOINPQC_TEST_SIGNER_FINGERPRINT:-$DEFAULT_SIGNER_FINGERPRINT}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [--allow-downgrade] [--accept-upstream <path>]... [<tag>]

Import a signed qbit-libbitcoinpqc release tag into $PREFIX as one main-line
commit that carries git-subtree-dir and git-subtree-split trailers, then run
test/lint/libbitcoinpqc-subtree-check.sh. Every check runs before the tree
changes; a failed subtree check undoes the import commit.
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

Test-only environment overrides (for the helper's tests, not for releases):
  LIBBITCOINPQC_TEST_SIGNER_CERT          default: $DEFAULT_SIGNER_CERT
  LIBBITCOINPQC_TEST_SIGNER_FINGERPRINT   default: $DEFAULT_SIGNER_FINGERPRINT
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

allow_downgrade=0
accept_upstream=()
tag=""
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
# finds it.
import_commit="$(
  git log --no-merges --grep="^git-subtree-dir: ${PREFIX}/*$" --format=%H -n 1 HEAD -- "${PREFIX}"
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
# certificate; the trap removes it on every exit and cannot fail itself.
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

upstream_commit="$(git rev-parse --verify "${tag_object}^{commit}")"
if [[ "${upstream_commit}" == "${old_split}" ]]; then
  echo "${PREFIX} already imports ${tag} (${upstream_commit}); nothing to do."
  exit 0
fi
if ! git cat-file -e "${old_split}^{commit}" 2>/dev/null; then
  git fetch --quiet --no-tags "${REMOTE_URL}" "${old_split}"
fi
if [[ "${allow_downgrade}" -ne 1 ]] \
  && ! git merge-base --is-ancestor "${old_split}" "${upstream_commit}"; then
  die "${tag} (${upstream_commit}) does not descend from the current split ${old_split}; pass --allow-downgrade to import it anyway"
fi

# Merge the qbit subtree into the release, with the old release as the base.
# Where the result differs from the release, the import would drop a qbit
# change or override a conflicting one.
old_upstream_tree="$(git rev-parse --verify "${old_split}^{tree}")"
qbit_tree="$(git rev-parse --verify "HEAD:${PREFIX}")"
new_upstream_tree="$(git rev-parse --verify "${upstream_commit}^{tree}")"
merge_status=0
merge_output="$(
  git merge-tree --write-tree --merge-base="${old_upstream_tree}" \
    "${qbit_tree}" "${new_upstream_tree}"
)" || merge_status=$?
merged_tree="${merge_output%%[[:space:]]*}"
if [[ "${merge_status}" -gt 1 || ! "${merged_tree}" =~ ^[0-9a-f]{40}$ ]]; then
  die "git merge-tree failed (status ${merge_status})"
fi
differing_paths="$(git diff --name-only "${new_upstream_tree}" "${merged_tree}")"
for path in ${accept_upstream[@]+"${accept_upstream[@]}"}; do
  grep -qxF -- "${path}" <<<"${differing_paths}" \
    || die "--accept-upstream ${path} does not name a path that differs from ${tag}"
done
unaccepted=""
while IFS= read -r path; do
  [[ -n "${path}" ]] || continue
  contains "${path}" ${accept_upstream[@]+"${accept_upstream[@]}"} && continue
  unaccepted+="  ${path}"$'\n'
done <<<"${differing_paths}"
if [[ -n "${unaccepted}" ]]; then
  echo "error: importing ${tag} would drop or override qbit changes under ${PREFIX}." >&2
  if [[ "${merge_status}" -eq 1 ]]; then
    echo "The qbit subtree also conflicts with how ${tag} changed some of these paths." >&2
  fi
  echo "Paths that would differ from ${tag} (new split ${upstream_commit}; current split ${old_split}):" >&2
  printf '%s' "${unaccepted}" >&2
  echo "Review them, then rerun with --accept-upstream <path> for each path to take ${tag}'s version." >&2
  exit 1
fi

# Import with the caller's own GnuPG environment, so a maintainer whose commits
# are signed gets a signed import commit. If the commit fails, restore the
# prefix, which was clean before the import started.
import_committed=0
restore_prefix() {
  if [[ "${import_committed}" -ne 1 ]]; then
    git reset -q -- "${PREFIX}" || true
    git checkout -q -- "${PREFIX}" || true
    git clean -q -fd -- "${PREFIX}" || true
  fi
}
trap restore_prefix EXIT
git rm -r -q -- "${PREFIX}"
git read-tree --prefix="${PREFIX}/" -u "${new_upstream_tree}"
git commit -q \
  -m "Squashed '${PREFIX}/' changes from ${old_split:0:10}..${upstream_commit:0:10}" \
  -m "git-subtree-dir: ${PREFIX}
git-subtree-split: ${upstream_commit}"
import_committed=1
trap - EXIT

if ! LIBBITCOINPQC_REMOTE_URL="${REMOTE_URL}" LIBBITCOINPQC_REMOTE_REF="${tag}" \
  test/lint/libbitcoinpqc-subtree-check.sh; then
  git reset -q --keep HEAD~1
  die "the subtree check failed; the import commit was undone"
fi

echo "Imported ${tag} (${upstream_commit}) into ${PREFIX}."
