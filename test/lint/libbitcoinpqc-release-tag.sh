# shellcheck shell=bash
# The scripts that source this file read its readonly variables.
# shellcheck disable=SC2034
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
#
# The qbit-libbitcoinpqc release-tag check that
# test/lint/libbitcoinpqc-subtree-check.sh and
# contrib/devtools/update-libbitcoinpqc-subtree.sh both source. Both
# already export LC_ALL=C; lint-shell-locale.py wants it here too.

export LC_ALL=C

readonly LIBBITCOINPQC_PREFIX="src/libbitcoinpqc"
readonly LIBBITCOINPQC_UPSTREAM_URL="https://github.com/Qbit-Org/qbit-libbitcoinpqc.git"
readonly LIBBITCOINPQC_SIGNER_CERT="contrib/keys/operator-keys/public-keys/operator-01-release.asc"
readonly LIBBITCOINPQC_SIGNER_FINGERPRINT="289EA3EC2F1939A24984840ED26CFC05586D371E"

# Succeeds if url, as git fetch would read it after url.<base>.insteadOf
# rewriting, is a local repository: a path or a file:// URL. Only a local
# repository may be checked against a test signer, so the real upstream, in any
# URL form, is always checked against the pinned one.
libbitcoinpqc_is_local_remote() {
  local url
  url="$(git ls-remote --get-url "$1")" || return 1
  case "${url}" in
    file://*) return 0 ;;
    *://*) return 1 ;;
  esac
  # Git reads a colon before the first slash as scp-like host:path syntax.
  [[ "${url}" != *:* || "${url%%:*}" == */* ]]
}

# Fetches refs/tags/<tag>, exactly, from url into ref and prints the object ID
# the ref then holds. Reading the explicit ref, not FETCH_HEAD, keeps
# fetch.writeFetchHEAD=false from leaving a stale object in its place.
libbitcoinpqc_fetch_tag() {
  local url="$1"
  local tag="$2"
  local ref="$3"
  git fetch --quiet --no-tags "${url}" "+refs/tags/${tag}:${ref}" || return 1
  git rev-parse --verify "${ref}"
}

# Checks the tag object fetched for tag against a throwaway keyring that holds
# only cert. It needs a good signature whose VALIDSIG names fingerprint, the
# signing (sub)key, as status_fingerprints in
# ci/release/validate_release_artifacts.py does, and a header that names tag and
# type commit, so an older signed tag published under a new name is refused. The
# keyring is removed on every exit, and a failure says why on stderr.
libbitcoinpqc_verify_tag() (
  local object="$1"
  local tag="$2"
  local cert="$3"
  local fingerprint="$4"
  local verify_status
  local tag_header
  GNUPGHOME="$(mktemp -d)" || exit 1
  export GNUPGHOME
  trap 'gpgconf --kill all >/dev/null 2>&1 || true; gpgconf --remove-socketdir >/dev/null 2>&1 || true; rm -rf "${GNUPGHOME:?}"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  if [[ "$(git cat-file -t "${object}" 2>/dev/null)" != tag ]]; then
    echo "${tag} is not a signed annotated tag" >&2
    exit 1
  fi
  gpg --batch --quiet --import "${cert}" || exit 1
  if ! verify_status="$(git -c gpg.openpgp.program=gpg verify-tag --raw "${object}" 2>&1)" \
    || ! grep -q "^\[GNUPG:\] VALIDSIG ${fingerprint} " <<<"${verify_status}"; then
    printf '%s\n' "${verify_status}" >&2
    echo "${tag} has no good signature from ${fingerprint}" >&2
    exit 1
  fi
  tag_header="$(git cat-file tag "${object}" | sed -n '1,/^$/p')"
  if ! grep -qxF "tag ${tag}" <<<"${tag_header}" \
    || ! grep -qxF "type commit" <<<"${tag_header}"; then
    printf '%s\n' "${tag_header}" >&2
    echo "the fetched tag object is not ${tag} pointing at a commit" >&2
    exit 1
  fi
)

# Prints the newest non-merge commit that carries the git-subtree-dir trailer
# for the prefix. --topo-order lists a commit before its ancestors whatever
# their dates, so a skewed committer date cannot make an older import win.
libbitcoinpqc_latest_import() {
  git log --topo-order --no-merges --grep="^git-subtree-dir: ${LIBBITCOINPQC_PREFIX}/*$" \
    --format=%H -n 1 HEAD
}
