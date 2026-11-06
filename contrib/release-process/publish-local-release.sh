#!/usr/bin/env bash
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

export LC_ALL=C
set -euo pipefail

# Every git command, including the validators', reads real objects only: none
# of the caller's GIT_* settings (repository, index, object or config
# overrides), no replace refs and no grafts. git status never writes the
# index, nothing pages, and nothing is fetched, so a partial-clone remote in a
# checkout's config cannot make a missing object run ssh or a helper
# (GIT_ALLOW_PROTOCOL allows only "none", which does not exist).
while IFS= read -r git_variable; do
    unset "$git_variable"
done < <(compgen -e | grep '^GIT_' || true)
export GIT_NO_REPLACE_OBJECTS=1
export GIT_GRAFT_FILE=/dev/null
export GIT_OPTIONAL_LOCKS=0
export GIT_PAGER=cat
export GIT_NO_LAZY_FETCH=1
export GIT_ALLOW_PROTOCOL=none
# Config every git command runs with, whatever the system, user or repository
# config says, as in contrib/release-process/release_staging_common.py: nothing
# may run a program or change which history is read. GIT_CONFIG_COUNT/KEY/VALUE
# outrank config files; only an explicit git -c (the validators' gpg.program)
# outranks them. /dev/null/disabled cannot exist, so no program or hook runs.
# advice.graftFileDeprecated only silences the hint the empty graft file causes.
# core.fsmonitor is empty, not false: git before 2.36 reads it as a hook
# command and would run "false". gpg.ssh.program and gpg.x509.program: git
# verify-tag runs the program of the signature's format, and only OpenPGP may
# verify, with the gpg.program the validators pass by git -c; gpg.program is
# off for anything else (a %G? export-subst placeholder in git archive).
# tar.umask keeps git archive's default file modes.
GIT_SAFE_CONFIG_KEYS=(
    advice.graftFileDeprecated core.fsmonitor core.hooksPath core.commitGraph
    gpg.ssh.program gpg.x509.program gpg.program tar.umask
)
GIT_SAFE_CONFIG_VALUES=(
    false "" /dev/null/disabled false
    /dev/null/disabled /dev/null/disabled /dev/null/disabled 0002
)
export_git_safe_config() {
    local index
    export GIT_CONFIG_COUNT="${#GIT_SAFE_CONFIG_KEYS[@]}"
    for index in "${!GIT_SAFE_CONFIG_KEYS[@]}"; do
        export "GIT_CONFIG_KEY_$index=${GIT_SAFE_CONFIG_KEYS[$index]}"
        export "GIT_CONFIG_VALUE_$index=${GIT_SAFE_CONFIG_VALUES[$index]}"
    done
}
export_git_safe_config

# GIT_CONFIG_COUNT arrived in git 2.31; older git would ignore the overrides.
# git archive pipes a .tar.gz through tar.tar.gz.command (tar.tgz.command),
# which config could set to any program: pin git's own default for this
# version (its built-in gzip from 2.38, gzip -cn before).
require_git() {
    local version
    local major
    local minor
    local gzip
    version="$(git version)" || die "Could not run git version"
    [[ "$version" =~ ^git\ version\ ([0-9]+)\.([0-9]+) ]] \
        || die "Cannot tell the git version from: $version"
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    if [ "$major" -lt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -lt 31 ]; }; then
        die "$version is too old: the publisher needs git 2.31 or newer, whose GIT_CONFIG_COUNT keeps checkout config from running programs"
    fi
    if [ "$major" -gt 2 ] || [ "$minor" -ge 38 ]; then
        gzip="git archive gzip"
    else
        gzip="gzip -cn"
    fi
    GIT_SAFE_CONFIG_KEYS+=(tar.tar.gz.command tar.tgz.command)
    GIT_SAFE_CONFIG_VALUES+=("$gzip" "$gzip")
    export_git_safe_config
}

# Python runs without PYTHON* environment variables, user or site packages,
# startup hooks or bytecode; everything it runs needs only the standard
# library. Inline snippets are fully isolated (-I keeps the current directory
# off sys.path). The validators run with -E -s instead of -I, because they
# import their siblings from their own directory, the exported trusted ref.
PYTHON_SNIPPET=(python3 -I -S -B)
PYTHON=(python3 -E -s -S -B)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

die() {
    echo "ERR: $*" >&2
    exit 1
}

msg() {
    echo "==> $*"
}

usage() {
    cat <<'EOF'
Validate and publish a qbit GitHub Release from coordinator-held artifacts.

The script must come from a clean checkout whose HEAD is the trusted release
ref. Validation is always performed before any release is created or changed.
With neither --create-draft nor --publish, the script is validation-only.

Required:
  --tag TAG                         Signed annotated release tag.
  --artifacts-dir DIR               Flat validator-approved staging directory.
  --trusted-release-ref SHA         Full commit SHA of this trusted checkout. It
                                     must be on the first-parent history of the
                                     trusted release branch.
  --guix-sigs-repo DIR              Clean qbit-guix.sigs checkout.
  --guix-sigs-ref SHA               Full commit SHA of that checkout.
  --release-line LINE               testnet or mainnet.

Required for testnet:
  --testnet-posture-evidence FILE   Testnet-only posture evidence.

Required for mainnet; optional as an all-or-none set for testnet:
  --p2mr-v1-conformance-evidence FILE
                                     qbit P2MR v1 release evidence envelope.
  --p2mr-v1-oracle-report FILE       Canonical standalone-oracle report.
  --p2mr-v1-integration-matrix FILE  Finalized integration support inventory.

Release policy:
  --require-photon                  Require PHOTON artifacts and attestations.
  --allow-unsigned-platform-artifacts
                                     Apply an explicit unsigned-platform waiver.
  --allow-codesigning-artifacts     Apply an explicit codesigning-payload waiver.

Release metadata:
  --notes-file FILE                 Release notes; otherwise generate notes.
  --release-name NAME               Default for a new draft: qbit <TAG>.
  --prerelease                      Mark the release as a prerelease.
  --no-prerelease                   Explicitly clear the prerelease flag.
  --make-latest MODE                true, false, or auto (GitHub legacy mode).

For a new draft, prerelease and make-latest default to false. When resuming a
draft, omitted metadata options preserve its current title, prerelease, and
latest state.

Publication mode (mutually exclusive):
  --create-draft                    Upload and verify assets, then leave a draft.
  --publish                         Upload and verify assets, then publish.

Repository overrides:
  --repo OWNER/REPO                 Default: Qbit-Org/qbit.
  --trusted-release-branch BRANCH   Protected branch that carries the trusted
                                     release ref. Default: main; a release line
                                     passes its own branch, such as 1.x.x. GitHub
                                     must report it as protected.
  --guix-sigs-github-repo OWNER/REPO
                                     Default: Qbit-Org/qbit-guix.sigs.
  --guix-sigs-branch BRANCH         Default: main.

Existing published releases are never changed. A matching draft can be safely
resumed: its notes are replaced and verified, and existing assets must be a
digest-matching subset of the validated set.
Published releases are accepted only when GitHub reports them as immutable. The
target of --repo must enable repository release immutability or be covered by an
organization immutable-release policy before publication.
EOF
}

need_cmd() {
    local command_name
    for command_name in "$@"; do
        command -v "$command_name" >/dev/null 2>&1 \
            || die "Missing required command: $command_name"
    done
}

require_value() {
    local option="$1"
    local value="${2:-}"
    [ -n "$value" ] || die "$option requires a value"
}

lowercase() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

on_first_parent_history() {
    # Succeeds if commit is on the first-parent history of history_ref, the
    # sequence of states that branch actually had. Under merge commits, any
    # other ancestor, including a merged pull request's head, can have a tree
    # the branch never had. awk reads the whole list, so pipefail cannot fail
    # on an early exit, and an unknown ref fails rev-list.
    local root="$1"
    local history_ref="$2"
    local commit
    commit="$(lowercase "$3")"
    git -C "$root" rev-list --first-parent "$history_ref" \
        | awk -v commit="$commit" '$0 == commit { found = 1 } END { exit !found }'
}

require_full_sha() {
    local name="$1"
    local value="$2"
    [[ "$value" =~ ^[0-9A-Fa-f]{40}$ ]] \
        || die "$name must be a full 40-character commit SHA: $value"
}

require_output() {
    local name="$1"
    local value="$2"
    [ -n "$value" ] || die "Release validators did not emit $name"
}

resolve_dir() {
    local path="$1"
    [ -d "$path" ] || die "Directory does not exist: $path"
    (cd "$path" && pwd -P)
}

resolve_file() {
    local path="$1"
    local parent
    local name
    [ -f "$path" ] || die "File does not exist: $path"
    parent="$(dirname "$path")"
    name="$(basename "$path")"
    printf '%s/%s\n' "$(resolve_dir "$parent")" "$name"
}

# Attributes can route any path through a filter driver, and git status and
# git archive run them; a driver git has no command for is a no-op. Drivers are
# named in config, so every one the checkout's config defines gets empty
# commands and required=false.
disable_git_filters() {
    local label="$1"
    local root="$2"
    local keys
    local key
    local driver
    local known
    keys="$(git -C "$root" config --list --name-only)" \
        || die "Could not read the git config of the $label: $root"
    while IFS= read -r key; do
        # The driver name may be empty: [filter ""] serves "filter=".
        [[ "$key" =~ ^filter\.(.*)\.(clean|smudge|process|required)$ ]] || continue
        driver="${BASH_REMATCH[1]}"
        for known in "${GIT_SAFE_CONFIG_KEYS[@]}"; do
            [ "$known" != "filter.$driver.clean" ] || continue 2
        done
        GIT_SAFE_CONFIG_KEYS+=(
            "filter.$driver.clean" "filter.$driver.smudge" "filter.$driver.process" "filter.$driver.required"
        )
        GIT_SAFE_CONFIG_VALUES+=("" "" "" false)
    done <<< "$keys"
    export_git_safe_config
}

require_clean_checkout() {
    local label="$1"
    local root="$2"
    local status
    local promisors
    # Like release_staging_common.refuse_partial_clone: the environment forbids
    # every fetch anyway; this says why up front.
    # extensions.partialClone names a remote, so any value counts.
    promisors="$(
        { git -C "$root" config --get-regexp '^extensions\.partialclone$' | awk '{ print $1 }' || true
          git -C "$root" config --type=bool --get-regexp '^remote\..*\.promisor$' \
              | awk '$NF != "false" { print $1 }' || true
        } | paste -sd, -
    )"
    [ -z "$promisors" ] \
        || die "$label must not be a partial clone ($promisors): $root; the publisher never fetches missing objects"
    disable_git_filters "$label" "$root"
    # --ignore-submodules=dirty: a gitlink still shows, but git status does not
    # run inside a submodule checkout, whose own config could name filters.
    status="$(git -C "$root" status --porcelain --untracked-files=normal --ignore-submodules=dirty)" \
        || die "Could not run git status in the $label: $root"
    [ -z "$status" ] || die "$label must be clean: $root"
}

# git status does not show files marked assume-unchanged (lowercase tag) or
# skip-worktree (S); only plain tracked entries (H) are acceptable.
require_plain_index() {
    local label="$1"
    local root="$2"
    shift 2
    local flagged
    flagged="$(git -C "$root" ls-files -v -- "$@" | awk '$1 != "H" { print substr($0, 3) }')"
    [ -z "$flagged" ] \
        || die "$label has index flags (assume-unchanged or skip-worktree) on: ${flagged//$'\n'/, }"
}

# Write the blobs under the given paths at a commit into a directory, so that
# what is read is exactly what the commit holds, whatever the working tree,
# its line-ending conversion or the index say.
export_trusted_paths() {
    local label="$1"
    local root="$2"
    local ref="$3"
    local destination="$4"
    shift 4
    local entry
    local meta
    local path
    local mode
    local type
    local object
    local listing="$destination.ls-tree"
    mkdir -p "$destination"
    git -C "$root" ls-tree -r -z --full-tree "$ref" -- "$@" > "$listing" \
        || die "Could not list ${*:-the tree} at $label $ref"
    while IFS= read -r -d '' entry; do
        meta="${entry%%$'\t'*}"
        path="${entry#*$'\t'}"
        read -r mode type object <<< "$meta"
        case "$mode:$type" in
            100644:blob|100755:blob) ;;
            *) die "$label $ref has a non-regular file at $path" ;;
        esac
        case "/$path/" in
            */../*|*/./*|*//*) die "$label $ref has an unsafe path: $path" ;;
        esac
        case "$path" in
            */*) mkdir -p "$destination/${path%/*}" ;;
        esac
        git -C "$root" cat-file blob "$object" > "$destination/$path" \
            || die "Could not read $path at $label $ref"
    done < "$listing"
}

# The release tag is signed by an active release key: the validator's own
# verify_tag_signature, given the pinned tag object (TAG_OBJECT) rather than
# the bare tag name that validate_release_artifacts.py --verify-tag-signature
# would pass to git verify-tag.
verify_release_tag_signature() {
    (cd "$TRUSTED_ROOT" && "${PYTHON_SNIPPET[@]}" - "$VALIDATORS" "$TRUSTED_KEYS_DIR" "$RELEASE_LINE" "$TAG" "$TAG_OBJECT" <<'PY'
import shutil
import sys
import tempfile
from pathlib import Path

validators, keys_dir, release_line, tag, tag_object = sys.argv[1:6]
# The validators import their siblings from the exported trusted ref.
sys.path.insert(0, validators)
import validate_release_artifacts as vra  # noqa: E402

gpg = shutil.which("gpg") or "gpg"
keys = Path(keys_dir)
try:
    policy = vra.load_release_policy(keys / "keys.json", keys, release_line)
    with tempfile.TemporaryDirectory(prefix="qbit-release-tag-gnupg-") as home:
        gnupg_home = Path(home)
        gnupg_home.chmod(0o700)
        vra.import_release_keys(gpg, gnupg_home, keys, policy)
        # git verify-tag runs in the current directory, the trusted checkout.
        vra.verify_tag_signature(gpg, gnupg_home, tag_object, policy)
except vra.ReleaseValidationError as exc:
    message = str(exc).replace(f"Release tag {tag_object}", f"Release tag {tag} ({tag_object})", 1)
    raise SystemExit(f"ERR: {message}")
PY
    ) || die "Release tag $TAG failed the signature check"
}

require_full_history() {
    # A shallow checkout cuts the first-parent walk short, so a merged commit
    # would be reported as not on its branch.
    local label="$1"
    local root="$2"
    case "$(git -C "$root" rev-parse --is-shallow-repository)" in
        false) ;;
        true) die "The $label is shallow; run git fetch --unshallow in $root" ;;
        *) die "Could not tell whether the $label is shallow" ;;
    esac
}

github_repo_path() {
    local repository="$1"
    local owner
    local name
    case "$repository" in
        */*)
            owner="${repository%/*}"
            owner="${owner##*/}"
            name="${repository##*/}"
            [ -n "$owner" ] && [ -n "$name" ] \
                || die "Invalid GitHub repository: $repository"
            printf '%s/%s\n' "$owner" "$name"
            ;;
        *) die "GitHub repository must be OWNER/REPO: $repository" ;;
    esac
}

github_output_value() {
    local path="$1"
    local key="$2"
    awk -F= -v key="$key" \
        '$1 == key { value=substr($0, length(key) + 2) } END { print value }' \
        "$path"
}

github_output_multiline() {
    local path="$1"
    local key="$2"
    awk -v key="$key" '
        index($0, key "<<") == 1 {
            delimiter = substr($0, length(key) + 3)
            while ((getline line) > 0) {
                if (line == delimiter) exit
                print line
            }
        }
    ' "$path"
}

print_shell_command() {
    printf '  '
    printf '%q ' "$@"
    printf '\n'
}

remote_commit() {
    local repository="$1"
    local commit_sha="$2"
    local label="$3"
    local resolved
    resolved="$(gh api "repos/$repository/commits/$commit_sha" --jq '.sha')" \
        || die "$label $commit_sha is not fetchable from $repository"
    [ "$(lowercase "$resolved")" = "$(lowercase "$commit_sha")" ] \
        || die "$label resolved to $resolved, expected $commit_sha"
}

api_path_escape() {
    # Percent-encodes a name for a GitHub API path. A valid branch name can
    # contain # or %, which would otherwise end or change the path: main#x
    # would query main.
    python3 -I -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe="/"))' "$1"
}

fetch_branch_tip() {
    # Prints the tip of a protected GitHub branch after fetching exactly that
    # commit into a local checkout, so its first-parent history can be read
    # locally. Fetching the SHA the API reported, not the moving branch, keeps a
    # merge that lands meanwhile from breaking the release partway. gh's
    # credential helper lets the fetch reach a private repository.
    local root="$1"
    local repository="$2"
    local branch="$3"
    local label="$4"
    local branch_path
    local branch_info
    local api_tip
    local protected
    local fetched_tip
    branch_path="$(api_path_escape "$branch")" \
        || die "Could not encode $label branch name $branch"
    branch_info="$(
        gh api "repos/$repository/branches/$branch_path" \
            --jq '[.commit.sha, (.protected | tostring)] | @tsv'
    )" || die "Could not read $label branch $repository:$branch"
    IFS=$'\t' read -r api_tip protected <<<"$branch_info"
    require_full_sha "$label branch tip" "$api_tip"
    [ "$protected" = true ] \
        || die "$repository:$branch is not a protected branch; protect it with a ruleset before releasing from it"
    git -C "$root" -c credential.helper= -c 'credential.helper=!gh auth git-credential' \
        fetch --quiet --no-tags "https://github.com/$repository.git" "$api_tip" \
        || die "Could not fetch $repository:$branch tip $api_tip into $root"
    fetched_tip="$(git -C "$root" rev-parse --verify FETCH_HEAD)"
    [ "$(lowercase "$fetched_tip")" = "$(lowercase "$api_tip")" ] \
        || die "$label branch $repository:$branch fetched $fetched_tip, but GitHub reports $api_tip"
    printf '%s\n' "$fetched_tip"
}

remote_tag_pin_failure() {
    local phase="$1"
    shift
    if [ "$phase" = post-publication ]; then
        die "$*" "Release $TAG may already be immutable. Stop distribution," \
            "preserve the publisher transcript and observed tag values, and follow" \
            "the immutable-publication recovery procedure in doc/release/release-process.md."
    fi
    die "$*"
}

verify_remote_tag_pin() {
    local phase="$1"
    local remote_ref
    local remote_tag_type
    local remote_tag_sha
    local remote_tag_query
    local remote_tag_info
    local remote_tag_target
    local remote_target_type
    local remote_verified
    local remote_verification_reason
    local remote_verified_at

    remote_ref="$(
        gh api "repos/$GH_REPO_PATH/git/ref/tags/$TAG" \
            --jq '.object.type + " " + .object.sha'
    )" || remote_tag_pin_failure "$phase" \
        "Could not resolve remote tag $TAG during $phase verification"
    remote_tag_type="${remote_ref%% *}"
    remote_tag_sha="${remote_ref#* }"
    [ "$remote_tag_type" = tag ] \
        || remote_tag_pin_failure "$phase" \
            "Remote tag $TAG must be annotated during $phase verification, got $remote_tag_type"
    [ "$(lowercase "$remote_tag_sha")" = "$(lowercase "$TAG_OBJECT")" ] \
        || remote_tag_pin_failure "$phase" \
            "Remote tag object $remote_tag_sha does not match pinned tag object $TAG_OBJECT during $phase verification"

    remote_tag_query='[.object.sha, .object.type, '
    remote_tag_query+='((.verification.verified // false) | tostring), '
    remote_tag_query+='(.verification.reason // "unknown"), '
    remote_tag_query+='(.verification.verified_at // "")] | @tsv'
    remote_tag_info="$(
        gh api "repos/$GH_REPO_PATH/git/tags/$TAG_OBJECT" \
            --jq "$remote_tag_query"
    )" || remote_tag_pin_failure "$phase" \
        "Could not inspect pinned remote tag object $TAG_OBJECT during $phase verification"
    IFS=$'\t' read -r remote_tag_target remote_target_type remote_verified \
        remote_verification_reason remote_verified_at <<< "$remote_tag_info"
    [ "$remote_target_type" = commit ] \
        || remote_tag_pin_failure "$phase" \
            "Remote tag $TAG must directly target a commit during $phase verification, got $remote_target_type"
    [ "$(lowercase "$remote_tag_target")" = "$(lowercase "$TAG_TARGET")" ] \
        || remote_tag_pin_failure "$phase" \
            "Remote tag target $remote_tag_target does not match pinned tag target" \
            "$TAG_TARGET during $phase verification"
    [ "$remote_verified" = true ] && [ "$remote_verification_reason" = valid ] \
        || remote_tag_pin_failure "$phase" \
            "Remote tag $TAG is not a GitHub-verified signed tag with exact valid" \
            "status during $phase verification (verified=$remote_verified" \
            "reason=$remote_verification_reason)"
    msg "Remote tag pin verified during $phase${remote_verified_at:+ at $remote_verified_at}"
}

release_view() {
    local errors="$WORK_DIR/release-view-errors"
    local response
    local release_id
    local is_draft
    local is_immutable
    local release_tag
    local release_url
    if ! response="$(
        gh api --paginate "repos/$GH_REPO_PATH/releases?per_page=100" \
            --jq '.[] | [.id, (.draft | tostring), (.immutable | tostring), .tag_name, .html_url] | @tsv' \
            2> "$errors"
    )"; then
        return 2
    fi
    while IFS=$'\t' read -r release_id is_draft is_immutable \
            release_tag release_url; do
        [ "$release_tag" = "$TAG" ] || continue
        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$release_id" "$is_draft" "$is_immutable" "$release_tag" "$release_url"
        return 0
    done <<< "$response"
    return 3
}

load_release_view() {
    local release_view_output="$1"
    IFS=$'\t' read -r RELEASE_ID RELEASE_IS_DRAFT RELEASE_IS_IMMUTABLE \
        RELEASE_TAG RELEASE_URL <<< "$release_view_output"
    [ "$RELEASE_TAG" = "$TAG" ] \
        || die "GitHub Release tag $RELEASE_TAG does not match $TAG"
}

require_release_view() {
    local output
    if output="$(release_view)"; then
        load_release_view "$output"
        return
    fi
    cat "$WORK_DIR/release-view-errors" >&2
    die "Could not inspect GitHub Release $TAG in $GH_REPO"
}

immutable_release_error() {
    local observed="${RELEASE_IS_IMMUTABLE:-missing}"
    die "Release $TAG in $GH_REPO is published but GitHub did not confirm it as immutable" \
        "(isImmutable=$observed). Enable release immutability under the target" \
        "repository's Settings > Releases or enforce the organization immutable-release" \
        "policy before publishing. GitHub applies this setting only to future releases;" \
        "this release requires manual remediation."
}

require_immutable_release() {
    [ "$RELEASE_IS_IMMUTABLE" = true ] || immutable_release_error
}

wait_for_published_immutable_release() {
    local attempt
    local metadata_observed=0
    local output
    local errors="$WORK_DIR/release-view-errors"
    for attempt in 1 2 3 4 5; do
        if output="$(release_view)"; then
            metadata_observed=1
            load_release_view "$output"
            if [ "$RELEASE_IS_DRAFT" = false ] && \
                    [ "$RELEASE_IS_IMMUTABLE" = true ]; then
                return 0
            fi
        fi
        [ "$attempt" -eq 5 ] || sleep 2
    done
    if [ "$metadata_observed" -eq 0 ]; then
        cat "$errors" >&2
        die "Could not confirm the final published state of release $TAG in $GH_REPO"
    fi
    [ "$RELEASE_IS_DRAFT" = false ] \
        || die "Release $TAG in $GH_REPO did not reach the published state"
    immutable_release_error
}

prepare_release_notes() {
    if [ -n "$NOTES_FILE" ]; then
        EFFECTIVE_NOTES_FILE="$WORK_DIR/explicit-release-notes.md"
        "${PYTHON_SNIPPET[@]}" - "$NOTES_FILE" "$EFFECTIVE_NOTES_FILE" <<'PY'
import sys
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
content = source.read_bytes()
try:
    content.decode("utf8")
except UnicodeDecodeError as error:
    raise SystemExit(f"Explicit release notes are not valid UTF-8: {error}") from error
destination.write_bytes(content)
PY
        msg "Snapshotted explicit release notes from $NOTES_FILE"
        return
    fi

    local response="$WORK_DIR/generated-release-notes.json"
    EFFECTIVE_NOTES_FILE="$WORK_DIR/generated-release-notes.md"
    msg "Generating authoritative release notes for $TAG"
    gh api "repos/$GH_REPO_PATH/releases/generate-notes" \
        --method POST \
        -f "tag_name=$TAG" > "$response" \
        || die "Could not generate release notes for $TAG"
    "${PYTHON_SNIPPET[@]}" - "$response" "$EFFECTIVE_NOTES_FILE" <<'PY'
import json
import sys
from pathlib import Path

response = json.loads(Path(sys.argv[1]).read_text(encoding="utf8"))
body = response.get("body")
if not isinstance(body, str):
    raise SystemExit("Generated release notes response did not contain a string body")
Path(sys.argv[2]).write_text(body, encoding="utf8")
PY
}

verify_release_notes() {
    local response="$WORK_DIR/remote-release.json"
    [ -n "$RELEASE_ID" ] || die "Cannot verify release notes without a release ID"
    gh api "repos/$GH_REPO_PATH/releases/$RELEASE_ID" > "$response" \
        || die "Could not inspect release $RELEASE_ID"
    "${PYTHON_SNIPPET[@]}" - "$EFFECTIVE_NOTES_FILE" "$response" <<'PY'
import json
import sys
from pathlib import Path

expected = Path(sys.argv[1]).read_text(encoding="utf8")
release = json.loads(Path(sys.argv[2]).read_text(encoding="utf8"))
actual = release.get("body")
if actual is None:
    actual = ""
if not isinstance(actual, str):
    print("Remote release notes verification failed: body is not a string", file=sys.stderr)
    raise SystemExit(1)
if actual != expected:
    print("Remote release notes verification failed: body does not match expected notes", file=sys.stderr)
    raise SystemExit(1)
PY
}

# Replace the manifest only after the whole paginated listing succeeds. A failed
# or partial listing leaves no manifest and returns nonzero: an unreadable asset
# list is unknown, never an empty release.
write_remote_asset_manifest() {
    local destination="$1"
    local listing="$destination.listing"
    [ -n "$RELEASE_ID" ] || die "Cannot list assets without a release ID"
    rm -f "$destination" "$listing" \
        || die "Could not discard the previous remote asset manifest"
    if ! gh api "repos/$GH_REPO_PATH/releases/$RELEASE_ID/assets?per_page=100" \
            --paginate --jq '.[] | [.name, (.digest // "")] | @tsv' \
            > "$listing" 2> "$ASSET_LIST_ERRORS"; then
        rm -f "$listing"
        return 1
    fi
    mv "$listing" "$destination" \
        || die "Could not store the remote asset manifest"
}

asset_list_failure() {
    local phase="$1"
    shift
    cat "$ASSET_LIST_ERRORS" >&2
    die "The asset-list request for release $TAG (ID $RELEASE_ID) in $GH_REPO" \
        "failed during $phase; the remote asset inventory is unknown and was not" \
        "compared." "$@"
}

compare_asset_manifests() {
    local mode="$1"
    local remote_manifest="$2"
    "${PYTHON_SNIPPET[@]}" - "$LOCAL_ASSET_MANIFEST" "$remote_manifest" "$mode" <<'PY'
import sys
from pathlib import Path


def load(path: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf8").splitlines():
        if not line:
            continue
        name, digest = line.split("\t", 1)
        if name in entries:
            raise SystemExit(f"duplicate asset name: {name}")
        entries[name] = digest.removeprefix("sha256:").lower()
    return entries


local = load(sys.argv[1])
remote = load(sys.argv[2])
mode = sys.argv[3]

if mode == "subset":
    extra = sorted(remote.keys() - local.keys())
    missing = []
else:
    extra = sorted(remote.keys() - local.keys())
    missing = sorted(local.keys() - remote.keys())

mismatched = sorted(
    name
    for name in remote.keys() & local.keys()
    if not remote[name] or remote[name] != local[name]
)

errors = []
if missing:
    errors.append("missing=" + ",".join(missing))
if extra:
    errors.append("extra=" + ",".join(extra))
if mismatched:
    errors.append("digest_mismatch=" + ",".join(mismatched))
if errors:
    print("Remote release asset verification failed: " + "; ".join(errors), file=sys.stderr)
    raise SystemExit(1)
PY
}

remote_has_asset() {
    local expected="$1"
    local name
    local _digest
    while IFS=$'\t' read -r name _digest; do
        [ "$name" = "$expected" ] && return 0
    done < "$REMOTE_ASSET_MANIFEST"
    return 1
}

# Returns 0 on a match, 1 when the last successful listing did not match, and 2
# when the last asset-list request failed.
wait_for_asset_manifest_match() {
    local mode="$1"
    local attempt
    local listed
    local errors="$WORK_DIR/asset-verification-errors"
    for attempt in 1 2 3 4 5; do
        if write_remote_asset_manifest "$REMOTE_ASSET_MANIFEST"; then
            listed=1
            if compare_asset_manifests "$mode" "$REMOTE_ASSET_MANIFEST" 2> "$errors"; then
                return 0
            fi
        else
            listed=0
        fi
        [ "$attempt" -eq 5 ] || sleep 2
    done
    [ "$listed" -eq 1 ] || return 2
    cat "$errors" >&2
    return 1
}

require_asset_manifest_match() {
    local mode="$1"
    local phase="$2"
    local mismatch_error="$3"
    shift 3
    local status=0
    wait_for_asset_manifest_match "$mode" || status=$?
    case "$status" in
        0) ;;
        2) asset_list_failure "$phase" "$@" ;;
        *) die "$mismatch_error" ;;
    esac
}

TAG=""
ARTIFACTS_DIR=""
TRUSTED_RELEASE_REF=""
GUIX_SIGS_REPO=""
GUIX_SIGS_REF=""
RELEASE_LINE=""
TESTNET_POSTURE_EVIDENCE=""
P2MR_V1_CONFORMANCE_EVIDENCE=""
P2MR_V1_ORACLE_REPORT=""
P2MR_V1_INTEGRATION_MATRIX=""
NOTES_FILE=""
RELEASE_NAME=""
RELEASE_NAME_EXPLICIT=0
RELEASE_CREATED_THIS_RUN=0
REQUIRE_PHOTON=0
ALLOW_UNSIGNED_PLATFORM_ARTIFACTS=0
ALLOW_CODESIGNING_ARTIFACTS=0
PRERELEASE=preserve
MAKE_LATEST=preserve
MODE=validate
GH_REPO=Qbit-Org/qbit
TRUSTED_RELEASE_BRANCH=main
TRUSTED_RELEASE_BRANCH_EXPLICIT=0
GUIX_SIGS_GH_REPO=Qbit-Org/qbit-guix.sigs
GUIX_SIGS_BRANCH=main

while [ "$#" -gt 0 ]; do
    case "$1" in
        --tag)
            require_value "$1" "${2:-}"
            TAG="$2"
            shift 2
            ;;
        --artifacts-dir)
            require_value "$1" "${2:-}"
            ARTIFACTS_DIR="$2"
            shift 2
            ;;
        --trusted-release-ref)
            require_value "$1" "${2:-}"
            TRUSTED_RELEASE_REF="$2"
            shift 2
            ;;
        --guix-sigs-repo)
            require_value "$1" "${2:-}"
            GUIX_SIGS_REPO="$2"
            shift 2
            ;;
        --guix-sigs-ref)
            require_value "$1" "${2:-}"
            GUIX_SIGS_REF="$2"
            shift 2
            ;;
        --release-line)
            require_value "$1" "${2:-}"
            RELEASE_LINE="$2"
            shift 2
            ;;
        --testnet-posture-evidence)
            require_value "$1" "${2:-}"
            TESTNET_POSTURE_EVIDENCE="$2"
            shift 2
            ;;
        --p2mr-v1-conformance-evidence)
            require_value "$1" "${2:-}"
            P2MR_V1_CONFORMANCE_EVIDENCE="$2"
            shift 2
            ;;
        --p2mr-v1-oracle-report)
            require_value "$1" "${2:-}"
            P2MR_V1_ORACLE_REPORT="$2"
            shift 2
            ;;
        --p2mr-v1-integration-matrix)
            require_value "$1" "${2:-}"
            P2MR_V1_INTEGRATION_MATRIX="$2"
            shift 2
            ;;
        --notes-file)
            require_value "$1" "${2:-}"
            NOTES_FILE="$2"
            shift 2
            ;;
        --release-name)
            require_value "$1" "${2:-}"
            RELEASE_NAME="$2"
            RELEASE_NAME_EXPLICIT=1
            shift 2
            ;;
        --require-photon) REQUIRE_PHOTON=1; shift ;;
        --allow-unsigned-platform-artifacts)
            ALLOW_UNSIGNED_PLATFORM_ARTIFACTS=1
            shift
            ;;
        --allow-codesigning-artifacts)
            ALLOW_CODESIGNING_ARTIFACTS=1
            shift
            ;;
        --prerelease)
            [ "$PRERELEASE" != false ] \
                || die "--prerelease and --no-prerelease are mutually exclusive"
            PRERELEASE=true
            shift
            ;;
        --no-prerelease)
            [ "$PRERELEASE" != true ] \
                || die "--prerelease and --no-prerelease are mutually exclusive"
            PRERELEASE=false
            shift
            ;;
        --make-latest)
            require_value "$1" "${2:-}"
            MAKE_LATEST="$(lowercase "$2")"
            shift 2
            ;;
        --create-draft)
            [ "$MODE" = validate ] || die "--create-draft and --publish are mutually exclusive"
            MODE=draft
            shift
            ;;
        --publish)
            [ "$MODE" = validate ] || die "--create-draft and --publish are mutually exclusive"
            MODE=publish
            shift
            ;;
        --repo)
            require_value "$1" "${2:-}"
            GH_REPO="$2"
            shift 2
            ;;
        --guix-sigs-github-repo)
            require_value "$1" "${2:-}"
            GUIX_SIGS_GH_REPO="$2"
            shift 2
            ;;
        --guix-sigs-branch)
            require_value "$1" "${2:-}"
            GUIX_SIGS_BRANCH="$2"
            shift 2
            ;;
        --trusted-release-branch)
            require_value "$1" "${2:-}"
            TRUSTED_RELEASE_BRANCH="$2"
            TRUSTED_RELEASE_BRANCH_EXPLICIT=1
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) die "Unknown argument: $1" ;;
    esac
done

[ -n "$TAG" ] || die "--tag is required"
[ -n "$ARTIFACTS_DIR" ] || die "--artifacts-dir is required"
[ -n "$TRUSTED_RELEASE_REF" ] || die "--trusted-release-ref is required"
[ -n "$GUIX_SIGS_REPO" ] || die "--guix-sigs-repo is required"
[ -n "$GUIX_SIGS_REF" ] || die "--guix-sigs-ref is required"
[ -n "$RELEASE_LINE" ] || die "--release-line is required"

[[ "$TAG" =~ ^v[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
    || die "--tag must be a safe v-prefixed release tag: $TAG"
case "$RELEASE_LINE" in
    testnet|mainnet) ;;
    *) die "--release-line must be testnet or mainnet: $RELEASE_LINE" ;;
esac
case "$MAKE_LATEST" in
    preserve|true|false|auto) ;;
    *) die "--make-latest must be true, false, or auto: $MAKE_LATEST" ;;
esac
if [ "$RELEASE_LINE" = testnet ] && [ -z "$TESTNET_POSTURE_EVIDENCE" ]; then
    die "--testnet-posture-evidence is required for testnet releases"
fi
P2MR_CONFORMANCE_REQUESTED=0
if [ "$RELEASE_LINE" = mainnet ] \
    || [ -n "$P2MR_V1_CONFORMANCE_EVIDENCE" ] \
    || [ -n "$P2MR_V1_ORACLE_REPORT" ] \
    || [ -n "$P2MR_V1_INTEGRATION_MATRIX" ]; then
    P2MR_CONFORMANCE_REQUESTED=1
    for input_name in \
        P2MR_V1_CONFORMANCE_EVIDENCE \
        P2MR_V1_ORACLE_REPORT \
        P2MR_V1_INTEGRATION_MATRIX; do
        input_path="${!input_name}"
        [ -n "$input_path" ] \
            || die "$input_name is required when qbit P2MR v1 conformance is requested and is always required for mainnet"
        [[ "$input_path" = /* ]] \
            || die "$input_name must be an absolute path"
    done
fi

need_cmd awk gh git gpg grep paste python3 tr
require_git
gh auth status >/dev/null
require_full_sha --trusted-release-ref "$TRUSTED_RELEASE_REF"
require_full_sha --guix-sigs-ref "$GUIX_SIGS_REF"
git check-ref-format --branch "$TRUSTED_RELEASE_BRANCH" >/dev/null 2>&1 \
    || die "--trusted-release-branch is not a valid branch name: $TRUSTED_RELEASE_BRANCH"
git check-ref-format --branch "$GUIX_SIGS_BRANCH" >/dev/null 2>&1 \
    || die "--guix-sigs-branch is not a valid branch name: $GUIX_SIGS_BRANCH"
msg "Trusted release branch: $GH_REPO:$TRUSTED_RELEASE_BRANCH"
if [ "$TRUSTED_RELEASE_BRANCH_EXPLICIT" -eq 0 ]; then
    msg "Hint: a release-line release must pass --trusted-release-branch <line>"
fi

TRUSTED_ROOT="$(git -C "$SCRIPT_DIR/../.." rev-parse --show-toplevel 2>/dev/null)" \
    || die "Publisher is not running from a git checkout"
TRUSTED_ROOT="$(resolve_dir "$TRUSTED_ROOT")"
TRUSTED_SHA="$(git -C "$TRUSTED_ROOT" rev-parse HEAD)"
[ "$(lowercase "$TRUSTED_SHA")" = "$(lowercase "$TRUSTED_RELEASE_REF")" ] \
    || die "Publisher checkout resolved $TRUSTED_SHA, expected $TRUSTED_RELEASE_REF"
require_clean_checkout "Trusted release checkout" "$TRUSTED_ROOT"
[ "$(git -C "$TRUSTED_ROOT" rev-parse --is-shallow-repository)" = false ] \
    || die "Trusted release checkout must not be shallow: $TRUSTED_ROOT"
require_plain_index "Trusted release checkout" "$TRUSTED_ROOT" \
    contrib/release-process ci/release contrib/keys

# Checked here to fail before any network call; the files that actually run are
# checked again after they are exported from the trusted ref below.
required_trusted_paths=(
    ci/release/validate_release_artifacts.py
    ci/release/validate_builder_attestations.py
    ci/release/validate_key_metadata.py
    ci/release/verify_mainnet_release_posture.py
    ci/release/verify_p2mr_v1_conformance.py
    ci/release/verify_testnet_release_posture.py
    contrib/keys/operator-keys/keys.json
)
for required_path in "${required_trusted_paths[@]}"; do
    [ -f "$TRUSTED_ROOT/$required_path" ] \
        || die "Trusted release ref is missing $required_path"
done

ARTIFACTS_DIR="$(resolve_dir "$ARTIFACTS_DIR")"
GUIX_SIGS_ROOT="$(git -C "$GUIX_SIGS_REPO" rev-parse --show-toplevel 2>/dev/null)" \
    || die "--guix-sigs-repo is not a git checkout: $GUIX_SIGS_REPO"
GUIX_SIGS_REPO="$(resolve_dir "$GUIX_SIGS_ROOT")"
GUIX_SIGS_SHA="$(git -C "$GUIX_SIGS_REPO" rev-parse HEAD)"
[ "$(lowercase "$GUIX_SIGS_SHA")" = "$(lowercase "$GUIX_SIGS_REF")" ] \
    || die "qbit-guix.sigs checkout resolved $GUIX_SIGS_SHA, expected $GUIX_SIGS_REF"
require_clean_checkout "qbit-guix.sigs checkout" "$GUIX_SIGS_REPO"
require_full_history "qbit-guix.sigs checkout" "$GUIX_SIGS_REPO"
# The validators read the qbit-guix.sigs files from an export of the pinned
# commit (below), not from this working tree; index flags would only hide local
# edits from the clean check above, so they are refused here, early.
require_plain_index "qbit-guix.sigs checkout" "$GUIX_SIGS_REPO" .

if [ -n "$NOTES_FILE" ]; then
    NOTES_FILE="$(resolve_file "$NOTES_FILE")"
fi
if [ -n "$TESTNET_POSTURE_EVIDENCE" ]; then
    TESTNET_POSTURE_EVIDENCE="$(resolve_file "$TESTNET_POSTURE_EVIDENCE")"
fi
if [ "$P2MR_CONFORMANCE_REQUESTED" -eq 1 ]; then
    P2MR_V1_CONFORMANCE_EVIDENCE="$(resolve_file "$P2MR_V1_CONFORMANCE_EVIDENCE")"
    P2MR_V1_ORACLE_REPORT="$(resolve_file "$P2MR_V1_ORACLE_REPORT")"
    P2MR_V1_INTEGRATION_MATRIX="$(resolve_file "$P2MR_V1_INTEGRATION_MATRIX")"
fi
RELEASE_NAME="${RELEASE_NAME:-qbit $TAG}"

# Only the exact ref refs/tags/$TAG is read (show-ref --verify): git looks a
# name up as $GIT_DIR/<name>, refs/<name>, refs/tags/<name>, ..., even
# refs/refs/tags/$TAG for refs/tags/$TAG, so a ref git status does not show
# could otherwise stand in for the tag. The signature check uses this object.
TAG_OBJECT="$(git -C "$TRUSTED_ROOT" show-ref --verify --hash "refs/tags/$TAG" 2>/dev/null || true)"
[ -n "$TAG_OBJECT" ] && [ "$(git -C "$TRUSTED_ROOT" cat-file -t "$TAG_OBJECT" 2>/dev/null)" = tag ] \
    || die "Trusted release checkout is missing annotated tag $TAG"
# Validators that take the tag name (verify_testnet_release_posture.py resolves
# $TAG^{commit}) must see the same object, so the bare name must resolve to it.
BARE_TAG_OBJECT="$(git -C "$TRUSTED_ROOT" rev-parse -q --verify "$TAG^{tag}" 2>/dev/null || true)"
[ "$BARE_TAG_OBJECT" = "$TAG_OBJECT" ] \
    || die "The name $TAG resolves to ${BARE_TAG_OBJECT:-no tag}, not to refs/tags/$TAG ($TAG_OBJECT): remove the ref git finds first (.git/$TAG or refs/$TAG)"
# The tag object must name $TAG: its signature covers that name, so a signed
# tag of another release cannot be put at refs/tags/$TAG. awk reads the whole
# object, so git cat-file never meets a closed pipe.
TAG_OBJECT_NAME="$(git -C "$TRUSTED_ROOT" cat-file tag "$TAG_OBJECT" \
    | awk 'BEGIN { header = 1 } $0 == "" { header = 0 } header && /^tag / { print substr($0, 5) }')"
[ "$TAG_OBJECT_NAME" = "$TAG" ] \
    || die "Release tag $TAG is a tag object named $(printf '%q' "${TAG_OBJECT_NAME:-nothing}") ($TAG_OBJECT at refs/tags/$TAG)"
TAG_TARGET="$(git -C "$TRUSTED_ROOT" rev-parse -q --verify "$TAG_OBJECT^{commit}" 2>/dev/null || true)"
[ -n "$TAG_TARGET" ] || die "Trusted release checkout is missing commit target for $TAG"
[ "$(lowercase "$TRUSTED_RELEASE_REF")" != "$(lowercase "$TAG_OBJECT")" ] \
    || die "--trusted-release-ref must not equal the release tag object"
[ "$(lowercase "$TRUSTED_RELEASE_REF")" != "$(lowercase "$TAG_TARGET")" ] \
    || die "--trusted-release-ref must not equal the release tag target"
on_first_parent_history "$TRUSTED_ROOT" "$TRUSTED_RELEASE_REF" "$TAG_TARGET" \
    || die "Release tag target $TAG_TARGET must be on the first-parent history of trusted release ref $TRUSTED_RELEASE_REF: tag the merge commit that landed the release, not the pull request's head"

GH_REPO_PATH="$(github_repo_path "$GH_REPO")"
GUIX_SIGS_GH_REPO_PATH="$(github_repo_path "$GUIX_SIGS_GH_REPO")"
REPO_CAN_PUSH="$(
    gh api "repos/$GH_REPO_PATH" --jq '(.permissions.push // false) | tostring'
)" || die "Could not verify authenticated access to $GH_REPO"
[ "$REPO_CAN_PUSH" = true ] \
    || die "Authenticated GitHub account requires push access to $GH_REPO to discover draft releases"
msg "Verifying trusted release ref is public and on $GH_REPO:$TRUSTED_RELEASE_BRANCH"
remote_commit "$GH_REPO_PATH" "$TRUSTED_RELEASE_REF" "Trusted release ref"
TRUSTED_BRANCH_TIP="$(
    fetch_branch_tip "$TRUSTED_ROOT" "$GH_REPO_PATH" "$TRUSTED_RELEASE_BRANCH" "Trusted release"
)"
on_first_parent_history "$TRUSTED_ROOT" "$TRUSTED_BRANCH_TIP" "$TRUSTED_RELEASE_REF" \
    || die "Trusted release ref $TRUSTED_RELEASE_REF must be on the first-parent history of $GH_REPO:$TRUSTED_RELEASE_BRANCH ($TRUSTED_BRANCH_TIP)"
msg "Verifying qbit-guix.sigs commit is public and merged"
remote_commit "$GUIX_SIGS_GH_REPO_PATH" "$GUIX_SIGS_REF" "qbit-guix.sigs commit"
GUIX_SIGS_BRANCH_TIP="$(
    fetch_branch_tip "$GUIX_SIGS_REPO" "$GUIX_SIGS_GH_REPO_PATH" "$GUIX_SIGS_BRANCH" "qbit-guix.sigs"
)"
on_first_parent_history "$GUIX_SIGS_REPO" "$GUIX_SIGS_BRANCH_TIP" "$GUIX_SIGS_REF" \
    || die "qbit-guix.sigs commit $GUIX_SIGS_REF must be on the first-parent history of $GUIX_SIGS_GH_REPO:$GUIX_SIGS_BRANCH ($GUIX_SIGS_BRANCH_TIP)"

verify_remote_tag_pin initial

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qbit-release-publish.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT
VALIDATION_OUTPUT="$WORK_DIR/validation-output.env"
LOCAL_ASSET_MANIFEST="$WORK_DIR/local-assets.tsv"
REMOTE_ASSET_MANIFEST="$WORK_DIR/remote-assets.tsv"
ASSET_LIST_ERRORS="$WORK_DIR/asset-list-errors"
: > "$VALIDATION_OUTPUT"

# The validators and the release key policy come from the trusted ref's git
# objects, not the working tree, and run isolated from Python startup hooks
# and bytecode, so nothing in the checkout outside its commit can change them.
TRUSTED_EXPORT="$WORK_DIR/trusted-ref"
export_trusted_paths "Trusted release ref" "$TRUSTED_ROOT" "$TRUSTED_RELEASE_REF" "$TRUSTED_EXPORT" \
    ci/release contrib/keys/operator-keys
VALIDATORS="$TRUSTED_EXPORT/ci/release"
TRUSTED_KEYS_DIR="$TRUSTED_EXPORT/contrib/keys/operator-keys"
for required_path in "${required_trusted_paths[@]}"; do
    [ -f "$TRUSTED_EXPORT/$required_path" ] \
        || die "Trusted release ref $TRUSTED_RELEASE_REF does not contain $required_path"
done
# The key mirror and this version's attestations, the only qbit-guix.sigs
# files the validators read, come from the pinned commit's objects too: index
# stat data, core.checkStat or core.ignoreCase can hide working-tree changes
# from git status, so the checkout checks above only give early, clear errors.
GUIX_SIGS_EXPORT="$WORK_DIR/qbit-guix.sigs-ref"
export_trusted_paths "qbit-guix.sigs ref" "$GUIX_SIGS_REPO" "$GUIX_SIGS_REF" "$GUIX_SIGS_EXPORT" \
    operator-keys "${TAG#v}"
[ -z "$NOTES_FILE" ] || prepare_release_notes

if [ "$RELEASE_LINE" = mainnet ]; then
    msg "Validating fail-closed mainnet launch posture"
    "${PYTHON[@]}" "$VALIDATORS/verify_mainnet_release_posture.py" \
        --source-root "$TRUSTED_ROOT" \
        --release-tag "$TAG"
fi

if [ "$P2MR_CONFORMANCE_REQUESTED" -eq 1 ]; then
    msg "Validating qbit P2MR v1 release conformance"
    "${PYTHON[@]}" "$VALIDATORS/verify_p2mr_v1_conformance.py" \
        --evidence "$P2MR_V1_CONFORMANCE_EVIDENCE" \
        --source-root "$TRUSTED_ROOT" \
        --release-tag "$TAG" \
        --oracle-report "$P2MR_V1_ORACLE_REPORT" \
        --integration-matrix "$P2MR_V1_INTEGRATION_MATRIX" \
        --github-output "$VALIDATION_OUTPUT"
fi

if [ "$RELEASE_LINE" = testnet ]; then
    msg "Validating testnet release posture"
    posture_args=(
        --evidence "$TESTNET_POSTURE_EVIDENCE"
        --source-root "$TRUSTED_ROOT"
        --release-tag "$TAG"
        --artifacts-dir "$ARTIFACTS_DIR"
    )
    [ "$ALLOW_UNSIGNED_PLATFORM_ARTIFACTS" -eq 0 ] \
        || posture_args+=(--allow-unsigned-platform-artifacts)
    [ "$ALLOW_CODESIGNING_ARTIFACTS" -eq 0 ] \
        || posture_args+=(--allow-codesigning-artifacts)
    "${PYTHON[@]}" "$VALIDATORS/verify_testnet_release_posture.py" \
        "${posture_args[@]}"
fi

msg "Validating release artifacts and release-signature quorum"
release_args=(
    --artifacts-dir "$ARTIFACTS_DIR"
    --tag "$TAG"
    --release-line "$RELEASE_LINE"
    --operator-key-policy "$TRUSTED_KEYS_DIR/keys.json"
    --operator-keys-dir "$TRUSTED_KEYS_DIR"
    --github-output "$VALIDATION_OUTPUT"
)
[ "$REQUIRE_PHOTON" -eq 0 ] || release_args+=(--require-photon-artifact)
[ "$ALLOW_UNSIGNED_PLATFORM_ARTIFACTS" -eq 0 ] \
    || release_args+=(--allow-unsigned-platform-artifacts)
[ "$ALLOW_CODESIGNING_ARTIFACTS" -eq 0 ] \
    || release_args+=(--allow-codesigning-artifacts)
(cd "$TRUSTED_ROOT" && "${PYTHON[@]}" "$VALIDATORS/validate_release_artifacts.py" "${release_args[@]}")
msg "Validating the release tag signature"
verify_release_tag_signature

msg "Validating qbit-guix.sigs key-policy mirror"
"${PYTHON[@]}" "$VALIDATORS/validate_key_metadata.py" \
    --operator-policy "$TRUSTED_KEYS_DIR/keys.json" \
    --operator-keys-dir "$TRUSTED_KEYS_DIR" \
    --operator-policy-mirror "$GUIX_SIGS_EXPORT/operator-keys/keys.json" \
    --operator-keys-dir-mirror "$GUIX_SIGS_EXPORT/operator-keys" \
    --skip-policy-transition-validation \
    --require-public-key-files

PHOTON_ARTIFACT_COUNT="$(github_output_value "$VALIDATION_OUTPUT" photon_artifact_count)"
PHOTON_ARTIFACT_COUNT="${PHOTON_ARTIFACT_COUNT:-0}"
msg "Validating builder-attestation quorum and signed-tag source binding"
builder_args=(
    --artifacts-dir "$ARTIFACTS_DIR"
    --tag "$TAG"
    --source-root "$TRUSTED_ROOT"
    --expected-tag-target "$TAG_TARGET"
    --release-line "$RELEASE_LINE"
    --guix-sigs-repo "$GUIX_SIGS_EXPORT"
    --operator-key-policy "$TRUSTED_KEYS_DIR/keys.json"
    --operator-keys-dir "$TRUSTED_KEYS_DIR"
    --guix-operator-key-policy "$GUIX_SIGS_EXPORT/operator-keys/keys.json"
    --guix-operator-keys-dir "$GUIX_SIGS_EXPORT/operator-keys"
    --github-output "$VALIDATION_OUTPUT"
)
if [ "$REQUIRE_PHOTON" -eq 1 ] || [ "$PHOTON_ARTIFACT_COUNT" != 0 ]; then
    builder_args+=(--artifact core --artifact photon)
fi
"${PYTHON[@]}" "$VALIDATORS/validate_builder_attestations.py" "${builder_args[@]}"

upload_files=()
while IFS= read -r upload_file; do
    [ -n "$upload_file" ] || continue
    upload_files+=("$upload_file")
done < <(github_output_multiline "$VALIDATION_OUTPUT" files)
[ "${#upload_files[@]}" -gt 0 ] || die "Release validator emitted no upload files"

for upload_file in "${upload_files[@]}"; do
    [ -f "$upload_file" ] || die "Validated upload file is missing: $upload_file"
    [ ! -L "$upload_file" ] || die "Validated upload file must not be a symlink: $upload_file"
    case "$upload_file" in
        "$ARTIFACTS_DIR"/*) ;;
        *) die "Validated upload file is outside the artifacts directory: $upload_file" ;;
    esac
    asset_name="$(basename "$upload_file")"
    if printf '%s' "$asset_name" | grep -q '[[:cntrl:]]'; then
        die "Validated upload filename contains control characters"
    fi
    [[ "$asset_name" != *'#'* ]] \
        || die "Validated upload filename must not contain #: $asset_name"
done

"${PYTHON_SNIPPET[@]}" - "$LOCAL_ASSET_MANIFEST" "${upload_files[@]}" <<'PY'
import hashlib
import sys
from pathlib import Path

destination = Path(sys.argv[1])
seen: set[str] = set()
lines: list[str] = []
for value in sys.argv[2:]:
    path = Path(value)
    name = path.name
    if name in seen:
        raise SystemExit(f"duplicate validated upload name: {name}")
    seen.add(name)
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    lines.append(f"{name}\t{digest.hexdigest()}")
destination.write_text("\n".join(sorted(lines)) + "\n", encoding="utf8")
PY

FILE_COUNT="$(github_output_value "$VALIDATION_OUTPUT" file_count)"
[ "$FILE_COUNT" = "${#upload_files[@]}" ] \
    || die "Validator file count $FILE_COUNT does not match upload list ${#upload_files[@]}"

ARTIFACT_COUNT="$(github_output_value "$VALIDATION_OUTPUT" artifact_count)"
CORE_ARTIFACT_COUNT="$(github_output_value "$VALIDATION_OUTPUT" core_artifact_count)"
RELEASE_SIGNER_COUNT="$(github_output_value "$VALIDATION_OUTPUT" release_signer_count)"
RELEASE_SIGNATURE_COUNT="$(github_output_value "$VALIDATION_OUTPUT" release_signature_count)"
RELEASE_SIGNATURE_QUORUM="$(github_output_value "$VALIDATION_OUTPUT" release_signature_quorum)"
RELEASE_SIGNATURE_ALIASES="$(github_output_value "$VALIDATION_OUTPUT" release_signature_aliases)"
KEYS_JSON_SHA256="$(github_output_value "$VALIDATION_OUTPUT" keys_json_sha256)"
BUILDER_QUORUM="$(github_output_value "$VALIDATION_OUTPUT" builder_attestation_quorum)"
BUILDER_CORE_COUNT="$(github_output_value "$VALIDATION_OUTPUT" builder_attestation_core_count)"
BUILDER_PHOTON_COUNT="$(github_output_value "$VALIDATION_OUTPUT" builder_attestation_photon_count)"
BUILDER_CORE_ALIASES="$(github_output_value "$VALIDATION_OUTPUT" builder_attestation_core_aliases)"
BUILDER_PHOTON_ALIASES="$(github_output_value "$VALIDATION_OUTPUT" builder_attestation_photon_aliases)"
SOURCE_ARCHIVE="$(github_output_value "$VALIDATION_OUTPUT" builder_attestation_source_archive)"
SOURCE_SHA256="$(github_output_value "$VALIDATION_OUTPUT" builder_attestation_source_sha256)"
SOURCE_TAG_TARGET="$(github_output_value "$VALIDATION_OUTPUT" builder_attestation_tag_target)"

require_output artifact_count "$ARTIFACT_COUNT"
require_output core_artifact_count "$CORE_ARTIFACT_COUNT"
require_output release_signer_count "$RELEASE_SIGNER_COUNT"
require_output release_signature_count "$RELEASE_SIGNATURE_COUNT"
require_output release_signature_quorum "$RELEASE_SIGNATURE_QUORUM"
require_output release_signature_aliases "$RELEASE_SIGNATURE_ALIASES"
require_output keys_json_sha256 "$KEYS_JSON_SHA256"
require_output builder_attestation_quorum "$BUILDER_QUORUM"
require_output builder_attestation_core_count "$BUILDER_CORE_COUNT"
require_output builder_attestation_core_aliases "$BUILDER_CORE_ALIASES"
require_output builder_attestation_source_archive "$SOURCE_ARCHIVE"
require_output builder_attestation_source_sha256 "$SOURCE_SHA256"
require_output builder_attestation_tag_target "$SOURCE_TAG_TARGET"
if [ "$PHOTON_ARTIFACT_COUNT" != 0 ]; then
    require_output builder_attestation_photon_count "$BUILDER_PHOTON_COUNT"
    require_output builder_attestation_photon_aliases "$BUILDER_PHOTON_ALIASES"
fi
[[ "$KEYS_JSON_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || die "Release validator emitted an invalid keys_json_sha256"
[[ "$SOURCE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
    || die "Builder validator emitted an invalid source archive SHA256"
[ "$(lowercase "$SOURCE_TAG_TARGET")" = "$(lowercase "$TAG_TARGET")" ] \
    || die "Builder validator source target $SOURCE_TAG_TARGET does not match $TAG_TARGET"

msg "Validated upload set contains ${#upload_files[@]} files"
msg "Pinned refs: tag_object=$TAG_OBJECT tag_target=$TAG_TARGET" \
    "trusted_release_ref=$TRUSTED_RELEASE_REF guix_sigs_ref=$GUIX_SIGS_REF"
msg "Key policy: sha256=$KEYS_JSON_SHA256 active_release_signers=$RELEASE_SIGNER_COUNT"
msg "Artifacts: total=$ARTIFACT_COUNT core=$CORE_ARTIFACT_COUNT photon=$PHOTON_ARTIFACT_COUNT"
msg "Release signatures: $RELEASE_SIGNATURE_COUNT/$RELEASE_SIGNATURE_QUORUM aliases=$RELEASE_SIGNATURE_ALIASES"
msg "Builder attestations: core=$BUILDER_CORE_COUNT/$BUILDER_QUORUM" \
    "aliases=$BUILDER_CORE_ALIASES photon=${BUILDER_PHOTON_COUNT:-n/a}/$BUILDER_QUORUM" \
    "aliases=${BUILDER_PHOTON_ALIASES:-n/a}"
msg "Builder source: $SOURCE_ARCHIVE $SOURCE_SHA256 from $SOURCE_TAG_TARGET"

RELEASE_ID=""
RELEASE_IS_DRAFT=""
RELEASE_IS_IMMUTABLE=""
RELEASE_TAG=""
RELEASE_URL=""
if RELEASE_VIEW_OUTPUT="$(release_view)"; then
    load_release_view "$RELEASE_VIEW_OUTPUT"
    if [ "$RELEASE_IS_DRAFT" != true ]; then
        [ "$MODE" = validate ] \
            || die "Release $TAG already exists and is published; refusing to modify it"
        require_immutable_release
        write_remote_asset_manifest "$REMOTE_ASSET_MANIFEST" \
            || asset_list_failure "published release validation"
        compare_asset_manifests exact "$REMOTE_ASSET_MANIFEST" \
            || die "Published release assets do not exactly match the validated upload set"
        verify_remote_tag_pin post-publication
        msg "Published release assets exactly match local names and SHA256 digests"
        msg "Validation-only mode complete: $RELEASE_URL (immutable=true)"
        exit 0
    fi
    require_asset_manifest_match subset "draft resume verification" \
        "Draft release assets are not a digest-matching subset of the validated upload set"
    msg "Found matching draft release; missing assets will be resumed"
else
    view_status=$?
    if [ "$view_status" -eq 3 ]; then
        : > "$REMOTE_ASSET_MANIFEST"
    else
        cat "$WORK_DIR/release-view-errors" >&2
        die "Could not inspect GitHub Release $TAG in $GH_REPO"
    fi
fi

[ -n "${EFFECTIVE_NOTES_FILE:-}" ] || prepare_release_notes

create_args=(
    gh release create "$TAG"
    --repo "$GH_REPO"
    --draft
    --verify-tag
    --title "$RELEASE_NAME"
)
create_args+=(--notes-file "$EFFECTIVE_NOTES_FILE")
case "$PRERELEASE" in
    true) create_args+=(--prerelease) ;;
    preserve|false) ;;
esac
case "$MAKE_LATEST" in
    true) create_args+=(--latest) ;;
    preserve|false) create_args+=(--latest=false) ;;
    auto) ;;
esac

if [ "$MODE" = validate ]; then
    msg "Validation-only mode; no GitHub Release will be changed"
    if [ -z "$RELEASE_ID" ]; then
        msg "Draft release $TAG would be created with the expected notes; rerun with --create-draft to create it"
    else
        verify_release_notes \
            || die "Draft release notes do not match the expected notes"
        msg "Draft release notes exactly match the expected notes"
    fi
    for upload_file in "${upload_files[@]}"; do
        asset_name="$(basename "$upload_file")"
        remote_has_asset "$asset_name" \
            || print_shell_command gh release upload "$TAG" "$upload_file" --repo "$GH_REPO"
    done
    exit 0
fi

if [ -z "$RELEASE_ID" ]; then
    RELEASE_CREATED_THIS_RUN=1
    msg "Creating draft release $TAG"
    "${create_args[@]}"
    require_release_view
    [ "$RELEASE_IS_DRAFT" = true ] || die "New release $TAG is not a draft"
fi

require_asset_manifest_match subset "pre-upload verification" \
    "Draft release assets are not a digest-matching subset of the validated upload set"
for upload_file in "${upload_files[@]}"; do
    asset_name="$(basename "$upload_file")"
    if remote_has_asset "$asset_name"; then
        msg "Keeping verified draft asset $asset_name"
    else
        msg "Uploading $asset_name"
        gh release upload "$TAG" "$upload_file" --repo "$GH_REPO"
    fi
done

require_asset_manifest_match exact "draft verification" \
    "Draft release assets do not exactly match the validated upload set"
msg "Draft release assets exactly match local names and SHA256 digests"

edit_args=(
    gh release edit "$TAG"
    --repo "$GH_REPO"
    --notes-file "$EFFECTIVE_NOTES_FILE"
)
[ "$RELEASE_NAME_EXPLICIT" -eq 0 ] || edit_args+=(--title "$RELEASE_NAME")
case "$PRERELEASE" in
    true) edit_args+=(--prerelease) ;;
    false) edit_args+=(--prerelease=false) ;;
    preserve) ;;
esac
if [ "$MODE" = draft ]; then
    case "$MAKE_LATEST" in
        true) edit_args+=(--latest) ;;
        false) edit_args+=(--latest=false) ;;
        preserve|auto) ;;
    esac
fi
msg "Updating verified draft metadata for $TAG"
"${edit_args[@]}" --draft
if [ "$MODE" = draft ] && [ "$MAKE_LATEST" = auto ]; then
    gh api "repos/$GH_REPO_PATH/releases/$RELEASE_ID" \
        --method PATCH -f make_latest=legacy >/dev/null \
        || die "Could not apply automatic latest-release policy to draft $TAG"
fi
verify_release_notes \
    || die "Draft release notes do not match the expected notes"
msg "Draft release notes exactly match the expected notes"

if [ "$MODE" = publish ]; then
    publish_args=(
        gh api "repos/$GH_REPO_PATH/releases/$RELEASE_ID"
        --method PATCH
        -F draft=false
    )
    case "$MAKE_LATEST" in
        true|false) publish_args+=(-f "make_latest=$MAKE_LATEST") ;;
        auto) publish_args+=(-f make_latest=legacy) ;;
        preserve)
            [ "$RELEASE_CREATED_THIS_RUN" -eq 0 ] \
                || publish_args+=(-f make_latest=false)
            ;;
    esac
    msg "Publishing release $TAG"
    verify_remote_tag_pin pre-publication
    "${publish_args[@]}" >/dev/null \
        || die "Could not publish release $TAG"
    wait_for_published_immutable_release
    require_asset_manifest_match exact "post-publication verification" \
        "Published immutable release assets do not exactly match the validated upload set" \
        "Release $TAG is already published. Preserve the publisher transcript and" \
        "rerun this publisher without --create-draft or --publish to verify the" \
        "published assets once the asset list is readable."
    verify_remote_tag_pin post-publication
    msg "Published immutable release assets exactly match local names and SHA256 digests"
    msg "Published immutable release: $RELEASE_URL"
else
    require_release_view
    [ "$RELEASE_IS_DRAFT" = true ] || die "Release $TAG did not remain a draft"
    msg "Verified draft release: $RELEASE_URL"
fi
msg "Evidence: tag_object=$TAG_OBJECT tag_target=$TAG_TARGET" \
    "trusted_release_ref=$TRUSTED_RELEASE_REF guix_sigs_ref=$GUIX_SIGS_REF" \
    "artifact_count=$ARTIFACT_COUNT file_count=$FILE_COUNT source_sha256=$SOURCE_SHA256"
