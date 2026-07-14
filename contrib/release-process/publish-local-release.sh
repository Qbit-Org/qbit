#!/usr/bin/env bash
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

export LC_ALL=C
set -euo pipefail

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
  --trusted-release-ref SHA         Full commit SHA of this trusted checkout.
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

require_clean_checkout() {
    local label="$1"
    local root="$2"
    [ -z "$(git -C "$root" status --porcelain --untracked-files=normal)" ] \
        || die "$label must be clean: $root"
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

remote_commit_on_branch() {
    local repository="$1"
    local commit_sha="$2"
    local branch="$3"
    local label="$4"
    local status
    status="$(gh api "repos/$repository/compare/$branch...$commit_sha" --jq '.status')" \
        || die "$label $commit_sha is not comparable with $repository:$branch"
    case "$status" in
        behind|identical) ;;
        *) die "$label $commit_sha is not reachable from $repository:$branch (status: $status)" ;;
    esac
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
        python3 - "$NOTES_FILE" "$EFFECTIVE_NOTES_FILE" <<'PY'
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
    python3 - "$response" "$EFFECTIVE_NOTES_FILE" <<'PY'
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
    python3 - "$EFFECTIVE_NOTES_FILE" "$response" <<'PY'
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

write_remote_asset_manifest() {
    local destination="$1"
    [ -n "$RELEASE_ID" ] || die "Cannot list assets without a release ID"
    gh api "repos/$GH_REPO_PATH/releases/$RELEASE_ID/assets?per_page=100" \
        --paginate --jq '.[] | [.name, (.digest // "")] | @tsv' > "$destination"
}

compare_asset_manifests() {
    local mode="$1"
    local remote_manifest="$2"
    python3 - "$LOCAL_ASSET_MANIFEST" "$remote_manifest" "$mode" <<'PY'
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

wait_for_asset_manifest_match() {
    local mode="$1"
    local attempt
    local errors="$WORK_DIR/asset-verification-errors"
    for attempt in 1 2 3 4 5; do
        write_remote_asset_manifest "$REMOTE_ASSET_MANIFEST"
        if compare_asset_manifests "$mode" "$REMOTE_ASSET_MANIFEST" 2> "$errors"; then
            return 0
        fi
        [ "$attempt" -eq 5 ] || sleep 2
    done
    cat "$errors" >&2
    return 1
}

wait_for_subset_assets() {
    wait_for_asset_manifest_match subset
}

wait_for_exact_assets() {
    wait_for_asset_manifest_match exact
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

need_cmd awk gh git gpg grep python3 tr
gh auth status >/dev/null
require_full_sha --trusted-release-ref "$TRUSTED_RELEASE_REF"
require_full_sha --guix-sigs-ref "$GUIX_SIGS_REF"

TRUSTED_ROOT="$(git -C "$SCRIPT_DIR/../.." rev-parse --show-toplevel 2>/dev/null)" \
    || die "Publisher is not running from a git checkout"
TRUSTED_ROOT="$(resolve_dir "$TRUSTED_ROOT")"
TRUSTED_SHA="$(git -C "$TRUSTED_ROOT" rev-parse HEAD)"
[ "$(lowercase "$TRUSTED_SHA")" = "$(lowercase "$TRUSTED_RELEASE_REF")" ] \
    || die "Publisher checkout resolved $TRUSTED_SHA, expected $TRUSTED_RELEASE_REF"
require_clean_checkout "Trusted release checkout" "$TRUSTED_ROOT"

required_trusted_paths=(
    ci/release/validate_release_artifacts.py
    ci/release/validate_builder_attestations.py
    ci/release/validate_key_metadata.py
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

TAG_OBJECT="$(git -C "$TRUSTED_ROOT" rev-parse -q --verify "refs/tags/$TAG^{tag}" 2>/dev/null || true)"
TAG_TARGET="$(git -C "$TRUSTED_ROOT" rev-parse -q --verify "refs/tags/$TAG^{commit}" 2>/dev/null || true)"
[ -n "$TAG_OBJECT" ] || die "Trusted release checkout is missing annotated tag $TAG"
[ -n "$TAG_TARGET" ] || die "Trusted release checkout is missing commit target for $TAG"
[ "$(lowercase "$TRUSTED_RELEASE_REF")" != "$(lowercase "$TAG_OBJECT")" ] \
    || die "--trusted-release-ref must not equal the release tag object"
[ "$(lowercase "$TRUSTED_RELEASE_REF")" != "$(lowercase "$TAG_TARGET")" ] \
    || die "--trusted-release-ref must not equal the release tag target"
git -C "$TRUSTED_ROOT" merge-base --is-ancestor "$TAG_TARGET" "$TRUSTED_RELEASE_REF" \
    || die "Release tag target $TAG_TARGET must be an ancestor of trusted release ref $TRUSTED_RELEASE_REF"

GH_REPO_PATH="$(github_repo_path "$GH_REPO")"
GUIX_SIGS_GH_REPO_PATH="$(github_repo_path "$GUIX_SIGS_GH_REPO")"
REPO_CAN_PUSH="$(
    gh api "repos/$GH_REPO_PATH" --jq '(.permissions.push // false) | tostring'
)" || die "Could not verify authenticated access to $GH_REPO"
[ "$REPO_CAN_PUSH" = true ] \
    || die "Authenticated GitHub account requires push access to $GH_REPO to discover draft releases"
msg "Verifying trusted release ref is public"
remote_commit "$GH_REPO_PATH" "$TRUSTED_RELEASE_REF" "Trusted release ref"
msg "Verifying qbit-guix.sigs commit is public and merged"
remote_commit "$GUIX_SIGS_GH_REPO_PATH" "$GUIX_SIGS_REF" "qbit-guix.sigs commit"
remote_commit_on_branch "$GUIX_SIGS_GH_REPO_PATH" "$GUIX_SIGS_REF" \
    "$GUIX_SIGS_BRANCH" "qbit-guix.sigs commit"

verify_remote_tag_pin initial

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/qbit-release-publish.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT
VALIDATION_OUTPUT="$WORK_DIR/validation-output.env"
LOCAL_ASSET_MANIFEST="$WORK_DIR/local-assets.tsv"
REMOTE_ASSET_MANIFEST="$WORK_DIR/remote-assets.tsv"
: > "$VALIDATION_OUTPUT"
[ -z "$NOTES_FILE" ] || prepare_release_notes

if [ "$P2MR_CONFORMANCE_REQUESTED" -eq 1 ]; then
    msg "Validating qbit P2MR v1 release conformance"
    python3 "$TRUSTED_ROOT/ci/release/verify_p2mr_v1_conformance.py" \
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
    python3 "$TRUSTED_ROOT/ci/release/verify_testnet_release_posture.py" \
        "${posture_args[@]}"
fi

msg "Validating release artifacts and release-signature quorum"
release_args=(
    --artifacts-dir "$ARTIFACTS_DIR"
    --tag "$TAG"
    --release-line "$RELEASE_LINE"
    --operator-key-policy "$TRUSTED_ROOT/contrib/keys/operator-keys/keys.json"
    --operator-keys-dir "$TRUSTED_ROOT/contrib/keys/operator-keys"
    --verify-tag-signature
    --github-output "$VALIDATION_OUTPUT"
)
[ "$REQUIRE_PHOTON" -eq 0 ] || release_args+=(--require-photon-artifact)
[ "$ALLOW_UNSIGNED_PLATFORM_ARTIFACTS" -eq 0 ] \
    || release_args+=(--allow-unsigned-platform-artifacts)
[ "$ALLOW_CODESIGNING_ARTIFACTS" -eq 0 ] \
    || release_args+=(--allow-codesigning-artifacts)
(cd "$TRUSTED_ROOT" && python3 ci/release/validate_release_artifacts.py "${release_args[@]}")

msg "Validating qbit-guix.sigs key-policy mirror"
python3 "$TRUSTED_ROOT/ci/release/validate_key_metadata.py" \
    --operator-policy "$TRUSTED_ROOT/contrib/keys/operator-keys/keys.json" \
    --operator-keys-dir "$TRUSTED_ROOT/contrib/keys/operator-keys" \
    --operator-policy-mirror "$GUIX_SIGS_REPO/operator-keys/keys.json" \
    --operator-keys-dir-mirror "$GUIX_SIGS_REPO/operator-keys" \
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
    --guix-sigs-repo "$GUIX_SIGS_REPO"
    --operator-key-policy "$TRUSTED_ROOT/contrib/keys/operator-keys/keys.json"
    --operator-keys-dir "$TRUSTED_ROOT/contrib/keys/operator-keys"
    --guix-operator-key-policy "$GUIX_SIGS_REPO/operator-keys/keys.json"
    --guix-operator-keys-dir "$GUIX_SIGS_REPO/operator-keys"
    --github-output "$VALIDATION_OUTPUT"
)
if [ "$REQUIRE_PHOTON" -eq 1 ] || [ "$PHOTON_ARTIFACT_COUNT" != 0 ]; then
    builder_args+=(--artifact core --artifact photon)
fi
python3 "$TRUSTED_ROOT/ci/release/validate_builder_attestations.py" "${builder_args[@]}"

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

python3 - "$LOCAL_ASSET_MANIFEST" "${upload_files[@]}" <<'PY'
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
        write_remote_asset_manifest "$REMOTE_ASSET_MANIFEST"
        compare_asset_manifests exact "$REMOTE_ASSET_MANIFEST"
        verify_remote_tag_pin post-publication
        msg "Published release assets exactly match local names and SHA256 digests"
        msg "Validation-only mode complete: $RELEASE_URL (immutable=true)"
        exit 0
    fi
    wait_for_subset_assets \
        || die "Draft release assets are not a digest-matching subset of the validated upload set"
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

wait_for_subset_assets \
    || die "Draft release assets are not a digest-matching subset of the validated upload set"
for upload_file in "${upload_files[@]}"; do
    asset_name="$(basename "$upload_file")"
    if remote_has_asset "$asset_name"; then
        msg "Keeping verified draft asset $asset_name"
    else
        msg "Uploading $asset_name"
        gh release upload "$TAG" "$upload_file" --repo "$GH_REPO"
    fi
done

wait_for_exact_assets \
    || die "Draft release assets do not exactly match the validated upload set"
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
    wait_for_exact_assets \
        || die "Published immutable release assets do not exactly match the validated upload set"
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
