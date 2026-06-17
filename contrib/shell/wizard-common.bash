#!/usr/bin/env bash
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

export wizard_name="${wizard_name:-qbit release workflow wizard}"
export WIZARD_PLAN="${WIZARD_PLAN:-0}"
export WIZARD_RESUME="${WIZARD_RESUME:-0}"
export WIZARD_DRY_RUN="${WIZARD_DRY_RUN:-0}"
export WIZARD_YES="${WIZARD_YES:-0}"
export WIZARD_NON_INTERACTIVE="${WIZARD_NON_INTERACTIVE:-0}"
export WIZARD_LIST_RUNS="${WIZARD_LIST_RUNS:-0}"
WIZARD_CONFIG="${WIZARD_CONFIG:-}"
WIZARD_WRITE_CONFIG="${WIZARD_WRITE_CONFIG:-}"
WIZARD_STATE_DIR="${WIZARD_STATE_DIR:-}"
WIZARD_RESUME_TARGET="${WIZARD_RESUME_TARGET:-}"
WIZARD_STATE_ROOT="${WIZARD_STATE_ROOT:-$HOME/.qbit-release-wizards}"

wizard_banner() {
    msg "$wizard_name"
    echo "This is a high-level wizard for normal operator use."
    echo "It orchestrates lower-level helper scripts and writes checkpoint state."
    echo "Run lower-level scripts directly only for recovery, debugging, or a known failed step."
}

wizard_usage_common() {
    cat <<'EOF'

Common wizard options:
  --plan                 Print stages and exit.
  --list-runs            List remembered runs for this wizard and exit.
  --resume [latest]      Load the remembered run and skip completed steps.
  --state-dir PATH       Checkpoint directory.
  --config PATH          Source answers from a shell config file.
  --write-config PATH    Write selected answers for review/reuse.
  --dry-run              Print lower-level commands without running them.
  --yes, -y              Accept confirmation prompts.
  --non-interactive      Refuse real sensitive flows unless used with --dry-run.
EOF
}

wizard_parse_common_arg() {
    export WIZARD_COMMON_CONSUMED=1
    case "${1:-}" in
        --plan)
            WIZARD_PLAN=1
            return 0
            ;;
        --resume)
            WIZARD_RESUME=1
            if [ "${2:-}" = "latest" ]; then
                WIZARD_RESUME_TARGET=latest
                export WIZARD_COMMON_CONSUMED=2
            fi
            return 0
            ;;
        --list-runs)
            WIZARD_LIST_RUNS=1
            return 0
            ;;
        --state-dir)
            [ -n "${2:-}" ] || die "--state-dir requires a path"
            WIZARD_STATE_DIR="$2"
            export WIZARD_COMMON_CONSUMED=2
            return 0
            ;;
        --config)
            [ -n "${2:-}" ] || die "--config requires a path"
            WIZARD_CONFIG="$2"
            export WIZARD_COMMON_CONSUMED=2
            return 0
            ;;
        --write-config)
            [ -n "${2:-}" ] || die "--write-config requires a path"
            WIZARD_WRITE_CONFIG="$2"
            export WIZARD_COMMON_CONSUMED=2
            return 0
            ;;
        --dry-run)
            WIZARD_DRY_RUN=1
            return 0
            ;;
        --yes|-y)
            WIZARD_YES=1
            return 0
            ;;
        --non-interactive)
            WIZARD_NON_INTERACTIVE=1
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

wizard_load_config() {
    [ -n "$WIZARD_CONFIG" ] || return 0
    [ -f "$WIZARD_CONFIG" ] || die "Wizard config not found: $WIZARD_CONFIG"
    # shellcheck source=/dev/null
    . "$WIZARD_CONFIG"
}

wizard_state_root() {
    printf '%s\n' "$WIZARD_STATE_ROOT"
}

wizard_state_family_dir() {
    local default_root="$1"
    printf '%s/%s\n' "$(wizard_state_root)" "$default_root"
}

wizard_latest_state_dir() {
    local default_root="$1"
    local root
    root="$(wizard_state_family_dir "$default_root")"
    [ -d "$root" ] || return 1
    python3 - "$root" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
runs = [path for path in root.iterdir() if path.is_dir()]
if not runs:
    raise SystemExit(1)
runs.sort(key=lambda path: (path.stat().st_mtime, path.name), reverse=True)
print(runs[0])
PY
}

wizard_list_runs() {
    local default_root="$1"
    local root
    root="$(wizard_state_family_dir "$default_root")"
    [ -d "$root" ] || return 0
    python3 - "$root" <<'PY'
from datetime import datetime, timezone
import sys
from pathlib import Path

root = Path(sys.argv[1])
runs = [path for path in root.iterdir() if path.is_dir()]
runs.sort(key=lambda path: (path.stat().st_mtime, path.name), reverse=True)
for path in runs:
    stamp = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    print(f"{stamp.strftime('%Y-%m-%dT%H:%M:%SZ')}\t{path}")
PY
}

wizard_handle_list_runs() {
    local default_root="$1"
    if [ "$WIZARD_LIST_RUNS" = "1" ]; then
        wizard_list_runs "$default_root"
        exit 0
    fi
}

wizard_load_state_answers() {
    [ -n "$WIZARD_STATE_DIR" ] || return 0
    [ -f "$WIZARD_STATE_DIR/answers.env" ] || return 0
    # shellcheck source=/dev/null
    . "$WIZARD_STATE_DIR/answers.env"
    msg "Loaded wizard answers: $WIZARD_STATE_DIR/answers.env"
}

wizard_auto_resume() {
    local default_root="$1"
    local latest
    [ "$WIZARD_RESUME" = "1" ] || return 0
    if [ -z "$WIZARD_STATE_DIR" ]; then
        latest="$(wizard_latest_state_dir "$default_root")" \
            || die "No remembered runs for $default_root; pass --state-dir or --config"
        WIZARD_STATE_DIR="$latest"
        msg "Resuming latest $default_root run: $WIZARD_STATE_DIR"
    else
        msg "Resuming $default_root run: $WIZARD_STATE_DIR"
    fi
    [ -d "$WIZARD_STATE_DIR" ] || die "Wizard state directory not found: $WIZARD_STATE_DIR"
    wizard_load_state_answers
}

wizard_require_interactive_for_sensitive_flow() {
    if [ "$WIZARD_NON_INTERACTIVE" = "1" ] && [ "$WIZARD_DRY_RUN" != "1" ]; then
        die "--non-interactive is allowed only with --dry-run for real sensitive wizard flows"
    fi
}

wizard_path_is_under() {
    python3 - "$1" "$2" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1]).expanduser().resolve(strict=False)
root = Path(sys.argv[2]).expanduser().resolve(strict=False)
print("1" if path == root or root in path.parents else "0")
PY
}

wizard_infer_bootstrap_root_from_script() {
    local script_dir="$1"
    local resolved prefix
    resolved="$(cd "$script_dir" && pwd -P)"
    case "$resolved" in
        */scripts/contrib/*)
            prefix="${resolved%%/scripts/contrib/*}"
            [ -n "$prefix" ] && printf '%s\n' "$prefix"
            ;;
    esac
}

wizard_require_local_script_copy() {
    local script_dir="$1"
    local script_name="$2"
    shift 2
    local bootstrap_root="${BOOTSTRAP_ROOT:-}"
    local script_abs scripts_root local_scripts_root rel_script local_script

    if [ -z "$bootstrap_root" ]; then
        bootstrap_root="$(wizard_infer_bootstrap_root_from_script "$script_dir" || true)"
    fi
    [ -n "$bootstrap_root" ] || return 0
    [ -d "$bootstrap_root/scripts" ] || return 0

    script_abs="$(cd "$script_dir" && pwd -P)/$script_name"
    scripts_root="$(cd "$bootstrap_root/scripts" && pwd -P)"
    if [ "$(wizard_path_is_under "$script_abs" "$scripts_root")" != "1" ]; then
        return 0
    fi

    local_scripts_root="${WIZARD_LOCAL_SCRIPTS_ROOT:-$HOME/qbit-release-ceremony-scripts}"
    rel_script="$(
        python3 - "$script_abs" "$scripts_root" <<'PY'
import sys
from pathlib import Path

script = Path(sys.argv[1]).resolve(strict=False)
root = Path(sys.argv[2]).resolve(strict=False)
print(script.relative_to(root))
PY
    )"
    local_script="$local_scripts_root/$rel_script"

    if [ "$WIZARD_DRY_RUN" = "1" ]; then
        msg "Dry run: would verify $bootstrap_root, install staged offline tools, and copy scripts to $local_scripts_root"
        cat <<EOF

Local wizard copy required
--------------------------
The release wizards must run from local disk, not from QBITOFFLINE.

Local scripts: $local_scripts_root

After local preparation, run this command from the offline machine:

  BOOTSTRAP_ROOT=$(printf '%q' "$bootstrap_root") $(printf '%q' "$local_script")$(printf ' %q' "$@")

EOF
        exit 0
    fi

    if command -v require_mounted_dir >/dev/null 2>&1; then
        require_mounted_dir "$bootstrap_root"
    else
        [ -d "$bootstrap_root" ] || die "bootstrap root not found: $bootstrap_root"
    fi
    if command -v require_transfer_usb >/dev/null 2>&1; then
        require_transfer_usb "$bootstrap_root"
    fi
    if [ -x "$bootstrap_root/scripts/contrib/release-key-ceremony/offline-verify-bootstrap.sh" ]; then
        env BOOTSTRAP_ROOT="$bootstrap_root" \
            "$bootstrap_root/scripts/contrib/release-key-ceremony/offline-verify-bootstrap.sh"
    else
        msg "Bootstrap verification helper not found under $bootstrap_root/scripts; continuing with local copy"
    fi
    if [ "$(uname -s)" = "Darwin" ]; then
        if [ -x "$bootstrap_root/scripts/contrib/release-key-ceremony/install-offline-macos-tools.sh" ]; then
            env BOOTSTRAP_ROOT="$bootstrap_root" \
                "$bootstrap_root/scripts/contrib/release-key-ceremony/install-offline-macos-tools.sh"
        else
            msg "macOS offline tool installer not found under $bootstrap_root/scripts; continuing with local copy"
        fi
    else
        msg "Non-macOS host: skipping macOS offline tool installer"
    fi
    if command -v copy_tree >/dev/null 2>&1; then
        copy_tree "$scripts_root" "$local_scripts_root"
    else
        mkdir -p "$local_scripts_root"
        find "$local_scripts_root" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
        (cd "$scripts_root" && tar -cf - .) | (cd "$local_scripts_root" && tar -xf -)
    fi
    [ -x "$local_script" ] || chmod +x "$local_script"

    cat <<EOF

Local wizard copy prepared
--------------------------
The release wizards must run from local disk, not from QBITOFFLINE.

Local scripts: $local_scripts_root

Run this command from the offline machine:

  BOOTSTRAP_ROOT=$(printf '%q' "$bootstrap_root") $(printf '%q' "$local_script")$(printf ' %q' "$@")

EOF
    exit 0
}

wizard_prompt() {
    local name="$1"
    local prompt="$2"
    local default="${3:-}"
    local value="${!name:-}"
    if [ -n "$value" ]; then
        export "${name?}"
        return 0
    fi
    if [ "$WIZARD_NON_INTERACTIVE" = "1" ]; then
        [ -n "$default" ] || die "$name is required in non-interactive mode"
        printf -v "$name" '%s' "$default"
        export "${name?}"
        return 0
    fi
    if [ -n "$default" ]; then
        printf '%s [%s]: ' "$prompt" "$default" >/dev/tty
    else
        printf '%s: ' "$prompt" >/dev/tty
    fi
    IFS= read -r value </dev/tty || die "failed to read $name"
    if [ -z "$value" ]; then
        value="$default"
    fi
    [ -n "$value" ] || die "$name is required"
    printf -v "$name" '%s' "$value"
    export "${name?}"
}

wizard_prompt_optional() {
    local name="$1"
    local prompt="$2"
    local default="${3:-}"
    local value="${!name:-}"
    if [ -n "$value" ]; then
        export "${name?}"
        return 0
    fi
    if [ "$WIZARD_NON_INTERACTIVE" = "1" ]; then
        printf -v "$name" '%s' "$default"
        export "${name?}"
        return 0
    fi
    if [ -n "$default" ]; then
        printf '%s [%s]: ' "$prompt" "$default" >/dev/tty
    else
        printf '%s [empty]: ' "$prompt" >/dev/tty
    fi
    IFS= read -r value </dev/tty || die "failed to read $name"
    if [ -z "$value" ]; then
        value="$default"
    fi
    printf -v "$name" '%s' "$value"
    export "${name?}"
}

wizard_openpgp_fingerprint_error() {
    local original="$1"
    local value
    value="$(printf '%s' "$original" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"
    case "$value" in
        *[!0-9A-F]*) printf '%s\n' "Invalid OpenPGP fingerprint: $original"; return 0 ;;
    esac
    if [ "${#value}" -ne 40 ]; then
        printf '%s\n' "Invalid OpenPGP fingerprint length: $original"
        return 0
    fi
    return 1
}

wizard_prompt_fingerprint() {
    local name="$1"
    local prompt="$2"
    local value error
    value="${!name:-}"
    while :; do
        if [ -z "$value" ]; then
            if [ "$WIZARD_NON_INTERACTIVE" = "1" ]; then
                die "$name is required in non-interactive mode"
            fi
            printf '%s: ' "$prompt" >/dev/tty
            IFS= read -r value </dev/tty || die "failed to read $name"
            if [ -z "$value" ]; then
                echo "ERR: $name is required" >/dev/tty
                continue
            fi
        fi
        if ! error="$(wizard_openpgp_fingerprint_error "$value")"; then
            value="$(printf '%s' "$value" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"
            printf -v "$name" '%s' "$value"
            export "${name?}"
            return 0
        fi
        if [ "$WIZARD_NON_INTERACTIVE" = "1" ]; then
            die "$error"
        fi
        echo "ERR: $error" >/dev/tty
        unset "$name"
        value=""
    done
}

wizard_prompt_stable_id() {
    local name="$1"
    local prompt="$2"
    local default="$3"
    local value
    if [ -n "${!name:-}" ]; then
        export "${name?}"
        return 0
    fi
    if [ "$WIZARD_RESUME" = "1" ] && [ -n "$WIZARD_STATE_DIR" ]; then
        value="$(basename "$WIZARD_STATE_DIR")"
        [ -n "$value" ] || die "Could not derive $name from resumed state dir: $WIZARD_STATE_DIR"
        printf -v "$name" '%s' "$value"
        export "${name?}"
        msg "Using resumed $prompt: $value"
        return 0
    fi
    if [ "$WIZARD_RESUME" = "1" ] && [ -z "${!name:-}" ] && [ -z "$WIZARD_STATE_DIR" ]; then
        wizard_prompt "$name" "$prompt from the previous run"
        return 0
    fi
    wizard_prompt "$name" "$prompt" "$default"
}

wizard_choice() {
    local name="$1"
    local prompt="$2"
    local default="$3"
    local choices="$4"
    local value="${!name:-}"
    local choice
    while :; do
        if [ -z "$value" ]; then
            wizard_prompt "$name" "$prompt ($choices)" "$default"
            value="${!name:-}"
        fi
        for choice in $choices; do
            if [ "$value" = "$choice" ]; then
                export "${name?}"
                return 0
            fi
        done
        if [ "$WIZARD_NON_INTERACTIVE" = "1" ]; then
            die "$name must be one of: $choices"
        fi
        echo "Expected one of: $choices" >/dev/tty
        value=""
        unset "$name"
    done
}

wizard_confirm() {
    local prompt="$1"
    local default="${2:-no}"
    local answer
    if [ "$WIZARD_YES" = "1" ]; then
        return 0
    fi
    if [ "$WIZARD_NON_INTERACTIVE" = "1" ]; then
        die "confirmation required: $prompt"
    fi
    while :; do
        printf '%s [%s]: ' "$prompt" "$default" >/dev/tty
        IFS= read -r answer </dev/tty || die "failed to read confirmation"
        answer="${answer:-$default}"
        case "$answer" in
            y|Y|yes|YES) return 0 ;;
            n|N|no|NO) return 1 ;;
            *) echo "Answer yes or no." >/dev/tty ;;
        esac
    done
}

wizard_drain_tty() {
    [ -r /dev/tty ] || return 0
    command -v python3 >/dev/null 2>&1 || return 0
    python3 -c '
import os
import select
import sys

fd = sys.stdin.fileno()
while True:
    ready, _, _ = select.select([fd], [], [], 0)
    if not ready:
        break
    try:
        if not os.read(fd, 1024):
            break
    except OSError:
        break
' </dev/tty >/dev/null 2>&1 || true
}

wizard_sensitive_confirm() {
    local prompt="$1"
    local challenge="$2"
    local answer
    if [ "$WIZARD_DRY_RUN" = "1" ]; then
        msg "Dry run sensitive gate: $prompt"
        return 0
    fi
    if [ "$WIZARD_NON_INTERACTIVE" = "1" ]; then
        die "sensitive confirmation requires an interactive operator: $prompt"
    fi
    wizard_drain_tty
    cat >/dev/tty <<EOF

$prompt
Type exactly: $challenge
EOF
    while :; do
        printf '> ' >/dev/tty
        IFS= read -r answer </dev/tty || die "failed to read sensitive confirmation"
        [ "$answer" = "$challenge" ] && return 0
        echo "ERR: sensitive confirmation failed; expected exact challenge" >/dev/tty
    done
}

wizard_require_positive_integer() {
    local name="$1"
    local value="${!name:-}"
    case "$value" in
        ""|*[!0-9]*) die "$name must be a positive integer: ${value:-<empty>}" ;;
    esac
    [ "$value" -gt 0 ] || die "$name must be greater than zero: $value"
}

wizard_require_nonnegative_integer() {
    local name="$1"
    local value="${!name:-}"
    case "$value" in
        ""|*[!0-9]*) die "$name must be a non-negative integer: ${value:-<empty>}" ;;
    esac
}

wizard_require_existing_file() {
    local name="$1"
    local value="${!name:-}"
    [ -n "$value" ] || die "$name is required"
    [ -f "$value" ] || die "$name must point to an existing file: $value"
}

wizard_require_existing_dir() {
    local name="$1"
    local value="${!name:-}"
    [ -n "$value" ] || die "$name is required"
    [ -d "$value" ] || die "$name must point to an existing directory: $value"
}

wizard_require_writable_dir() {
    local name="$1"
    local value="${!name:-}"
    [ -n "$value" ] || die "$name is required"
    [ -d "$value" ] || die "$name must point to an existing directory: $value"
    [ -w "$value" ] || die "$name must point to a writable directory: $value"
}

wizard_paths_related() {
    python3 - "$1" "$2" <<'PY'
import sys
from pathlib import Path

a = Path(sys.argv[1]).expanduser().resolve(strict=False)
b = Path(sys.argv[2]).expanduser().resolve(strict=False)
print("1" if a == b or a in b.parents or b in a.parents else "0")
PY
}

wizard_require_distinct_paths() {
    local left right left_value right_value
    while [ "$#" -gt 0 ]; do
        left="$1"
        left_value="${!left:-}"
        shift
        for right in "$@"; do
            right_value="${!right:-}"
            [ -n "$left_value" ] || die "$left is required"
            [ -n "$right_value" ] || die "$right is required"
            if [ "$(wizard_paths_related "$left_value" "$right_value")" = "1" ]; then
                die "$left and $right must be separate paths: $left_value vs $right_value"
            fi
        done
    done
}

wizard_require_sha256_digest() {
    local name="$1"
    local value
    if [ "$#" -eq 2 ]; then
        value="$2"
    else
        value="${!name:-}"
    fi
    case "$value" in
        ""|*[!0-9a-fA-F]*) die "$name must be a 64-character SHA256 digest: ${value:-<empty>}" ;;
    esac
    if [ "${#value}" -ne 64 ]; then
        die "$name must be a 64-character SHA256 digest: $value"
    fi
}

wizard_openpgp_card_status() {
    if [ -n "${WIZARD_CARD_STATUS_FILE:-}" ]; then
        cat "$WIZARD_CARD_STATUS_FILE"
        return 0
    fi
    "${GPG:-gpg}" --card-status
}

wizard_card_serial() {
    wizard_openpgp_card_status 2>/dev/null \
        | awk -F: '
            /^Serial number/ {
                serial=$2
                gsub(/[^0-9A-Za-z]/, "", serial)
                if (serial != "") print serial
                exit
            }
        '
}

wizard_card_fingerprints() {
    wizard_openpgp_card_status 2>/dev/null \
        | awk -F: '
            /^(Signature key|Encryption key|Authentication key)/ {
                key=$2
                gsub(/[^0-9A-Fa-f]/, "", key)
                if (key != "") print toupper(key)
            }
        '
}

wizard_card_has_fingerprint() {
    local expected="$1"
    expected="$(printf '%s' "$expected" | tr '[:lower:]' '[:upper:]')"
    wizard_card_fingerprints \
        | awk -v expected="$expected" '
            $0 == expected { found=1 }
            END { exit found ? 0 : 1 }
        '
}

wizard_card_key_attributes() {
    wizard_openpgp_card_status 2>/dev/null \
        | awk -F: '
            /^Key attributes/ {
                attrs=$2
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", attrs)
                print attrs
                exit
            }
        '
}

wizard_card_slot_attribute() {
    local slot="$1"
    local attrs attr1 attr2 attr3
    attrs="$(wizard_card_key_attributes)"
    read -r attr1 attr2 attr3 <<EOF
$attrs
EOF
    case "$slot" in
        1) printf '%s\n' "$attr1" ;;
        2) printf '%s\n' "$attr2" ;;
        3) printf '%s\n' "$attr3" ;;
        *) die "OpenPGP slot must be 1, 2, or 3: $slot" ;;
    esac
}

wizard_normalize_card_algorithm() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d ' _-'
}

wizard_key_attr_admin_command() {
    local slot="$1"
    local expected
    expected="$(wizard_normalize_card_algorithm "$2")"
    case "$expected" in
        ed25519) printf 'gpg-connect-agent "SCD SETATTR KEY-ATTR --force %s 22 ed25519" /bye\n' "$slot" ;;
        cv25519|x25519) printf 'gpg-connect-agent "SCD SETATTR KEY-ATTR --force %s 18 cv25519" /bye\n' "$slot" ;;
        rsa|rsa2048|rsa3072|rsa4096) printf 'gpg-connect-agent "SCD SETATTR KEY-ATTR --force %s 1 %s" /bye\n' "$slot" "$expected" ;;
        *) die "Unsupported OpenPGP card algorithm: $expected" ;;
    esac
}

wizard_card_algorithm_matches() {
    local actual expected
    actual="$(wizard_normalize_card_algorithm "$1")"
    expected="$(wizard_normalize_card_algorithm "$2")"
    case "$expected" in
        rsa) [ "${actual#rsa}" != "$actual" ] ;;
        cv25519) [ "$actual" = "cv25519" ] || [ "$actual" = "x25519" ] ;;
        *) [ "$actual" = "$expected" ] ;;
    esac
}

wizard_require_card_slot_algorithm() {
    local slot="$1"
    local expected="$2"
    local label="$3"
    local actual command
    [ -n "$expected" ] || return 0
    if [ "$WIZARD_DRY_RUN" = "1" ]; then
        msg "Dry run: skipping $label OpenPGP slot $slot algorithm check ($expected)"
        return 0
    fi
    need_cmd "${GPG:-gpg}" gpg-connect-agent
    actual="$(wizard_card_slot_attribute "$slot")"
    [ -n "$actual" ] || die "Could not read OpenPGP card key attributes for $label"
    if wizard_card_algorithm_matches "$actual" "$expected"; then
        msg "Verified $label OpenPGP slot $slot algorithm: $actual"
        return 0
    fi
    command="$(wizard_key_attr_admin_command "$slot" "$expected")"
    {
        echo "ERR: $label OpenPGP slot $slot algorithm mismatch: expected $expected, found $actual"
        echo "ERR: Insert the intended YubiKey, run this admin command, then retry provisioning:"
        echo "ERR:   $command"
    } >&2
    die "$label OpenPGP slot $slot is not configured for $expected"
}

wizard_require_card_fingerprint() {
    local expected="$1"
    local label="$2"
    [ -n "$expected" ] || return 0
    if [ "$WIZARD_DRY_RUN" = "1" ]; then
        msg "Dry run: skipping $label card fingerprint check"
        return 0
    fi
    case "$expected" in
        *[!0-9A-Fa-f]*|"") return 0 ;;
    esac
    [ "${#expected}" -eq 40 ] || return 0
    if ! wizard_card_has_fingerprint "$expected"; then
        die "Inserted YubiKey does not expose expected $label fingerprint: $expected"
    fi
    msg "Verified $label card fingerprint: $expected"
}

wizard_final_summary() {
    local title="$1"
    shift
    cat <<EOF

$title
$(printf '%s' "$title" | sed 's/./-/g')
EOF
    local line
    for line in "$@"; do
        printf '%s\n' "$line"
    done
}

wizard_setup_state_dir() {
    local default_root="$1"
    local id="$2"
    if [ -z "$WIZARD_STATE_DIR" ]; then
        WIZARD_STATE_DIR="$(wizard_state_family_dir "$default_root")/$id"
    fi
    mkdir -p "$WIZARD_STATE_DIR"
    # Checkpoint state is local to this wizard; child wizards must derive their
    # own state directory unless the operator explicitly passes one to them.
    export -n WIZARD_STATE_DIR
    if [ "$WIZARD_RESUME" = "1" ]; then
        wizard_load_state_answers
    fi
}

wizard_prepare_child_state_dir() {
    local path="$1"
    [ -n "$path" ] || die "Child wizard state directory is required"
    mkdir -p "$path"
    [ -d "$path" ] || die "Could not create child wizard state directory: $path"
}

wizard_step_done() {
    local step="$1"
    [ -f "$WIZARD_STATE_DIR/$step.done" ]
}

wizard_arg_is_env_assignment() {
    local name
    case "$1" in
        *=*) ;;
        *) return 1 ;;
    esac
    name="${1%%=*}"
    case "$name" in
        ""|[0-9]*|*[!A-Za-z0-9_]*)
            return 1
            ;;
    esac
    return 0
}

wizard_run_step() {
    local step="$1"
    shift
    [ -n "$WIZARD_STATE_DIR" ] || die "WIZARD_STATE_DIR is not set"
    if [ "$#" -gt 0 ] && wizard_arg_is_env_assignment "$1"; then
        set -- env "$@"
    fi
    if [ "$WIZARD_RESUME" = "1" ] && wizard_step_done "$step"; then
        msg "Skipping completed step: $step"
        return 0
    fi
    {
        printf '$'
        printf ' %q' "$@"
        echo
    } > "$WIZARD_STATE_DIR/$step.command"
    if [ "$WIZARD_DRY_RUN" = "1" ]; then
        msg "Dry run step: $step"
        sed -n '1p' "$WIZARD_STATE_DIR/$step.command"
        return 0
    fi
    date -u +%FT%TZ > "$WIZARD_STATE_DIR/$step.started"
    msg "Running step: $step"
    "$@"
    date -u +%FT%TZ > "$WIZARD_STATE_DIR/$step.done"
}

wizard_write_config_file() {
    local output="$1"
    shift
    mkdir -p "$(dirname "$output")"
    {
        echo "# qbit release wizard config"
        echo "# Generated at $(date -u +%FT%TZ)"
        local name
        for name in "$@"; do
            if [ "${!name+x}" = "x" ]; then
                printf 'export %s=%q\n' "$name" "${!name}"
            fi
        done
    } > "$output"
}

wizard_write_config() {
    if [ -n "$WIZARD_STATE_DIR" ]; then
        wizard_write_config_file "$WIZARD_STATE_DIR/answers.env" "$@"
        msg "Remembered wizard answers: $WIZARD_STATE_DIR/answers.env"
    fi
    [ -n "$WIZARD_WRITE_CONFIG" ] || return 0
    local output="$WIZARD_WRITE_CONFIG"
    wizard_write_config_file "$output" "$@"
    msg "Wrote wizard config: $output"
}

wizard_sha256_digest() {
    local path="$1"
    sha256_one "$path" | awk '{ print $1 }'
}
