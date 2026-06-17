#!/usr/bin/env bash
# Copyright (c) 2026 The qbit developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C
set -euo pipefail

usage() {
    cat <<'EOF'
usage: contrib/macdeploy/check-apple-signing-env.sh [options]

Preflight a macOS Developer ID signing host and an unpacked qbit Guix
codesigning tarball. This script does not read passphrases, sign artifacts,
notarize artifacts, or validate private key contents.

Options:
  --codesigning-dir <dir>       Unpacked qbit macOS codesigning tarball root
                               (default: current directory).
  --developer-id-key <path>     Developer ID Application key file, typically
                               a password-protected .p12 export.
  --app-store-connect-key <path>
                               App Store Connect notarization key file,
                               typically AuthKey_<KEYID>.p8.
  --team-id <team-id>           Apple Developer Team ID.
  --identity <name>             Optional Keychain identity string to look for
                               with security find-identity.
  -h, --help                    Show this help.

Examples:
  contrib/macdeploy/check-apple-signing-env.sh \
    --codesigning-dir /tmp/qbit-0.1.0-arm64-apple-darwin-codesigning \
    --developer-id-key /Volumes/Secrets/qbit-developer-id.p12 \
    --app-store-connect-key /Volumes/Secrets/AuthKey_ABC123DEFG.p8 \
    --team-id ABC123DEFG

  # From inside an unpacked codesigning tarball:
  /path/to/qbit/contrib/macdeploy/check-apple-signing-env.sh
EOF
}

codesigning_dir="."
developer_id_key=""
app_store_connect_key=""
team_id=""
identity=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --codesigning-dir)
            codesigning_dir="${2:?missing value for --codesigning-dir}"
            shift 2
            ;;
        --developer-id-key)
            developer_id_key="${2:?missing value for --developer-id-key}"
            shift 2
            ;;
        --app-store-connect-key)
            app_store_connect_key="${2:?missing value for --app-store-connect-key}"
            shift 2
            ;;
        --team-id)
            team_id="${2:?missing value for --team-id}"
            shift 2
            ;;
        --identity)
            identity="${2:?missing value for --identity}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

errors=0
warnings=0

ok() {
    printf 'ok: %s\n' "$*"
}

warn() {
    warnings=$((warnings + 1))
    printf 'warning: %s\n' "$*" >&2
}

fail() {
    errors=$((errors + 1))
    printf 'error: %s\n' "$*" >&2
}

require_command() {
    local cmd="$1"
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "found $cmd: $(command -v "$cmd")"
    else
        fail "missing required command: $cmd"
    fi
}

check_realpath_relative_to() {
    if ! command -v realpath >/dev/null 2>&1; then
        return
    fi

    if realpath --relative-to=. . >/dev/null 2>&1; then
        ok "realpath supports --relative-to"
    else
        fail "realpath does not support --relative-to; install GNU coreutils and put its realpath first in PATH"
    fi
}

check_file_arg() {
    local label="$1"
    local path="$2"

    if [[ -z "$path" ]]; then
        warn "$label not provided; required for real signing/notarization"
        return
    fi
    if [[ -f "$path" && -r "$path" ]]; then
        ok "$label exists and is readable"
    else
        fail "$label does not exist or is not readable"
    fi
}

echo "Apple signing preflight"
echo "codesigning_dir: $codesigning_dir"

if [[ "$(uname -s)" == "Darwin" ]]; then
    ok "running on macOS"
else
    warn "not running on macOS; real Developer ID signing/notarization should run on a controlled Mac"
fi

require_command signapple
require_command codesign
require_command xcrun
require_command spctl
require_command realpath
require_command tar
check_realpath_relative_to

if [[ -d "$codesigning_dir" ]]; then
    ok "codesigning directory exists"
else
    fail "codesigning directory does not exist: $codesigning_dir"
fi

unsigned_bundle="$codesigning_dir/dist/qbit-qt.app"
unsigned_binary="$unsigned_bundle/Contents/MacOS/qbit-qt"

if [[ -d "$unsigned_bundle" ]]; then
    ok "found unsigned app bundle: dist/qbit-qt.app"
else
    fail "missing unsigned app bundle: $unsigned_bundle"
fi

if [[ -f "$unsigned_binary" ]]; then
    ok "found unsigned app binary: dist/qbit-qt.app/Contents/MacOS/qbit-qt"
else
    fail "missing unsigned app binary: $unsigned_binary"
fi

first_cli_binary=""
if [[ -d "$codesigning_dir" ]]; then
    first_cli_binary="$(find "$codesigning_dir" -maxdepth 3 \( -wholename "*/bin/*" -o -wholename "*/libexec/*" \) -type f -print -quit)"
fi
if [[ -n "$first_cli_binary" ]]; then
    ok "found command-line binaries under bin/ or libexec/"
else
    warn "no command-line binaries found under bin/ or libexec/"
fi

arch=""
if command -v signapple >/dev/null 2>&1 && [[ -f "$unsigned_binary" ]]; then
    if signapple_info="$(signapple info "$unsigned_binary" 2>/dev/null)"; then
        first_line="${signapple_info%%$'\n'*}"
        arch="${first_line%% *}"
    fi

    if [[ -n "$arch" ]]; then
        ok "signapple parsed architecture: $arch"
        case "$arch" in
            x86_64|arm64)
                ok "architecture maps to expected detached-sigs host: osx/${arch}-apple-darwin"
                ;;
            *)
                warn "unexpected architecture from signapple: $arch"
                ;;
        esac
        if [[ -e "$codesigning_dir/signature-osx-${arch}.tar.gz" ]]; then
            warn "output already exists and would be overwritten by a release run: signature-osx-${arch}.tar.gz"
        fi
    else
        fail "signapple could not parse the unsigned qbit binary"
    fi
fi

check_file_arg "Developer ID key" "$developer_id_key"
check_file_arg "App Store Connect key" "$app_store_connect_key"

if [[ -z "$team_id" ]]; then
    warn "Team ID not provided; required for notarization"
elif [[ "$team_id" =~ ^[A-Z0-9]{10}$ ]]; then
    ok "Team ID format looks valid"
else
    warn "Team ID does not look like a 10-character Apple team identifier"
fi

if [[ -n "$identity" ]]; then
    if command -v security >/dev/null 2>&1; then
        if security find-identity -v -p codesigning 2>/dev/null | grep -F -- "$identity" >/dev/null; then
            ok "Keychain code-signing identity found"
        else
            fail "Keychain code-signing identity not found: $identity"
        fi
    else
        fail "security command is unavailable; cannot check Keychain identity"
    fi
fi

if command -v xcrun >/dev/null 2>&1; then
    if xcrun notarytool --version >/dev/null 2>&1; then
        ok "xcrun notarytool is available"
    else
        fail "xcrun notarytool is unavailable"
    fi
    if stapler_path="$(xcrun -f stapler 2>/dev/null)" && [[ -n "$stapler_path" ]]; then
        ok "xcrun stapler is available: $stapler_path"
    else
        fail "xcrun stapler is unavailable"
    fi
fi

echo
if [[ "$errors" -eq 0 ]]; then
    echo "Preflight completed with $warnings warning(s) and no errors."
    if [[ -n "$developer_id_key" && -n "$app_store_connect_key" && -n "$team_id" ]]; then
        echo "From the codesigning directory, the release signing command shape is:"
        echo "  ./detached-sig-create.sh <developer-id-key> <app-store-connect-key> <team-id>"
    fi
    exit 0
fi

echo "Preflight failed with $errors error(s) and $warnings warning(s)." >&2
exit 1
