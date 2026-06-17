#!/usr/bin/env bash
# Copyright (c) 2026 The qbit developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C
set -euo pipefail

OSSLSIGNCODE="${OSSLSIGNCODE:-osslsigncode}"
JSIGN="${JSIGN:-jsign}"
AZ="${AZ:-az}"

OUT="signature-win.tar.gz"
SRCDIR="unsigned"
WORKDIR="./.tmp-qbit-azure-sign"
SIGNEDDIR="${WORKDIR}/signed"
OUTDIR="${WORKDIR}/out"
OUTSUBDIR="${OUTDIR}/win"
FILELIST="${WORKDIR}/files-to-sign.txt"
UNSIGNED_FILELIST="${WORKDIR}/unsigned-files-to-sign.txt"
DISCOVERED_FILELIST="${WORKDIR}/discovered-files-to-sign.txt"
MANIFEST_PATHLIST="${WORKDIR}/manifest-paths.txt"
MISSING_MANIFEST_FILES="${WORKDIR}/missing-from-manifest.txt"
TIMESTAMP_URL="${QBIT_AZURE_TIMESTAMP_URL:-http://timestamp.acs.microsoft.com/}"

EXPECTED_TESTNET_PROFILE="${QBIT_AZURE_TESTNET_PROFILE:-qbit-windows-testnet}"
EXPECTED_MAINNET_PROFILE="${QBIT_AZURE_MAINNET_PROFILE:-qbit-windows-mainnet}"

network=""
version=""
azure_endpoint=""
azure_account=""
azure_profile=""
manifest=""
dry_run=0
keep_workdir=0
created_workdir=0

usage() {
    cat <<EOF
usage: $0 --network <testnet|mainnet> --version <version> \\
          --azure-endpoint <endpoint> --azure-account <account> \\
          --azure-profile <profile> [options]

Create Bitcoin-compatible detached Windows Authenticode signatures using
Jsign and Azure Artifact Signing. Run this from the root of an unpacked
Windows Guix codesigning tarball containing:

  unsigned/

Required arguments:
  --network             Release line being signed: testnet or mainnet.
  --version             Release version, without the leading v.
  --azure-endpoint      Azure Artifact Signing endpoint, for example
                        https://eus.codesigning.azure.net/
  --azure-account       Azure Artifact Signing account name.
  --azure-profile       Azure certificate profile name.

Options:
  --manifest <file>     sha256sum-compatible manifest for unsigned inputs.
  --timestamp-url <url> RFC3161 timestamp URL. Defaults to:
                        ${TIMESTAMP_URL}
  --dry-run             Validate inputs and list files without Azure signing.
  --keep-workdir        Keep ${WORKDIR} for debugging.
  -h, --help            Show this help.

Profile guardrails:
  testnet expects QBIT_AZURE_TESTNET_PROFILE, default ${EXPECTED_TESTNET_PROFILE}
  mainnet expects QBIT_AZURE_MAINNET_PROFILE, default ${EXPECTED_MAINNET_PROFILE}

For mainnet, this script also requires an interactive literal confirmation.
EOF
}

die() {
    echo "error: $*" >&2
    exit 1
}

need_arg() {
    local name="$1"
    local value="${2:-}"
    if [ -z "$value" ]; then
        die "${name} requires a value"
    fi
}

check_tool() {
    command -v "$1" >/dev/null 2>&1 || die "required tool not found on PATH: $1"
}

sha256_check() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c "$file"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -c "$file"
    else
        die "neither sha256sum nor shasum is available for --manifest"
    fi
}

manifest_paths() {
    local file="$1"
    awk '
        NF == 0 { next }
        {
            line = $0
            if (substr(line, 1, 1) == "\\") {
                line = substr(line, 2)
            }
            path = substr(line, 66)
            sub(/^[ *]/, "", path)
            sub(/^\.\//, "", path)
            print path
        }
    ' "$file"
}

cleanup() {
    unset QBIT_AZURE_CODESIGN_TOKEN || true
    if [ "$created_workdir" -eq 1 ] && [ "$keep_workdir" -eq 0 ]; then
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT

while [ "$#" -gt 0 ]; do
    case "$1" in
        --network)
            need_arg "$1" "${2:-}"
            network="$2"
            shift 2
            ;;
        --version)
            need_arg "$1" "${2:-}"
            version="$2"
            shift 2
            ;;
        --azure-endpoint)
            need_arg "$1" "${2:-}"
            azure_endpoint="$2"
            shift 2
            ;;
        --azure-account)
            need_arg "$1" "${2:-}"
            azure_account="$2"
            shift 2
            ;;
        --azure-profile)
            need_arg "$1" "${2:-}"
            azure_profile="$2"
            shift 2
            ;;
        --manifest)
            need_arg "$1" "${2:-}"
            manifest="$2"
            shift 2
            ;;
        --timestamp-url)
            need_arg "$1" "${2:-}"
            TIMESTAMP_URL="$2"
            shift 2
            ;;
        --dry-run)
            dry_run=1
            shift
            ;;
        --keep-workdir)
            keep_workdir=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

[ -n "$network" ] || die "--network is required"
[ -n "$version" ] || die "--version is required"
[ -n "$azure_endpoint" ] || die "--azure-endpoint is required"
[ -n "$azure_account" ] || die "--azure-account is required"
[ -n "$azure_profile" ] || die "--azure-profile is required"

case "$network" in
    testnet)
        expected_profile="$EXPECTED_TESTNET_PROFILE"
        ;;
    mainnet)
        expected_profile="$EXPECTED_MAINNET_PROFILE"
        ;;
    *)
        die "--network must be testnet or mainnet"
        ;;
esac

if [ "$azure_profile" != "$expected_profile" ]; then
    cat >&2 <<EOF
error: Azure profile/network mismatch

  network:          ${network}
  supplied profile: ${azure_profile}
  expected profile: ${expected_profile}

Set QBIT_AZURE_TESTNET_PROFILE or QBIT_AZURE_MAINNET_PROFILE only if the
documented qbit Azure profile names intentionally changed.
EOF
    exit 1
fi

if [ "$network" = "mainnet" ]; then
    if [[ "$version" =~ (test|signet|regtest|dev|dirty) ]]; then
        die "refusing to use the mainnet Azure profile for non-mainnet-looking version: ${version}"
    fi
    if ! [[ "$version" =~ ^[0-9]+[.][0-9]+[.][0-9]+(-rc[0-9]+)?$ ]]; then
        die "mainnet version must look like MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-rcN"
    fi
fi

[ -d "$SRCDIR" ] || die "missing ${SRCDIR}/; run from an unpacked Windows codesigning tarball"
[ ! -e "$WORKDIR" ] || die "${WORKDIR} already exists; remove it before signing"

check_tool "$JSIGN"
check_tool "$OSSLSIGNCODE"
if [ "$dry_run" -eq 0 ] && [ -z "${QBIT_AZURE_CODESIGN_TOKEN:-}" ]; then
    check_tool "$AZ"
fi

if [ -n "$manifest" ]; then
    [ -f "$manifest" ] || die "manifest not found: ${manifest}"
    echo "Checking unsigned input manifest: ${manifest}"
    sha256_check "$manifest"
fi

mkdir -p "$SIGNEDDIR" "$OUTSUBDIR"
created_workdir=1

file_count=0
while IFS= read -r -d '' bin; do
    rel="${bin#"${SRCDIR}"/}"
    mkdir -p "${SIGNEDDIR}/$(dirname "$rel")"
    cp -p "$bin" "${SIGNEDDIR}/${rel}"
    printf '%s\n' "${SIGNEDDIR}/${rel}" >> "$FILELIST"
    printf '%s\n' "$bin" >> "$UNSIGNED_FILELIST"
    file_count=$((file_count + 1))
done < <(find "$SRCDIR" -name "*.exe" -type f -print0)

[ "$file_count" -gt 0 ] || die "no .exe files found under ${SRCDIR}/"

if [ -n "$manifest" ]; then
    sort -u "$UNSIGNED_FILELIST" > "$DISCOVERED_FILELIST"
    manifest_paths "$manifest" | sort -u > "$MANIFEST_PATHLIST"
    comm -23 "$DISCOVERED_FILELIST" "$MANIFEST_PATHLIST" > "$MISSING_MANIFEST_FILES"
    if [ -s "$MISSING_MANIFEST_FILES" ]; then
        cat >&2 <<EOF
error: unsigned executables are missing from the manifest

Every executable under ${SRCDIR}/ must be listed in --manifest before it can be
signed. Missing executable paths:
EOF
        sed 's/^/  /' "$MISSING_MANIFEST_FILES" >&2
        exit 1
    fi
fi

cat <<EOF
Windows Authenticode detached-signature plan:
  network:          ${network}
  version:          ${version}
  Azure endpoint:   ${azure_endpoint}
  Azure account:    ${azure_account}
  Azure profile:    ${azure_profile}
  timestamp URL:    ${TIMESTAMP_URL}
  executable count: ${file_count}
  output:           ${OUT}
EOF

if [ "$dry_run" -eq 1 ]; then
    echo "Dry run only; files that would be signed:"
    sed 's/^/  /' "$FILELIST"
    exit 0
fi

if [ "$network" = "mainnet" ]; then
    if [ ! -t 0 ]; then
        die "mainnet signing requires an interactive terminal confirmation"
    fi
    expected_confirmation="SIGN MAINNET ${version}"
    printf "Type '%s' to continue: " "$expected_confirmation"
    IFS= read -r confirmation
    [ "$confirmation" = "$expected_confirmation" ] || die "mainnet confirmation did not match"
fi

if [ -z "${QBIT_AZURE_CODESIGN_TOKEN:-}" ]; then
    echo "Requesting Azure Artifact Signing access token..."
    QBIT_AZURE_CODESIGN_TOKEN="$("$AZ" account get-access-token \
        --resource https://codesigning.azure.net \
        --query accessToken \
        -o tsv)"
    export QBIT_AZURE_CODESIGN_TOKEN
fi

echo "Signing copied executables with Jsign and Azure Artifact Signing..."
"$JSIGN" \
    --storetype TRUSTEDSIGNING \
    --keystore "$azure_endpoint" \
    --storepass env:QBIT_AZURE_CODESIGN_TOKEN \
    --alias "${azure_account}/${azure_profile}" \
    --alg SHA-256 \
    --tsaurl "$TIMESTAMP_URL" \
    --tsmode RFC3161 \
    --replace \
    @"$FILELIST"

echo "Extracting Authenticode signatures..."
while IFS= read -r signed_bin; do
    rel="${signed_bin#"${SIGNEDDIR}"/}"
    mkdir -p "${OUTSUBDIR}/$(dirname "$rel")"
    "$OSSLSIGNCODE" extract-signature \
        -pem \
        -in "$signed_bin" \
        -out "${OUTSUBDIR}/${rel}.pem"
    rm -f "$signed_bin"
done < "$FILELIST"

rm -f "$OUT"
tar -C "$OUTDIR" -czf "$OUT" .
echo "Created ${OUT}"
