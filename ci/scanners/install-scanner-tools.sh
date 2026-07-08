#!/usr/bin/env bash
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
#
# Install the external tools required by the scanner runner.

export LC_ALL=C

set -euo pipefail

TOOL_ROOT="${QBIT_SCANNER_TOOL_ROOT:-${RUNNER_TOOL_CACHE:-$HOME/.cache/qbit}/scanners}"
BIN_DIR="${QBIT_SCANNER_BIN_DIR:-$TOOL_ROOT/bin}"
CARGO_ROOT="${QBIT_SCANNER_CARGO_ROOT:-$TOOL_ROOT/cargo}"
PYTHON_VENV="${QBIT_SCANNER_PYTHON_VENV:-$TOOL_ROOT/python}"
CARGO_AUDIT_VERSION="${QBIT_SCANNER_CARGO_AUDIT_VERSION:-0.22.2}"

mkdir -p "$BIN_DIR" "$CARGO_ROOT/bin"
export PATH="$BIN_DIR:$CARGO_ROOT/bin:$PATH"

if [[ -n "${GITHUB_PATH:-}" ]]; then
    {
        echo "$BIN_DIR"
        echo "$CARGO_ROOT/bin"
    } >> "$GITHUB_PATH"
fi

log() {
    printf '==> %s\n' "$*"
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

sudo_or_root() {
    if [[ "$(id -u)" == "0" ]]; then
        env DEBIAN_FRONTEND=noninteractive "$@"
    else
        sudo env DEBIAN_FRONTEND=noninteractive "$@"
    fi
}

install_apt_packages() {
    if ! need_cmd apt-get; then
        echo "apt-get is required to install scanner host dependencies on this runner" >&2
        exit 1
    fi

    log "Installing host packages"
    sudo_or_root apt-get update
    sudo_or_root apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cargo \
        clang \
        clang-tools \
        cmake \
        curl \
        git \
        gzip \
        libboost-dev \
        libcapnp-dev \
        libevent-dev \
        libqrencode-dev \
        libsqlite3-dev \
        libzmq3-dev \
        ninja-build \
        pkgconf \
        python3 \
        python3-pip \
        python3-venv \
        systemtap-sdt-dev \
        tar \
        unzip
}

cmake_meets_minimum() {
    need_cmd cmake || return 1
    python3 - "$(cmake --version | awk 'NR == 1 { print $3 }')" <<'PY'
import re
import sys

parts = re.findall(r"\d+", sys.argv[1])
version = tuple(int(part) for part in (parts + ["0", "0", "0"])[:3])
minimum = (3, 22, 0)
raise SystemExit(0 if version >= minimum else 1)
PY
}

ensure_cmake() {
    if cmake_meets_minimum; then
        log "cmake already available at $(cmake --version | awk 'NR == 1 { print $3 }')"
        return
    fi

    log "Installing cmake >= 3.22"
    if [[ ! -x "$PYTHON_VENV/bin/python" ]]; then
        python3 -m venv "$PYTHON_VENV"
        "$PYTHON_VENV/bin/python" -m pip install --upgrade pip wheel
    fi
    "$PYTHON_VENV/bin/python" -m pip install --upgrade 'cmake>=3.22,<4'
    ln -sf "$PYTHON_VENV/bin/cmake" "$BIN_DIR/cmake"
    hash -r
    if ! cmake_meets_minimum; then
        echo "cmake >= 3.22 is still missing after installation" >&2
        exit 1
    fi
}

github_latest_asset_url() {
    local repo="$1"
    local asset_regex="$2"
    python3 - "$repo" "$asset_regex" <<'PY'
import json
import os
import re
import sys
import urllib.parse
import urllib.request

repo = sys.argv[1]
asset_regex = re.compile(sys.argv[2])
request = urllib.request.Request(
    f"https://api.github.com/repos/{repo}/releases/latest",
    headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "qbit-scanner-installer",
    },
)
token = os.environ.get("GITHUB_TOKEN")
if token:
    request.add_header("Authorization", f"Bearer {token}")
with urllib.request.urlopen(request, timeout=60) as response:
    release = json.load(response)
for asset in release.get("assets", []):
    name = str(asset.get("name", ""))
    if asset_regex.search(name):
        print(asset["browser_download_url"])
        raise SystemExit(0)
raise SystemExit(f"No release asset matching {asset_regex.pattern!r} found in {repo} {release.get('tag_name', '')}")
PY
}

github_release_asset_url() {
    local repo="$1"
    local tag="$2"
    local asset_regex="$3"
    python3 - "$repo" "$tag" "$asset_regex" <<'PY'
import json
import os
import re
import sys
import urllib.parse
import urllib.request

repo = sys.argv[1]
tag = urllib.parse.quote(sys.argv[2], safe="")
asset_regex = re.compile(sys.argv[3])
request = urllib.request.Request(
    f"https://api.github.com/repos/{repo}/releases/tags/{tag}",
    headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "qbit-scanner-installer",
    },
)
token = os.environ.get("GITHUB_TOKEN")
if token:
    request.add_header("Authorization", f"Bearer {token}")
with urllib.request.urlopen(request, timeout=60) as response:
    release = json.load(response)
for asset in release.get("assets", []):
    name = str(asset.get("name", ""))
    if asset_regex.search(name):
        print(asset["browser_download_url"])
        raise SystemExit(0)
raise SystemExit(f"No release asset matching {asset_regex.pattern!r} found in {repo} {release.get('tag_name', '')}")
PY
}

download() {
    local url="$1"
    local output="$2"
    local -a curl_args=(-fsSL --retry 5 --retry-delay 2)
    if [[ -n "${GITHUB_TOKEN:-}" && "$url" == https://github.com/* ]]; then
        curl_args+=(-H "Authorization: Bearer $GITHUB_TOKEN")
    fi
    curl "${curl_args[@]}" "$url" -o "$output"
}

install_plain_binary() {
    local name="$1"
    local repo="$2"
    local asset_regex="$3"
    if [[ -x "$BIN_DIR/$name" ]]; then
        log "$name already available in scanner tool cache"
        return
    fi

    log "Installing $name"
    local tmp
    tmp="$(mktemp -d)"
    local url
    url="$(github_latest_asset_url "$repo" "$asset_regex")"
    download "$url" "$tmp/$name"
    install -m 0755 "$tmp/$name" "$BIN_DIR/$name"
    rm -rf "$tmp"
}

install_tar_binary() {
    local name="$1"
    local repo="$2"
    local asset_regex="$3"
    if [[ -x "$BIN_DIR/$name" ]]; then
        log "$name already available in scanner tool cache"
        return
    fi

    log "Installing $name"
    local tmp
    tmp="$(mktemp -d)"
    local url
    url="$(github_latest_asset_url "$repo" "$asset_regex")"
    download "$url" "$tmp/$name.tar.gz"
    tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
    local candidate
    candidate="$(find "$tmp" -type f -name "$name" | head -n 1)"
    if [[ -z "$candidate" ]]; then
        echo "Unable to find $name in downloaded archive from $repo" >&2
        exit 1
    fi
    install -m 0755 "$candidate" "$BIN_DIR/$name"
    rm -rf "$tmp"
}

install_codeql() {
    if need_cmd codeql; then
        log "codeql already available"
        return
    fi

    log "Installing codeql"
    local tmp
    tmp="$(mktemp -d)"
    local url
    url="$(github_latest_asset_url github/codeql-action '^codeql-bundle-linux64\.tar\.gz$')"
    download "$url" "$tmp/codeql-bundle-linux64.tar.gz"
    tar -xzf "$tmp/codeql-bundle-linux64.tar.gz" -C "$tmp"
    rm -rf "$TOOL_ROOT/codeql"
    mv "$tmp/codeql" "$TOOL_ROOT/codeql"
    ln -sf "$TOOL_ROOT/codeql/codeql" "$BIN_DIR/codeql"
    rm -rf "$tmp"
}

ensure_scan_build() {
    if need_cmd scan-build; then
        log "scan-build available"
        return
    fi

    local -a candidates=()
    mapfile -t candidates < <(compgen -c scan-build- | sort -V || true)
    if [[ "${#candidates[@]}" -gt 0 ]]; then
        local candidate="${candidates[$((${#candidates[@]} - 1))]}"
        ln -sf "$(command -v "$candidate")" "$BIN_DIR/scan-build"
        log "Linked scan-build to $candidate"
        return
    fi

    echo "scan-build is still missing after installing clang-tools" >&2
    exit 1
}

install_python_tool() {
    local name="$1"

    log "Installing or upgrading $name"
    if [[ ! -x "$PYTHON_VENV/bin/python" ]]; then
        python3 -m venv "$PYTHON_VENV"
        "$PYTHON_VENV/bin/python" -m pip install --upgrade pip wheel
    fi
    "$PYTHON_VENV/bin/python" -m pip install --upgrade "$name"
    ln -sf "$PYTHON_VENV/bin/$name" "$BIN_DIR/$name"
}

cargo_audit_target() {
    case "$(uname -m)" in
        x86_64)
            printf 'x86_64-unknown-linux-musl'
            ;;
        aarch64|arm64)
            printf 'aarch64-unknown-linux-gnu'
            ;;
        armv7l)
            printf 'armv7-unknown-linux-gnueabihf'
            ;;
        *)
            echo "Unsupported cargo-audit release architecture: $(uname -m)" >&2
            exit 1
            ;;
    esac
}

install_cargo_audit() {
    local current_version=""
    if [[ -x "$BIN_DIR/cargo-audit" ]]; then
        if current_version="$("$BIN_DIR/cargo-audit" --version 2>/dev/null | awk '{print $2}')"; then
            if [[ "$current_version" == "$CARGO_AUDIT_VERSION" ]]; then
                log "cargo-audit $CARGO_AUDIT_VERSION already available"
                return
            fi
            log "Replacing cargo-audit ${current_version:-unknown} with $CARGO_AUDIT_VERSION"
        else
            log "Replacing broken cached cargo-audit with $CARGO_AUDIT_VERSION"
        fi
    else
        log "Installing cargo-audit $CARGO_AUDIT_VERSION"
    fi

    local tmp
    tmp="$(mktemp -d)"
    local target
    target="$(cargo_audit_target)"
    local url
    url="$(github_release_asset_url \
        rustsec/rustsec \
        "cargo-audit/v${CARGO_AUDIT_VERSION}" \
        "^cargo-audit-${target}-v${CARGO_AUDIT_VERSION}\\.tgz$")"
    download "$url" "$tmp/cargo-audit.tar.gz"
    tar -xzf "$tmp/cargo-audit.tar.gz" -C "$tmp"
    local candidate
    candidate="$(find "$tmp" -type f -name cargo-audit | head -n 1)"
    if [[ -z "$candidate" ]]; then
        echo "Unable to find cargo-audit in downloaded archive" >&2
        exit 1
    fi
    install -m 0755 "$candidate" "$BIN_DIR/cargo-audit"
    rm -rf "$tmp"
}

show_versions() {
    log "Scanner tool versions"
    cmake --version | head -n 1
    codeql version
    osv-scanner --version
    gitleaks version
    zizmor --version
    actionlint --version
    semgrep --version
    printf 'scan-build: %s\n' "$(command -v scan-build)"
    syft version
    grype version
    cargo audit --version
}

install_apt_packages
ensure_cmake
install_codeql
install_plain_binary osv-scanner google/osv-scanner '^osv-scanner_linux_amd64$'
install_tar_binary gitleaks gitleaks/gitleaks '^gitleaks_.*_linux_x64\.tar\.gz$'
install_python_tool zizmor
install_tar_binary actionlint rhysd/actionlint '^actionlint_.*_linux_amd64\.tar\.gz$'
install_python_tool semgrep
ensure_scan_build
install_tar_binary syft anchore/syft '^syft_.*_linux_amd64\.tar\.gz$'
install_tar_binary grype anchore/grype '^grype_.*_linux_amd64\.tar\.gz$'
install_cargo_audit
show_versions
