#!/usr/bin/env bash
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none
export NEEDRESTART_MODE=a

readonly APT_LLVM_VERSION="${APT_LLVM_VERSION:-16}"

apt_retry_opts=(
  -o Acquire::Retries=5
  -o Acquire::http::Timeout=30
  -o Acquire::https::Timeout=30
  -o Dpkg::Options::=--force-confdef
  -o Dpkg::Options::=--force-confold
)

apt_get_retry() {
  local attempt
  local delay
  for attempt in 1 2 3 4; do
    if sudo env \
      DEBIAN_FRONTEND="$DEBIAN_FRONTEND" \
      APT_LISTCHANGES_FRONTEND="$APT_LISTCHANGES_FRONTEND" \
      NEEDRESTART_MODE="$NEEDRESTART_MODE" \
      apt-get "${apt_retry_opts[@]}" "$@"; then
      return 0
    fi

    if [ "$attempt" -eq 4 ]; then
      return 1
    fi

    delay=$((attempt * 20))
    echo "apt-get $* failed; retrying in ${delay}s" >&2
    sudo apt-get clean || true
    sudo rm -rf /var/lib/apt/lists/partial /var/cache/apt/archives/partial || true
    sleep "$delay"
  done
}

apt_update() {
  apt_get_retry update --fix-missing
}

apt_install() {
  apt_get_retry install -y --no-install-recommends --fix-missing "$@"
}

curl_retry() {
  local url="$1"
  local output="${2:-}"
  local attempt
  local delay
  local args=(
    -fsSL
    --connect-timeout 20
    --retry 3
    --retry-delay 5
    "$url"
  )

  for attempt in 1 2 3 4; do
    if [ -n "$output" ]; then
      if curl "${args[@]}" -o "$output"; then
        return 0
      fi
    else
      if curl "${args[@]}"; then
        return 0
      fi
    fi

    if [ "$attempt" -eq 4 ]; then
      return 1
    fi

    delay=$((attempt * 10))
    echo "curl $url failed; retrying in ${delay}s" >&2
    sleep "$delay"
  done
}

install_llvm_apt_source() {
  local codename
  local keyring="/etc/apt/keyrings/apt.llvm.org.asc"
  local source_list

  codename="$(awk -F= '$1 == "VERSION_CODENAME" { gsub(/"/, "", $2); print $2; exit }' /etc/os-release)"
  if [ -z "$codename" ]; then
    echo "missing VERSION_CODENAME in /etc/os-release" >&2
    exit 1
  fi
  source_list="/etc/apt/sources.list.d/llvm-toolchain-${codename}-${APT_LLVM_VERSION}.list"

  sudo install -d -m 0755 /etc/apt/keyrings
  curl_retry https://apt.llvm.org/llvm-snapshot.gpg.key | sudo tee "$keyring" >/dev/null
  echo "deb [signed-by=${keyring}] http://apt.llvm.org/${codename}/ llvm-toolchain-${codename}-${APT_LLVM_VERSION} main" |
    sudo tee "$source_list" >/dev/null
}

install_boost_headers() {
  # qbit requires Boost 1.74+, but some self-hosted runner images still expose
  # Boost 1.71 system packages. Only Boost::headers is used here, so install an
  # isolated 1.74 header package for CMake to find without changing the host.
  local boost_tarball="$RUNNER_TEMP/boost_1_74_0.tar.bz2"
  local boost_root="$RUNNER_TEMP/boost_1_74_0"
  local boost_config_dir="$boost_root/lib/cmake/Boost-1.74.0"

  curl_retry https://archives.boost.io/release/1.74.0/source/boost_1_74_0.tar.bz2 "$boost_tarball"
  tar -xf "$boost_tarball" -C "$RUNNER_TEMP"
  mkdir -p "$boost_config_dir"
  cat > "$boost_config_dir/BoostConfig.cmake" <<'BOOST_CONFIG'
if(NOT TARGET Boost::headers)
  get_filename_component(_boost_root "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)
  add_library(Boost::headers INTERFACE IMPORTED)
  set_target_properties(Boost::headers PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${_boost_root}"
  )
endif()
set(Boost_VERSION 107400)
set(Boost_VERSION_STRING 1.74.0)
BOOST_CONFIG
  cat > "$boost_config_dir/BoostConfigVersion.cmake" <<'BOOST_CONFIG_VERSION'
set(PACKAGE_VERSION "1.74.0")
if(PACKAGE_FIND_VERSION VERSION_GREATER PACKAGE_VERSION)
  set(PACKAGE_VERSION_COMPATIBLE FALSE)
else()
  set(PACKAGE_VERSION_COMPATIBLE TRUE)
  if(PACKAGE_FIND_VERSION VERSION_EQUAL PACKAGE_VERSION)
    set(PACKAGE_VERSION_EXACT TRUE)
  endif()
endif()
BOOST_CONFIG_VERSION

  if [ -n "${GITHUB_ENV:-}" ]; then
    {
      echo "BOOST_ROOT=$boost_root"
      echo "Boost_DIR=$boost_config_dir"
    } >> "$GITHUB_ENV"
  fi
}

main() {
  local packages=(
    build-essential
    ccache
    clang-"$APT_LLVM_VERSION"
    cmake
    jq
    libc++-"$APT_LLVM_VERSION"-dev
    libc++abi-"$APT_LLVM_VERSION"-dev
    libboost-dev
    libevent-dev
    libsqlite3-dev
    libzmq3-dev
    ninja-build
    pkgconf
    systemtap-sdt-dev
  )

  apt_update
  apt_install ca-certificates curl
  install_llvm_apt_source
  apt_update
  apt_install "${packages[@]}"

  if [ "${INSTALL_BPFTRACE:-false}" = "true" ]; then
    apt_install bpftrace
  fi

  python3 -m pip install --user "cmake>=3.22,<4" pyzmq
  if [ -n "${GITHUB_PATH:-}" ]; then
    echo "${HOME}/.local/bin" >> "$GITHUB_PATH"
  fi

  install_boost_headers
}

main "$@"
