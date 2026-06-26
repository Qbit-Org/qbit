#!/usr/bin/env bash
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

export LC_ALL=C
set -euo pipefail

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "${value}"
}

toml_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "${value}"
}

toml_array_from_csv() {
  local csv="$1"
  local raw_value
  local remaining="${csv},"
  local value
  local separator=""

  printf '['
  while [[ -n "${remaining}" ]]; do
    raw_value="${remaining%%,*}"
    remaining="${remaining#*,}"
    value="$(trim "${raw_value}")"
    if [[ -n "${value}" ]]; then
      printf '%s"%s"' "${separator}" "$(toml_escape "${value}")"
      separator=", "
    fi
  done
  printf ']'
}

if [[ -z "${RUNNER_TEMP:-}" ]]; then
  echo "::error::RUNNER_TEMP is required to write buildkitd.toml."
  exit 1
fi

if [[ -z "${GITHUB_ENV:-}" ]]; then
  echo "::error::GITHUB_ENV is required to export BUILDKIT_CONFIG."
  exit 1
fi

BUILDKIT_CONFIG="${RUNNER_TEMP}/buildkitd.toml"
: > "${BUILDKIT_CONFIG}"

if [[ "${CI_ENFORCE_INTERNAL_REGISTRY:-}" == "1" ]] && [[ -n "${CI_IMAGE_REGISTRY_PREFIX:-}" ]]; then
  REGISTRY_HOST="${CI_IMAGE_REGISTRY_PREFIX%%/*}"
  {
    echo "[registry]"
    echo "  [registry.\"${REGISTRY_HOST}\"]"
    echo "    http = true"
    echo "    insecure = true"
  } >> "${BUILDKIT_CONFIG}"
  echo "Configured BuildKit to allow plain HTTP for registry host '${REGISTRY_HOST}'."
fi

dns_nameservers="$(toml_array_from_csv "${BUILDKIT_DNS_NAMESERVERS:-${CI_BUILDKIT_DNS_NAMESERVERS:-}}")"
dns_search_domains="$(toml_array_from_csv "${BUILDKIT_DNS_SEARCH_DOMAINS:-${CI_BUILDKIT_DNS_SEARCH_DOMAINS:-}}")"

if [[ "${dns_nameservers}" != "[]" || "${dns_search_domains}" != "[]" ]]; then
  needs_blank_line="0"
  if [[ -s "${BUILDKIT_CONFIG}" ]]; then
    needs_blank_line="1"
  fi
  {
    if [[ "${needs_blank_line}" == "1" ]]; then
      echo
    fi
    echo "[dns]"
    if [[ "${dns_nameservers}" != "[]" ]]; then
      echo "  nameservers = ${dns_nameservers}"
    fi
    if [[ "${dns_search_domains}" != "[]" ]]; then
      echo "  searchDomains = ${dns_search_domains}"
    fi
  } >> "${BUILDKIT_CONFIG}"
  echo "Configured BuildKit DNS settings."
fi

echo "BUILDKIT_CONFIG=${BUILDKIT_CONFIG}" >> "${GITHUB_ENV}"
