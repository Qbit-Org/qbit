#!/usr/bin/env bash
#
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C
export CI_IMAGE_REGISTRY_PREFIX="${CI_IMAGE_REGISTRY_PREFIX:-docker.io/library}"
export CI_ENFORCE_INTERNAL_REGISTRY="${CI_ENFORCE_INTERNAL_REGISTRY:-0}"

ci_validate_image_registry_prefix() {
  if [[ "${CI_ENFORCE_INTERNAL_REGISTRY:-0}" != "1" ]]; then
    return 0
  fi

  local expected_prefix="${CI_IMAGE_REGISTRY_PREFIX}/"
  if [[ -z "${CI_IMAGE_NAME_TAG:-}" ]]; then
    echo "Error: CI_ENFORCE_INTERNAL_REGISTRY=1 requires CI_IMAGE_NAME_TAG to be set." >&2
    echo "Set CI_IMAGE_REGISTRY_PREFIX to your internal registry and resolve the base image via ci_set_base_image_name_tag." >&2
    return 1
  fi

  if [[ "${CI_IMAGE_NAME_TAG}" != "${expected_prefix}"* ]]; then
    echo "Error: CI_ENFORCE_INTERNAL_REGISTRY=1 requires CI_IMAGE_NAME_TAG to start with '${expected_prefix}', got '${CI_IMAGE_NAME_TAG}'." >&2
    echo "Set CI_IMAGE_REGISTRY_PREFIX to your internal registry endpoint and use ci_set_base_image_name_tag to resolve CI_IMAGE_NAME_TAG." >&2
    return 1
  fi
}

ci_set_base_image_name_tag() {
  local base_image="$1"
  case "${base_image}" in
    ubuntu:24.04|ubuntu:22.04|debian:bookworm)
      ;;
    *)
      echo "Error: Unsupported base image '${base_image}'. Supported values: ubuntu:24.04, ubuntu:22.04, debian:bookworm." >&2
      return 1
      ;;
  esac

  export CI_IMAGE_NAME_TAG="${CI_IMAGE_REGISTRY_PREFIX}/${base_image}"
  ci_validate_image_registry_prefix
}
