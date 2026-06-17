#!/usr/bin/env bash
#
# Copyright (c) 2018-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8
export CI_IMAGE_LABEL="bitcoin-ci-test"

set -o errexit -o pipefail -o xtrace

# shellcheck source=ci/test/00_setup_env_base_image.sh
source "$( dirname "${BASH_SOURCE[0]}" )/00_setup_env_base_image.sh"

CI_CONTAINER_NAME="${CI_CONTAINER_NAME:-${CONTAINER_NAME}}"
CI_ENV_FILE="${CI_ENV_FILE:-/tmp/env-${USER:-ci}-${CI_CONTAINER_NAME}}"

preflight_validate_base_image() {
  if [[ "${CI_ENFORCE_INTERNAL_REGISTRY:-0}" != "1" ]]; then
    return 0
  fi

  if ! ci_validate_image_registry_prefix; then
    echo "Error: Refusing to build CI container image outside the configured internal registry." >&2
    echo "Set CI_IMAGE_REGISTRY_PREFIX to your internal endpoint and ensure CI_IMAGE_NAME_TAG resolves through it." >&2
    return 1
  fi
}

is_transient_buildx_error() {
  local buildx_log_file="$1"

  grep -Eiq '(failed to resolve source metadata|could not fetch content descriptor|from remote: not found)' "${buildx_log_file}" ||
  grep -Eiq '(tls handshake timeout|i/o timeout|timed? out|timeout)' "${buildx_log_file}" ||
  grep -Eiq '(connection reset by peer|unexpected eof|temporary failure|temporarily unavailable|service unavailable)' "${buildx_log_file}" ||
  grep -Eq '(^|[^0-9])(502|503|504)([^0-9]|$)' "${buildx_log_file}"
}

run_buildx_with_transient_retry_filter() {
  local buildx_log_file
  local buildx_status
  buildx_log_file="$(mktemp)"

  # shellcheck disable=SC2086
  if docker buildx build \
      --file "${BASE_READ_ONLY_DIR}/ci/test_imagefile" \
      --build-arg "CI_IMAGE_NAME_TAG=${CI_IMAGE_NAME_TAG}" \
      --build-arg "FILE_ENV=${FILE_ENV}" \
      --build-arg "BASE_ROOT_DIR=${BASE_ROOT_DIR}" \
      $MAYBE_CPUSET \
      --platform="${CI_IMAGE_PLATFORM}" \
      --label="${CI_IMAGE_LABEL}" \
      --tag="${CONTAINER_NAME}" \
      $DOCKER_BUILD_CACHE_ARG \
      "${BASE_READ_ONLY_DIR}" \
      2> >(tee "${buildx_log_file}" >&2); then
    rm -f "${buildx_log_file}"
    return 0
  fi
  buildx_status=$?

  if is_transient_buildx_error "${buildx_log_file}"; then
    echo "Transient docker buildx failure detected (exit code ${buildx_status}); retrying..." >&2
    rm -f "${buildx_log_file}"
    return 1
  fi

  echo "Non-transient docker buildx failure detected (exit code ${buildx_status}); failing fast without retry." >&2
  rm -f "${buildx_log_file}"
  return 127
}

ci_ipv6_subnet_for_attempt() {
  local network_key="$1"
  local attempt="$2"
  local checksum
  local checksum_hex
  local subnet_hi
  local subnet_lo

  checksum="$(printf '%s' "${network_key}:${attempt}" | cksum | cut -d' ' -f1)"
  checksum_hex="$(printf '%08x' "${checksum}")"
  subnet_hi="${checksum_hex:0:4}"
  subnet_lo="${checksum_hex:4:4}"
  printf '1111:1111:%s:%s::/112' "${subnet_hi}" "${subnet_lo}"
}

ci_ipv4_subnet_for_attempt() {
  local network_key="$1"
  local attempt="$2"
  local checksum
  local checksum_hex
  local subnet_mid
  local subnet_lo

  checksum="$(printf '%s' "${network_key}:${attempt}" | cksum | cut -d' ' -f1)"
  checksum_hex="$(printf '%08x' "${checksum}")"
  subnet_mid=$(( 16#${checksum_hex:0:2} % 16 + 240 ))
  subnet_lo=$(( 16#${checksum_hex:2:2} ))
  printf '10.%d.%d.0/24' "${subnet_mid}" "${subnet_lo}"
}

create_ci_network() {
  local network_name="$1"
  local network_key="$2"
  local ipv4_subnet
  local ipv6_subnet
  local create_output=""
  local attempt=0
  local max_attempts=32

  while [ "${attempt}" -lt "${max_attempts}" ]; do
    ipv4_subnet="$(ci_ipv4_subnet_for_attempt "${network_key}" "${attempt}")"
    ipv6_subnet="$(ci_ipv6_subnet_for_attempt "${network_key}" "${attempt}")"
    if create_output="$(
      docker network create \
        --ipv6 \
        --subnet "${ipv4_subnet}" \
        --subnet "${ipv6_subnet}" \
        "${network_name}" \
        2>&1
    )"; then
      return 0
    fi

    if grep -q "already exists" <<< "${create_output}"; then
      echo "Reusing existing Docker network ${network_name}"
      return 0
    fi

    if grep -q "Pool overlaps with other one on this address space" <<< "${create_output}"; then
      attempt=$((attempt + 1))
      if [ "${attempt}" -lt "${max_attempts}" ]; then
        echo "Docker network subnets ${ipv4_subnet} and ${ipv6_subnet} overlap with another active network, retrying..." >&2
        continue
      fi

      echo "Error: Failed to find non-overlapping Docker subnets for ${network_name} after ${max_attempts} attempts" >&2
      echo "${create_output}" >&2
      return 1
    fi

    echo "Error: Failed to create Docker network ${network_name}" >&2
    echo "${create_output}" >&2
    return 1
  done
}

if [ -z "$DANGER_RUN_CI_ON_HOST" ]; then
  preflight_validate_base_image

  if [ -n "${RESTART_CI_DOCKER_BEFORE_RUN}" ] ; then
    echo "Restart docker before run to stop and clear all containers started with --rm"
    podman container rm --force --all  # Similar to "systemctl restart docker"

    # Still prune everything in case the filtered pruning doesn't work, or if labels were not set
    # on a previous run. Belt and suspenders approach, should be fine to remove in the future.
    # Prune images used by --external containers (e.g. build containers) when
    # using podman.
    echo "Prune all dangling images"
    podman image prune --force --external
  fi
  echo "Prune all dangling $CI_IMAGE_LABEL images"
  # When detecting podman-docker, `--external` should be added.
  # Tolerate failure when another job is already pruning on the same host.
  #
  # Run prune before the build so we never remove the image we are about to run.
  docker image prune --force --filter "label=$CI_IMAGE_LABEL" || true

  # Remove any leftover container from a previous failed/cancelled run.
  docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

  # Env vars during the build can not be changed. For example, a modified
  # $MAKEJOBS is ignored in the build process. Use --cpuset-cpus as an
  # approximation to respect $MAKEJOBS somewhat, if cpuset is available.
  MAYBE_CPUSET=""
  if [ "$HAVE_CGROUP_CPUSET" ]; then
    MAYBE_CPUSET="--cpuset-cpus=$( python3 -c "import random;P=$( nproc );M=min(P,int('$MAKEJOBS'.lstrip('-j')));print(','.join(map(str,sorted(random.sample(range(P),M)))))" )"
  fi
  echo "Creating $CI_IMAGE_NAME_TAG container to run in"

  export MAYBE_CPUSET
  export -f is_transient_buildx_error
  export -f run_buildx_with_transient_retry_filter

  # Use buildx unconditionally
  # Using buildx is required to properly load the correct driver, for use with registry caching. Neither build, nor BUILDKIT=1 currently do this properly
  echo "Running docker buildx build with transient retry handling"
  # shellcheck disable=SC2086
  PATH="${BASE_READ_ONLY_DIR}/ci/retry:${PATH}" ${CI_RETRY_EXE} bash -c run_buildx_with_transient_retry_filter

  docker volume create "${CONTAINER_NAME}_ccache" || true
  docker volume create "${CONTAINER_NAME}_depends" || true
  docker volume create "${CONTAINER_NAME}_depends_sources" || true
  docker volume create "${CONTAINER_NAME}_previous_releases" || true

  CI_CCACHE_MOUNT="type=volume,src=${CONTAINER_NAME}_ccache,dst=$CCACHE_DIR"
  CI_DEPENDS_MOUNT="type=volume,src=${CONTAINER_NAME}_depends,dst=$DEPENDS_DIR/built"
  CI_DEPENDS_SOURCES_MOUNT="type=volume,src=${CONTAINER_NAME}_depends_sources,dst=$DEPENDS_DIR/sources"
  CI_PREVIOUS_RELEASES_MOUNT="type=volume,src=${CONTAINER_NAME}_previous_releases,dst=$PREVIOUS_RELEASES_DIR"
  CI_BUILD_MOUNT=""

  if [ "$DANGER_CI_ON_HOST_FOLDERS" ]; then
    # ensure the directories exist
    mkdir -p "${CCACHE_DIR}"
    mkdir -p "${DEPENDS_DIR}/built"
    mkdir -p "${DEPENDS_DIR}/sources"
    mkdir -p "${PREVIOUS_RELEASES_DIR}"
    mkdir -p "${BASE_BUILD_DIR}"  # Unset by default, must be defined externally

    CI_CCACHE_MOUNT="type=bind,src=${CCACHE_DIR},dst=$CCACHE_DIR"
    CI_DEPENDS_MOUNT="type=bind,src=${DEPENDS_DIR}/built,dst=$DEPENDS_DIR/built"
    CI_DEPENDS_SOURCES_MOUNT="type=bind,src=${DEPENDS_DIR}/sources,dst=$DEPENDS_DIR/sources"
    CI_PREVIOUS_RELEASES_MOUNT="type=bind,src=${PREVIOUS_RELEASES_DIR},dst=$PREVIOUS_RELEASES_DIR"
    CI_BUILD_MOUNT="--mount type=bind,src=${BASE_BUILD_DIR},dst=${BASE_BUILD_DIR}"
  fi

  if [ "$DANGER_CI_ON_HOST_CCACHE_FOLDER" ]; then
    if [ ! -d "${CCACHE_DIR}" ]; then
      echo "Error: Directory '${CCACHE_DIR}' must be created in advance."
      exit 1
    fi
    CI_CCACHE_MOUNT="type=bind,src=${CCACHE_DIR},dst=${CCACHE_DIR}"
  fi

  # Keep network identity tied to the runtime container name so concurrent
  # jobs sharing the same Docker daemon do not race on one network.
  CI_NETWORK_NAME="ci-ip6net-${CI_CONTAINER_NAME}"
  create_ci_network "${CI_NETWORK_NAME}" "${CI_CONTAINER_NAME}"

  if [ -n "${RESTART_CI_DOCKER_BEFORE_RUN}" ] ; then
    echo "Restart docker before run to stop and clear all containers started with --rm"
    podman container rm --force --all  # Similar to "systemctl restart docker"

    # Still prune everything in case the filtered pruning doesn't work, or if labels were not set
    # on a previous run. Belt and suspenders approach, should be fine to remove in the future.
    # Prune images used by --external containers (e.g. build containers) when
    # using podman.
    echo "Prune all dangling images"
    podman image prune --force --external
  fi
  echo "Prune all dangling $CI_IMAGE_LABEL images"
  # When detecting podman-docker, `--external` should be added.
  # Tolerate failure when another job is already pruning on the same host.
  docker image prune --force --filter "label=$CI_IMAGE_LABEL" || true

  # Remove any leftover container from a previous failed/cancelled run.
  docker rm -f "${CI_CONTAINER_NAME}" 2>/dev/null || true
  MAYBE_DOCKER_RUN_CPUS=""
  if [ -n "${CI_DOCKER_RUN_CPUS}" ]; then
    MAYBE_DOCKER_RUN_CPUS="--cpus=${CI_DOCKER_RUN_CPUS}"
  fi
  MAYBE_DOCKER_RUN_MEMORY=""
  if [ -n "${CI_DOCKER_RUN_MEMORY}" ]; then
    MAYBE_DOCKER_RUN_MEMORY="--memory=${CI_DOCKER_RUN_MEMORY}"
  fi

  # shellcheck disable=SC2086
  CI_CONTAINER_ID=$(docker run --cap-add LINUX_IMMUTABLE $CI_CONTAINER_CAP --rm --interactive --detach --tty \
                  ${MAYBE_DOCKER_RUN_CPUS} \
                  ${MAYBE_DOCKER_RUN_MEMORY} \
                  --mount "type=bind,src=$BASE_READ_ONLY_DIR,dst=$BASE_READ_ONLY_DIR,readonly" \
                  --mount "${CI_CCACHE_MOUNT}" \
                  --mount "${CI_DEPENDS_MOUNT}" \
                  --mount "${CI_DEPENDS_SOURCES_MOUNT}" \
                  --mount "${CI_PREVIOUS_RELEASES_MOUNT}" \
                  ${CI_BUILD_MOUNT} \
                  --env-file "${CI_ENV_FILE}" \
                  --name "${CI_CONTAINER_NAME}" \
                  --network "${CI_NETWORK_NAME}" \
                  --platform="${CI_IMAGE_PLATFORM}" \
                  "$CONTAINER_NAME")
  export CI_CONTAINER_ID
  export CI_EXEC_CMD_PREFIX="docker exec ${CI_CONTAINER_ID}"
else
  echo "Running on host system without docker wrapper"
  echo "Create missing folders"
  mkdir -p "${CCACHE_DIR}"
  mkdir -p "${PREVIOUS_RELEASES_DIR}"
fi

if [ "$CI_OS_NAME" == "macos" ]; then
  IN_GETOPT_BIN="$(brew --prefix gnu-getopt)/bin/getopt"
  export IN_GETOPT_BIN
fi

CI_EXEC () {
  $CI_EXEC_CMD_PREFIX bash -c "export PATH=\"/path_with space:${BINS_SCRATCH_DIR}:${BASE_ROOT_DIR}/ci/retry:\$PATH\" && cd \"${BASE_ROOT_DIR}\" && $*"
}
export -f CI_EXEC

# Normalize all folders to BASE_ROOT_DIR
CI_EXEC rsync --recursive --perms --stats --human-readable "${BASE_READ_ONLY_DIR}/" "${BASE_ROOT_DIR}" || echo "Nothing to copy from ${BASE_READ_ONLY_DIR}/"
CI_EXEC "${BASE_ROOT_DIR}/ci/test/01_base_install.sh"

CI_EXEC mkdir -p "${BINS_SCRATCH_DIR}"

CI_EXEC "${BASE_ROOT_DIR}/ci/test/03_test_script.sh"

if [ -z "$DANGER_RUN_CI_ON_HOST" ]; then
  echo "Stop and remove CI container by ID"
  docker container kill "${CI_CONTAINER_ID}"
  docker network rm "${CI_NETWORK_NAME}" || true
fi
