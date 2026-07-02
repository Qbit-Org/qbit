#!/usr/bin/env bash
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

export LC_ALL=C
set -uo pipefail

usage() {
    cat <<'EOF'
Usage: collect-tsan-evidence.sh --output-dir DIR [options]

Build and run the qbit-owned libbitcoinpqc concurrency harness.

Options:
  --source-dir DIR              qbit source checkout (default: current directory)
  --build-dir DIR               CMake build directory (default: OUT/build)
  --upstream-repo OWNER/REPO    libbitcoinpqc upstream repo metadata
  --upstream-ref REF            libbitcoinpqc upstream ref metadata
  --subtree-source-ref REF      libbitcoinpqc source tag metadata (default: --upstream-ref)
  --expected-subtree-tree SHA   fail if HEAD:src/libbitcoinpqc tree differs
  --threads N                  worker thread count (default: 8)
  --iterations N               per-thread iterations when duration is 0 (default: 2)
  --duration-seconds N         wall-clock run duration, overrides iterations (default: 0)
  --sanitizer thread|none      build sanitizer mode (default: thread)
EOF
}

source_dir="."
output_dir=""
build_dir=""
upstream_repo=""
upstream_ref=""
subtree_source_ref=""
expected_subtree_tree=""
threads="8"
iterations="2"
duration_seconds="0"
sanitizer="thread"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source-dir) source_dir="$2"; shift 2 ;;
        --output-dir) output_dir="$2"; shift 2 ;;
        --build-dir) build_dir="$2"; shift 2 ;;
        --upstream-repo) upstream_repo="$2"; shift 2 ;;
        --upstream-ref) upstream_ref="$2"; shift 2 ;;
        --subtree-source-ref) subtree_source_ref="$2"; shift 2 ;;
        --expected-subtree-tree) expected_subtree_tree="$2"; shift 2 ;;
        --threads) threads="$2"; shift 2 ;;
        --iterations) iterations="$2"; shift 2 ;;
        --duration-seconds) duration_seconds="$2"; shift 2 ;;
        --sanitizer) sanitizer="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$output_dir" || -z "$upstream_repo" || -z "$upstream_ref" ]]; then
    usage >&2
    exit 2
fi
if [[ -z "$subtree_source_ref" ]]; then
    subtree_source_ref="$upstream_ref"
fi

for numeric in threads iterations duration_seconds; do
    value="${!numeric}"
    if ! [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "--${numeric//_/-} must be a non-negative integer" >&2
        exit 2
    fi
done

if [[ "$threads" -lt 1 || "$threads" -gt 256 ]]; then
    echo "--threads must be between 1 and 256" >&2
    exit 2
fi

case "$sanitizer" in
    thread|none) ;;
    *) echo "--sanitizer must be 'thread' or 'none'" >&2; exit 2 ;;
esac

source_dir="$(cd "$source_dir" && pwd)"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
if [[ -z "$build_dir" ]]; then
    build_dir="$output_dir/build"
fi
mkdir -p "$build_dir"
build_dir="$(cd "$build_dir" && pwd)"

log_dir="$output_dir/logs"
meta_dir="$output_dir/metadata"
cmake_project_dir="$output_dir/cmake-project"
mkdir -p "$log_dir" "$meta_dir" "$cmake_project_dir"

failures_file="$output_dir/failures.txt"
: > "$failures_file"

overall_status=0
subtree_check_status="not_run"
configure_status="not_run"
build_status="not_run"
tsan_smoke_status="not_run"
harness_status="not_run"
upstream_ref_status="not_run"
actual_subtree_tree=""

record_failure() {
    printf '%s\n' "$1" >> "$failures_file"
    overall_status=1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/libbitcoinpqc/evidence-helpers.sh
source "$SCRIPT_DIR/evidence-helpers.sh"

do_validate_upstream_ref() {
    if validate_upstream_ref "$upstream_repo" "$upstream_ref" "$output_dir" "$log_dir" "$meta_dir"; then
        upstream_ref_status="passed"
    else
        upstream_ref_status="failed"
        record_failure "failed to resolve upstream ref $upstream_repo@$upstream_ref"
    fi
}

qbit_commit="$(git -C "$source_dir" rev-parse HEAD 2>/dev/null || true)"
run_url=""
if [[ -n "${GITHUB_SERVER_URL:-}" && -n "${GITHUB_REPOSITORY:-}" && -n "${GITHUB_RUN_ID:-}" ]]; then
    run_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
fi

{
    echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "qbit_commit=$qbit_commit"
    echo "source_dir=$source_dir"
    echo "upstream_repo=$upstream_repo"
    echo "upstream_ref=$upstream_ref"
    echo "subtree_source_ref=$subtree_source_ref"
    echo "expected_subtree_tree=$expected_subtree_tree"
    echo "github_run_url=$run_url"
    echo "github_ref=${GITHUB_REF:-}"
    echo "github_ref_name=${GITHUB_REF_NAME:-}"
    echo "github_sha=${GITHUB_SHA:-}"
    echo "runner_name=${RUNNER_NAME:-}"
    echo "runner_os=${RUNNER_OS:-}"
    echo "runner_arch=${RUNNER_ARCH:-}"
    echo "image_os=${ImageOS:-}"
    echo "image_version=${ImageVersion:-}"
    echo "threads=$threads"
    echo "iterations=$iterations"
    echo "duration_seconds=$duration_seconds"
    echo "sanitizer=$sanitizer"
} > "$meta_dir/run.env"

{
    uname -a || true
    echo
    if [[ -r /etc/os-release ]]; then
        cat /etc/os-release
    elif command -v sw_vers >/dev/null 2>&1; then
        sw_vers
    fi
    echo
    if command -v lscpu >/dev/null 2>&1; then
        lscpu || true
    fi
    echo
    cc --version || true
    echo
    cmake --version || true
} > "$meta_dir/host.txt" 2>&1

do_validate_upstream_ref

if actual_subtree_tree="$(git -C "$source_dir" rev-parse HEAD:src/libbitcoinpqc 2>"$log_dir/subtree-tree.log")"; then
    printf '%s\n' "$actual_subtree_tree" > "$meta_dir/subtree-tree.txt"
    if [[ -n "$expected_subtree_tree" && "$actual_subtree_tree" != "$expected_subtree_tree" ]]; then
        subtree_check_status="failed"
        record_failure "src/libbitcoinpqc tree mismatch: expected $expected_subtree_tree, got $actual_subtree_tree"
    else
        subtree_check_status="passed"
    fi
else
    subtree_check_status="failed"
    record_failure "failed to resolve HEAD:src/libbitcoinpqc tree"
fi

if [[ "$sanitizer" == "thread" ]]; then
    tsan_smoke_source="$output_dir/tsan-smoke.c"
    tsan_smoke_binary="$output_dir/tsan-smoke"
    cat > "$tsan_smoke_source" <<'EOF'
int main(void) { return 0; }
EOF
    if cc -fsanitize=thread "$tsan_smoke_source" -o "$tsan_smoke_binary" > "$log_dir/tsan-smoke.log" 2>&1 &&
       "$tsan_smoke_binary" >> "$log_dir/tsan-smoke.log" 2>&1; then
        tsan_smoke_status="passed"
    else
        tsan_smoke_status="failed"
        record_failure "TSAN compile/runtime smoke failed"
    fi
else
    tsan_smoke_status="skipped"
fi

cat > "$cmake_project_dir/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.16)
project(libbitcoinpqc_tsan_evidence C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

if(TSAN_EVIDENCE_SANITIZER STREQUAL "thread")
  add_compile_options(-fsanitize=thread -g -O1 -fno-omit-frame-pointer)
  add_link_options(-fsanitize=thread)
elseif(TSAN_EVIDENCE_SANITIZER STREQUAL "none")
else()
  message(FATAL_ERROR "Unsupported TSAN_EVIDENCE_SANITIZER=${TSAN_EVIDENCE_SANITIZER}")
endif()

add_subdirectory("${QBIT_SOURCE_DIR}/src/libbitcoinpqc" "${CMAKE_BINARY_DIR}/libbitcoinpqc-build")

add_executable(libbitcoinpqc_tsan_concurrency
  "${QBIT_SOURCE_DIR}/ci/libbitcoinpqc/tsan-concurrency-harness.c"
)
target_link_libraries(libbitcoinpqc_tsan_concurrency PRIVATE bitcoinpqc)
EOF

if cmake -S "$cmake_project_dir" -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DQBIT_SOURCE_DIR="$source_dir" \
    -DTSAN_EVIDENCE_SANITIZER="$sanitizer" \
    > "$log_dir/cmake-configure.log" 2>&1; then
    configure_status="passed"
else
    configure_status="failed"
    record_failure "CMake configure failed"
fi

if [[ "$configure_status" == "passed" ]]; then
    build_jobs="${MAKEJOBS:-}"
    if [[ -z "$build_jobs" ]]; then
        if command -v nproc >/dev/null 2>&1; then
            build_jobs="-j$(nproc)"
        elif command -v sysctl >/dev/null 2>&1; then
            build_jobs="-j$(sysctl -n hw.ncpu)"
        else
            build_jobs="-j2"
        fi
    fi
    if cmake --build "$build_dir" --target libbitcoinpqc_tsan_concurrency -- "$build_jobs" \
        > "$log_dir/cmake-build.log" 2>&1; then
        build_status="passed"
    else
        build_status="failed"
        record_failure "CMake build failed"
    fi
else
    build_status="skipped"
fi

if [[ "$build_status" == "passed" ]]; then
    if [[ "$sanitizer" == "thread" ]]; then
        tsan_options="halt_on_error=1:second_deadlock_stack=1"
        if [[ -f "$source_dir/test/sanitizer_suppressions/tsan" ]]; then
            tsan_options="suppressions=$source_dir/test/sanitizer_suppressions/tsan:$tsan_options"
        fi
        export TSAN_OPTIONS="${TSAN_OPTIONS:-$tsan_options}"
    fi
    harness_binary="$build_dir/bin/libbitcoinpqc_tsan_concurrency"
    if "$harness_binary" \
        --threads "$threads" \
        --iterations "$iterations" \
        --seconds "$duration_seconds" \
        > "$log_dir/harness.log" 2>&1; then
        harness_status="passed"
    else
        harness_status="failed"
        record_failure "concurrency harness failed"
    fi
else
    harness_status="skipped"
fi

export SUMMARY_STATUS="passed"
if [[ "$overall_status" -ne 0 ]]; then
    SUMMARY_STATUS="failed"
fi
export QBIT_COMMIT="$qbit_commit"
export SOURCE_DIR="$source_dir"
export UPSTREAM_REPO="$upstream_repo"
export UPSTREAM_REF="$upstream_ref"
export SUBTREE_SOURCE_REF="$subtree_source_ref"
export EXPECTED_SUBTREE_TREE="$expected_subtree_tree"
export ACTUAL_SUBTREE_TREE="$actual_subtree_tree"
export GITHUB_RUN_URL="$run_url"
export THREADS="$threads"
export ITERATIONS="$iterations"
export DURATION_SECONDS="$duration_seconds"
export SANITIZER="$sanitizer"
export UPSTREAM_REF_STATUS="$upstream_ref_status"
export SUBTREE_CHECK_STATUS="$subtree_check_status"
export TSAN_SMOKE_STATUS="$tsan_smoke_status"
export CONFIGURE_STATUS="$configure_status"
export BUILD_STATUS="$build_status"
export HARNESS_STATUS="$harness_status"
export RUNNER_NAME_VALUE="${RUNNER_NAME:-}"
export RUNNER_OS_VALUE="${RUNNER_OS:-}"
export RUNNER_ARCH_VALUE="${RUNNER_ARCH:-}"
export IMAGE_OS_VALUE="${ImageOS:-}"
export IMAGE_VERSION_VALUE="${ImageVersion:-}"
export SUMMARY_JSON="$output_dir/summary.json"
export SUMMARY_MD="$output_dir/summary.md"
export FAILURES_FILE="$failures_file"

python3 <<'PY'
import json
import os
from pathlib import Path

failures = [
    line.strip()
    for line in Path(os.environ["FAILURES_FILE"]).read_text(encoding="utf-8").splitlines()
    if line.strip()
]

summary = {
    "schema_version": 1,
    "status": os.environ["SUMMARY_STATUS"],
    "qbit_commit": os.environ["QBIT_COMMIT"],
    "upstream_repo": os.environ["UPSTREAM_REPO"],
    "upstream_ref": os.environ["UPSTREAM_REF"],
    "subtree_source_ref": os.environ["SUBTREE_SOURCE_REF"],
    "expected_subtree_tree": os.environ["EXPECTED_SUBTREE_TREE"],
    "actual_subtree_tree": os.environ["ACTUAL_SUBTREE_TREE"],
    "github_run_url": os.environ["GITHUB_RUN_URL"],
    "runner": {
        "name": os.environ["RUNNER_NAME_VALUE"],
        "os": os.environ["RUNNER_OS_VALUE"],
        "arch": os.environ["RUNNER_ARCH_VALUE"],
        "image_os": os.environ["IMAGE_OS_VALUE"],
        "image_version": os.environ["IMAGE_VERSION_VALUE"],
    },
    "harness": {
        "threads": int(os.environ["THREADS"]),
        "iterations": int(os.environ["ITERATIONS"]),
        "duration_seconds": int(os.environ["DURATION_SECONDS"]),
        "sanitizer": os.environ["SANITIZER"],
    },
    "checks": {
        "upstream_ref": os.environ["UPSTREAM_REF_STATUS"],
        "subtree_tree": os.environ["SUBTREE_CHECK_STATUS"],
        "tsan_smoke": os.environ["TSAN_SMOKE_STATUS"],
        "cmake_configure": os.environ["CONFIGURE_STATUS"],
        "cmake_build": os.environ["BUILD_STATUS"],
        "concurrency_harness": os.environ["HARNESS_STATUS"],
    },
    "failures": failures,
}

Path(os.environ["SUMMARY_JSON"]).write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

lines = [
    "# libbitcoinpqc TSAN Concurrency Evidence",
    "",
    f"- Status: `{summary['status']}`",
    f"- qbit commit: `{summary['qbit_commit']}`",
    f"- upstream: `{summary['upstream_repo']}` @ `{summary['upstream_ref']}`",
    f"- subtree source ref: `{summary['subtree_source_ref']}`",
    f"- expected subtree tree: `{summary['expected_subtree_tree']}`",
    f"- actual subtree tree: `{summary['actual_subtree_tree']}`",
    f"- GitHub run: {summary['github_run_url'] or '(not running in GitHub Actions)'}",
    f"- runner: `{summary['runner']['os']}` / `{summary['runner']['arch']}` / `{summary['runner']['image_os']} {summary['runner']['image_version']}`",
    f"- sanitizer: `{summary['harness']['sanitizer']}`",
    f"- threads: `{summary['harness']['threads']}`",
    f"- iterations: `{summary['harness']['iterations']}`",
    f"- duration seconds: `{summary['harness']['duration_seconds']}`",
    f"- upstream ref check: `{summary['checks']['upstream_ref']}`",
    f"- TSAN smoke: `{summary['checks']['tsan_smoke']}`",
    f"- CMake configure: `{summary['checks']['cmake_configure']}`",
    f"- CMake build: `{summary['checks']['cmake_build']}`",
    f"- concurrency harness: `{summary['checks']['concurrency_harness']}`",
]
if failures:
    lines.extend(["", "## Failures"])
    lines.extend(f"- {failure}" for failure in failures)
lines.append("")
Path(os.environ["SUMMARY_MD"]).write_text("\n".join(lines), encoding="utf-8")
PY

exit "$overall_status"
