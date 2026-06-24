#!/usr/bin/env bash
set -euo pipefail

# Run repeated SLH benchmark passes from a clean detached worktree, so the
# benchmark harness never sees a dirty git state.
#
# Usage:
#   ./scripts/x86_bench_5x.sh [commit-ish]
#
# Env overrides:
#   RUNS=5                     # number of repetitions
#   SAMPLE_SIZE=20             # criterion sample size
#   BENCH_TARGET=sig_benchmarks
#   BENCH_FILTER=slh_dsa_sha2_128s_bounded
#   RESULT_ROOT=.context/x86-bench
#   CARGO_TARGET_DIR=target       # per-worktree target (recommended)
#   ENABLE_TEST_BENCH_ENV_KNOBS=0 # set to 1 to honor SPX_* backend env knobs

RUNS="${RUNS:-5}"
SAMPLE_SIZE="${SAMPLE_SIZE:-20}"
BENCH_TARGET="${BENCH_TARGET:-sig_benchmarks}"
BENCH_FILTER="${BENCH_FILTER:-slh_dsa_sha2_128s_bounded}"
RESULT_ROOT="${RESULT_ROOT:-.context/x86-bench}"
ENABLE_TEST_BENCH_ENV_KNOBS="${ENABLE_TEST_BENCH_ENV_KNOBS:-0}"
COMMIT="${1:-HEAD}"

ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64|i386|i686) ;;
    *)
        echo "error: x86 host required (detected '${ARCH}')" >&2
        exit 1
        ;;
esac

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "error: run this from inside the git repo" >&2
    exit 1
fi

ROOT="$(git rev-parse --show-toplevel)"
cd "${ROOT}"

if ! git rev-parse --verify --quiet "${COMMIT}^{commit}" >/dev/null; then
    echo "error: commit-ish '${COMMIT}' not found" >&2
    exit 1
fi

COMMIT_FULL="$(git rev-parse "${COMMIT}^{commit}")"
COMMIT_SHORT="$(git rev-parse --short "${COMMIT_FULL}")"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${ROOT}/${RESULT_ROOT}/${STAMP}-${COMMIT_SHORT}"
mkdir -p "${OUT_DIR}"

if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
    export CARGO_TARGET_DIR="target"
fi

capture_host_metadata() {
    {
        echo "generated_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "arch=${ARCH}"
        echo "commit=${COMMIT_FULL}"
        echo "bench_target=${BENCH_TARGET}"
        echo "bench_filter=${BENCH_FILTER}"
        echo "runs=${RUNS}"
        echo "sample_size=${SAMPLE_SIZE}"
        echo "cargo_target_dir=${CARGO_TARGET_DIR}"
        echo "test_bench_env_knobs=${ENABLE_TEST_BENCH_ENV_KNOBS}"
        echo "spx_opt_profile=${SPX_OPT_PROFILE:-unset}"
        echo "spx_disable_sha_accel=${SPX_DISABLE_SHA_ACCEL:-unset}"
        echo "spx_disable_simd=${SPX_DISABLE_SIMD:-unset}"
        echo "spx_fors_threads=${SPX_FORS_THREADS:-unset}"
        echo "spx_disable_threads=${SPX_DISABLE_THREADS:-unset}"
        echo "spx_enable_arm_sha_accel=${SPX_ENABLE_ARM_SHA_ACCEL:-unset}"
        echo "spx_sha_backend=${SPX_SHA_BACKEND:-unset}"
        echo
        echo "== uname =="
        uname -a || true
        echo
        echo "== lscpu =="
        if command -v lscpu >/dev/null 2>&1; then
            lscpu
        else
            echo "lscpu not available"
        fi
        echo
        echo "== cpu flags =="
        if command -v lscpu >/dev/null 2>&1; then
            lscpu | sed -n '/^Flags:/,$p' || true
        elif [[ -r /proc/cpuinfo ]]; then
            grep -m1 '^flags' /proc/cpuinfo || true
        else
            echo "cpu flags unavailable"
        fi
        echo
        echo "== toolchain =="
        rustc --version || true
        cargo --version || true
        cmake --version | head -n1 || true
    } > "${OUT_DIR}/host.txt"
}

summarize_runs() {
    python3 - "${OUT_DIR}" <<'PY'
import json
import pathlib
import statistics
import sys

out_dir = pathlib.Path(sys.argv[1])
rows = {"keygen": [], "sign": [], "verify": []}

for json_file in sorted(out_dir.glob("run*.json")):
    data = json.loads(json_file.read_text())
    seen = set()
    for bench in data.get("benchmarks", []):
        if bench.get("algorithm") != "bounded_slh_dsa_sha2_128s":
            continue
        op = bench.get("operation")
        if op in rows and op not in seen:
            rows[op].append(float(bench["latency_ms"]))
            seen.add(op)

def line(op: str) -> str:
    vals = rows[op]
    if not vals:
        return f"{op:7s} no data"
    med = statistics.median(vals)
    mean = statistics.fmean(vals)
    lo = min(vals)
    hi = max(vals)
    stdev = statistics.stdev(vals) if len(vals) > 1 else 0.0
    return (
        f"{op:7s} n={len(vals):2d} "
        f"median={med:9.3f} ms "
        f"mean={mean:9.3f} ms "
        f"stdev={stdev:8.3f} ms "
        f"range=[{lo:9.3f}, {hi:9.3f}] ms"
    )

summary = "\n".join(
    [
        "SLH x86 repeated benchmark summary",
        line("keygen"),
        line("sign"),
        line("verify"),
    ]
)

print(summary)
(out_dir / "summary.txt").write_text(summary + "\n")
PY
}

declare -a WORKTREES=()
cleanup() {
    local wt
    for wt in "${WORKTREES[@]}"; do
        if [[ -d "${wt}" ]]; then
            git worktree remove --force "${wt}" >/dev/null 2>&1 || true
        fi
    done
}
trap cleanup EXIT

capture_host_metadata

echo "Output dir: ${OUT_DIR}"
echo "Commit: ${COMMIT_FULL}"
echo "Running ${RUNS} repetitions..."

for i in $(seq 1 "${RUNS}"); do
    wt="${ROOT}/.context/wt-x86-${COMMIT_SHORT}-run${i}-$$"
    WORKTREES+=("${wt}")

    echo "[${i}/${RUNS}] creating detached worktree"
    git worktree add --detach "${wt}" "${COMMIT_FULL}" >/dev/null

    if [[ "${ENABLE_TEST_BENCH_ENV_KNOBS}" == "1" ]]; then
        echo "[${i}/${RUNS}] cargo bench --features test-bench-env-knobs --bench ${BENCH_TARGET} ${BENCH_FILTER} -- --sample-size ${SAMPLE_SIZE}"
    else
        echo "[${i}/${RUNS}] cargo bench --bench ${BENCH_TARGET} ${BENCH_FILTER} -- --sample-size ${SAMPLE_SIZE}"
    fi
    (
        cd "${wt}"
        if [[ "${ENABLE_TEST_BENCH_ENV_KNOBS}" == "1" ]]; then
            cargo bench --features test-bench-env-knobs --bench "${BENCH_TARGET}" "${BENCH_FILTER}" -- --sample-size "${SAMPLE_SIZE}"
        else
            cargo bench --bench "${BENCH_TARGET}" "${BENCH_FILTER}" -- --sample-size "${SAMPLE_SIZE}"
        fi
        cp benches/benchmark-results.json "${OUT_DIR}/run${i}.json"
        cp benches/REPORT.md "${OUT_DIR}/run${i}.md"
    )

    echo "[${i}/${RUNS}] done"
    git worktree remove --force "${wt}" >/dev/null
done

summarize_runs

echo "Done. Artifacts:"
echo "  ${OUT_DIR}/host.txt"
echo "  ${OUT_DIR}/run*.json"
echo "  ${OUT_DIR}/run*.md"
echo "  ${OUT_DIR}/summary.txt"
