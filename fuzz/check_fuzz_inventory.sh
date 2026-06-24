#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_MANIFEST="${ROOT}/fuzz/Cargo.toml"
RUN_ALL="${ROOT}/fuzz/run_all_fuzzers.sh"
CI_WORKFLOW="${ROOT}/.github/workflows/ci.yml"

for cmd in cargo python3 sort grep diff; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "missing required command: ${cmd}" >&2
    exit 1
  fi
done

cargo_targets="$(
  cargo metadata --manifest-path "${CARGO_MANIFEST}" --format-version 1 --no-deps \
    | python3 -c '
import json
import pathlib
import sys

manifest = pathlib.Path(sys.argv[1]).resolve()
metadata = json.load(sys.stdin)
packages = [
    package
    for package in metadata["packages"]
    if pathlib.Path(package["manifest_path"]).resolve() == manifest
]
if len(packages) != 1:
    raise SystemExit(f"expected one fuzz package for {manifest}, found {len(packages)}")

targets = sorted(
    target["name"]
    for target in packages[0]["targets"]
    if "bin" in target["kind"]
)
for target in targets:
    print(target)
' "${CARGO_MANIFEST}"
)"

script_targets="$("${RUN_ALL}" --list | LC_ALL=C sort)"

if [[ -z "${cargo_targets}" ]]; then
  echo "no fuzz targets found in ${CARGO_MANIFEST}" >&2
  exit 1
fi

if [[ "${cargo_targets}" != "${script_targets}" ]]; then
  echo "fuzz target inventory drift between fuzz/Cargo.toml and fuzz/run_all_fuzzers.sh" >&2
  diff -u \
    <(printf '%s\n' "${cargo_targets}") \
    <(printf '%s\n' "${script_targets}") >&2 || true
  exit 1
fi

python3 - "${CI_WORKFLOW}" <<'PY'
import pathlib
import re
import sys

workflow = pathlib.Path(sys.argv[1])
lines = workflow.read_text(encoding="utf-8").splitlines()

job_start = next(
    (index for index, line in enumerate(lines) if re.match(r"^  fuzz-smoke:\s*$", line)),
    None,
)
if job_start is None:
    raise SystemExit("fuzz-smoke job not found in .github/workflows/ci.yml")

job_end = next(
    (
        index
        for index, line in enumerate(lines[job_start + 1 :], start=job_start + 1)
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line)
    ),
    len(lines),
)
job_lines = lines[job_start:job_end]

step_start = next(
    (
        index
        for index, line in enumerate(job_lines)
        if re.match(r"^      - name:\s*Run fuzz smoke targets\s*$", line)
    ),
    None,
)
if step_start is None:
    raise SystemExit("fuzz-smoke Run fuzz smoke targets step not found")

step_end = next(
    (
        index
        for index, line in enumerate(job_lines[step_start + 1 :], start=step_start + 1)
        if re.match(r"^      - ", line)
    ),
    len(job_lines),
)
step_lines = job_lines[step_start:step_end]

if any(re.match(r"^        if:\s*", line) for line in step_lines):
    raise SystemExit("fuzz-smoke Run fuzz smoke targets step must be unconditional")

if not any(
    re.match(r"^        run:\s*\./fuzz/run_all_fuzzers\.sh\s+-runs=1\s*$", line)
    for line in step_lines
):
    raise SystemExit(
        "fuzz-smoke Run fuzz smoke targets step must invoke "
        "./fuzz/run_all_fuzzers.sh -runs=1"
    )
PY

if grep -Eq 'cargo[[:space:]]+\+nightly[[:space:]]+fuzz[[:space:]]+run' "${CI_WORKFLOW}"; then
  echo "CI must not maintain an inline cargo fuzz target list" >&2
  exit 1
fi

target_count="$(printf '%s\n' "${cargo_targets}" | sed '/^$/d' | wc -l | tr -d ' ')"
echo "Fuzz inventory check passed (${target_count} targets)."
