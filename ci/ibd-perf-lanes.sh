# shellcheck shell=bash
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
#
# Lane command builders for .github/workflows/ibd-perf-manual.yml.
#
# This file is sourced, never executed: the workflow step sets its own
# `set -euo pipefail`, and every function below relies on the caller's shell
# options so a failing harness invocation aborts the step with the harness's
# own exit status.
#
# Required environment (all provided by the workflow job env):
#   PERF_BUILD_DIR PERF_ARTIFACT_ROOT
#   BLOCKS TAIL_BLOCKS TXS_PER_BLOCK P2MR_SPENDS_PER_BLOCK TRACE_THRESHOLD_MS
#   FASTPRUNE ENABLE_TRACING ENABLE_REPLAY_LANES ENABLE_NETWORK_IBD RUNS_PER_LANE
#   REPLAY_TIMEOUT NETWORK_HEADERS_TIMEOUT NETWORK_TIP_TIMEOUT NETWORK_IBD_EXIT_TIMEOUT
#
# Timeout handling: a blank timeout variable omits the flag so the harness
# default applies; any nonempty value is forwarded verbatim as one
# `--flag=value` token. No numeric rule lives here. The harness argparse
# (`type=int`) rejects malformed or empty values with exit 2 and
# `validate_options` rejects values below 1 with exit 1.
#
# Every builder fills the global array IBD_PERF_CMD (bash 3.2 has no namerefs).

export LC_ALL=C

build_replay_cmd() {
  local workload="$1"
  local history_mode="$2"
  local reindex_mode="$3"
  local history_tail="$4"
  local report_file="$5"
  local trace_file="$6"

  IBD_PERF_CMD=(
    python3 test/functional/feature_ibd_perf_replay.py
    --configfile="$PERF_BUILD_DIR/test/config.ini"
    --blocks="$BLOCKS"
    --workload="$workload"
    --txs-per-block="$TXS_PER_BLOCK"
    --p2mr-spends-per-block="$P2MR_SPENDS_PER_BLOCK"
    --tail-blocks="$history_tail"
    --history-mode="$history_mode"
    --reindex-mode="$reindex_mode"
    --report-file="$report_file"
    --connectblock-threshold-ms="$TRACE_THRESHOLD_MS"
  )
  if [ -n "$trace_file" ]; then
    IBD_PERF_CMD+=(--connectblock-trace-file="$trace_file")
  fi
  if [ "$FASTPRUNE" = "true" ]; then
    IBD_PERF_CMD+=(--fastprune)
  fi
  if [ -n "$REPLAY_TIMEOUT" ]; then
    IBD_PERF_CMD+=(--replay-timeout="$REPLAY_TIMEOUT")
  fi
}

build_network_cmd() {
  local workload="$1"
  local report_file="$2"
  local trace_file="$3"

  IBD_PERF_CMD=(
    python3 test/functional/feature_ibd_perf_network.py
    --configfile="$PERF_BUILD_DIR/test/config.ini"
    --blocks="$BLOCKS"
    --workload="$workload"
    --txs-per-block="$TXS_PER_BLOCK"
    --p2mr-spends-per-block="$P2MR_SPENDS_PER_BLOCK"
    --lane-name="w3-network-mixed"
    --report-file="$report_file"
    --connectblock-threshold-ms="$TRACE_THRESHOLD_MS"
  )
  if [ -n "$trace_file" ]; then
    IBD_PERF_CMD+=(--connectblock-trace-file="$trace_file")
  fi
  if [ "$FASTPRUNE" = "true" ]; then
    IBD_PERF_CMD+=(--fastprune)
  fi
  if [ -n "$NETWORK_HEADERS_TIMEOUT" ]; then
    IBD_PERF_CMD+=(--network-headers-timeout="$NETWORK_HEADERS_TIMEOUT")
  fi
  if [ -n "$NETWORK_TIP_TIMEOUT" ]; then
    IBD_PERF_CMD+=(--network-tip-timeout="$NETWORK_TIP_TIMEOUT")
  fi
  if [ -n "$NETWORK_IBD_EXIT_TIMEOUT" ]; then
    IBD_PERF_CMD+=(--network-ibd-exit-timeout="$NETWORK_IBD_EXIT_TIMEOUT")
  fi
}

# True when the lane loop in run_ibd_lanes iterates at least once. The
# campaign's own `seq` decides, so no separate numeric rule is introduced
# here: a resolved runs-per-lane that yields no iteration builds no command.
ibd_perf_lane_runs() {
  [ -n "$(seq 1 "$RUNS_PER_LANE" 2>/dev/null)" ]
}

# Each lane records itself here immediately before its first command runs, so
# the evidence below can tell a lane that was invoked from one the campaign
# never reached (a failed build, a rejected preflight, an earlier lane failing).
ibd_perf_lane_invocations() {
  echo "$PERF_ARTIFACT_ROOT/summary/lane-invocations.txt"
}

ibd_perf_record_lane_invocation() {
  mkdir -p "$PERF_ARTIFACT_ROOT/summary"
  echo "$1" >> "$(ibd_perf_lane_invocations)"
}

ibd_perf_lane_invoked() {
  grep -qx -- "$1" "$(ibd_perf_lane_invocations)" 2>/dev/null
}

# Writes the requested timeout strings plus an explicit forwarded marker to
# stdout (the workflow appends this to summary/host.env after the lanes step,
# whatever its outcome). The marker mirrors what actually happened: a blank
# value is never forwarded, a value for a disabled lane is never reached by any
# command, neither is a value for a lane that never iterates, and a lane the
# campaign never reached forwarded nothing. Effective values are only ever
# written by the harness reports.
write_ibd_timeout_evidence() {
  ibd_timeout_evidence_lines replay_timeout "$REPLAY_TIMEOUT" "$ENABLE_REPLAY_LANES" replay
  ibd_timeout_evidence_lines network_headers_timeout "$NETWORK_HEADERS_TIMEOUT" "$ENABLE_NETWORK_IBD" network
  ibd_timeout_evidence_lines network_tip_timeout "$NETWORK_TIP_TIMEOUT" "$ENABLE_NETWORK_IBD" network
  ibd_timeout_evidence_lines network_ibd_exit_timeout "$NETWORK_IBD_EXIT_TIMEOUT" "$ENABLE_NETWORK_IBD" network
}

ibd_timeout_evidence_lines() {
  local key="$1"
  local value="$2"
  local lane_enabled="$3"
  local lane="$4"
  local forwarded reason

  if [ -z "$value" ]; then
    forwarded=false
    reason="blank"
  elif [ "$lane_enabled" != "true" ]; then
    forwarded=false
    reason="lane-disabled"
  elif ! ibd_perf_lane_runs; then
    forwarded=false
    reason="no-runs"
  elif ! ibd_perf_lane_invoked "$lane"; then
    forwarded=false
    reason="not-reached"
  else
    forwarded=true
    reason="forwarded"
  fi
  echo "${key}=${value}"
  echo "${key}_forwarded=${forwarded}"
  echo "${key}_forwarded_reason=${reason}"
}

# Validates every nonempty timeout request through the same command builder
# and the same harness parser the campaign uses, before any lane runs. The
# framework's `--test_methods validate_options` switch runs the harness's own
# validation instead of the workload; a nonzero exit (1 from validate_options,
# 2 from argparse, 77 from SkipTest) aborts the caller under `set -e`.
# Requests for lanes that are disabled are still validated here so a typo is
# reported instead of ignored.
preflight_ibd_timeouts() {
  if [ -n "$REPLAY_TIMEOUT" ]; then
    echo "=== preflight replay timeout request via validate_options ==="
    build_replay_cmd w1-replay-floor archive chainstate "$TAIL_BLOCKS" \
      "$PERF_ARTIFACT_ROOT/summary/preflight-replay.json" ""
    IBD_PERF_CMD+=(--test_methods validate_options)
    "${IBD_PERF_CMD[@]}"
  fi
  if [ -n "$NETWORK_HEADERS_TIMEOUT" ] || [ -n "$NETWORK_TIP_TIMEOUT" ] || [ -n "$NETWORK_IBD_EXIT_TIMEOUT" ]; then
    echo "=== preflight network timeout requests via validate_options ==="
    build_network_cmd w2-replay-mixed \
      "$PERF_ARTIFACT_ROOT/summary/preflight-network.json" ""
    IBD_PERF_CMD+=(--test_methods validate_options)
    "${IBD_PERF_CMD[@]}"
  fi
}

run_replay() {
  local workload="$1"
  local history_mode="$2"
  local reindex_mode="$3"
  local run_id="$4"
  local history_tail="$TAIL_BLOCKS"
  local report_name="${workload}-${history_mode}-${reindex_mode}-run${run_id}.json"
  local trace_file=""

  if [ "$history_mode" = "witness-pruned" ]; then
    history_tail="$IBD_PERF_EFFECTIVE_WITNESS_TAIL"
  fi

  if [ "$ENABLE_TRACING" = "true" ] && [ "$workload" = "w2-replay-mixed" ] && [ "$reindex_mode" = "full" ]; then
    trace_file="$PERF_ARTIFACT_ROOT/replay/${workload}-${history_mode}-${reindex_mode}-run${run_id}.trace.txt"
  fi

  echo "=== replay ${workload} ${history_mode} ${reindex_mode} run ${run_id} ==="
  build_replay_cmd "$workload" "$history_mode" "$reindex_mode" "$history_tail" \
    "$PERF_ARTIFACT_ROOT/replay/$report_name" "$trace_file"
  ibd_perf_record_lane_invocation replay
  "${IBD_PERF_CMD[@]}"
}

run_network() {
  local workload="$1"
  local run_id="$2"
  local report_name="w3-network-${workload}-run${run_id}.json"
  local trace_file=""

  if [ "$ENABLE_TRACING" = "true" ]; then
    trace_file="$PERF_ARTIFACT_ROOT/network/${workload}-run${run_id}.trace.txt"
  fi

  mkdir -p "$PERF_ARTIFACT_ROOT/network"
  echo "=== network ${workload} run ${run_id} ==="
  build_network_cmd "$workload" "$PERF_ARTIFACT_ROOT/network/$report_name" "$trace_file"
  ibd_perf_record_lane_invocation network
  "${IBD_PERF_CMD[@]}"
}

run_ibd_lanes() {
  local required_tail run

  IBD_PERF_EFFECTIVE_WITNESS_TAIL="$TAIL_BLOCKS"
  required_tail=$((1002 - BLOCKS))
  if [ "$required_tail" -gt "$IBD_PERF_EFFECTIVE_WITNESS_TAIL" ]; then
    IBD_PERF_EFFECTIVE_WITNESS_TAIL="$required_tail"
  fi
  if [ "$IBD_PERF_EFFECTIVE_WITNESS_TAIL" -lt 0 ]; then
    IBD_PERF_EFFECTIVE_WITNESS_TAIL=0
  fi
  echo "effective_witness_tail_blocks=$IBD_PERF_EFFECTIVE_WITNESS_TAIL" \
    > "$PERF_ARTIFACT_ROOT/summary/replay-parameters.env"

  for run in $(seq 1 "$RUNS_PER_LANE"); do
    if [ "$ENABLE_REPLAY_LANES" = "true" ]; then
      run_replay w1-replay-floor archive chainstate "$run"
      run_replay w1-replay-floor archive full "$run"
      run_replay w1-replay-floor witness-pruned chainstate "$run"
      run_replay w2-replay-mixed archive chainstate "$run"
      run_replay w2-replay-mixed archive full "$run"
      run_replay w2-replay-mixed witness-pruned chainstate "$run"
    fi
    if [ "$ENABLE_NETWORK_IBD" = "true" ]; then
      run_network w2-replay-mixed "$run"
    fi
  done
}
