#!/usr/bin/env bash
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
#
# Record one post-quantum transport sample for the mainnet canary (#184, R5).
# Run every 5 minutes from cron or a systemd timer on each canary node and on
# the control node; see README.md.
#
#   pq-canary-sample.sh --host LABEL --out DIR [--pinned ADDR:PORT] -- QBIT_CLI [ARGS...]
#
# Appends one row to DIR/samples.csv and, when getpqtransportinfo answers, one
# line to DIR/failures.jsonl. A failed call or a missing field is written as NA,
# never 0. --pinned names the archive node the pool node is pinned to; it makes
# getpeerinfo part of the sample. The addresses in failures.jsonl stay on the node.
# Exit status: 0 for a complete sample, 2 when sample_ok=0, 1 on a usage error.

export LC_ALL=C
set -o nounset -o pipefail

usage() {
  echo "Usage: $0 --host LABEL --out DIR [--pinned ADDR:PORT] -- QBIT_CLI [ARGS...]" >&2
  exit 1
}

host=""
out=""
pinned=""
while [ $# -gt 0 ]; do
  case "$1" in
    --host) [ $# -ge 2 ] || usage; host="$2"; shift 2 ;;
    --out) [ $# -ge 2 ] || usage; out="$2"; shift 2 ;;
    --pinned) [ $# -ge 2 ] || usage; pinned="$2"; shift 2 ;;
    --) shift; break ;;
    *) usage ;;
  esac
done
[ -n "$host" ] && [ -n "$out" ] && [ $# -gt 0 ] || usage
case "$host" in
  *[!A-Za-z0-9._-]*) echo "Error: --host must be letters, digits, '.', '_' or '-'" >&2; exit 1 ;;
esac
# The pinned peer as getpeerinfo shows it: host:port or [ipv6]:port (I2P peers show port 0).
if [ -n "$pinned" ]; then
  if ! [[ "$pinned" =~ ^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):([0-9]{1,5})$ ]] || [ "${BASH_REMATCH[2]}" -gt 65535 ]; then
    echo "Error: --pinned must be ADDRESS:PORT or [IPV6]:PORT, as getpeerinfo shows the pinned peer" >&2
    exit 1
  fi
fi

mkdir -p "$out" || exit 1
rpc_dir="$(mktemp -d)" || exit 1
trap 'rm -rf "$rpc_dir"' EXIT

# One timestamp for the whole sample.
now="$(date -u +%s)"
utc="$(date -u -d "@$now" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$now" +%Y-%m-%dT%H:%M:%SZ)"

cli=("$@")
# A hung node must not stall cron: bound each call when timeout(1) exists.
limit=()
if command -v timeout > /dev/null; then
  limit=(timeout 60)
fi

# Run one RPC; a failure leaves a marker so the formatter writes NA, not 0.
rpc() {
  local method="$1"
  if ! ${limit[@]+"${limit[@]}"} "${cli[@]}" "$method" > "$rpc_dir/$method" 2> "$rpc_dir/$method.err"; then
    : > "$rpc_dir/$method.failed"
  fi
}

rpc uptime
rpc getnetworkinfo
rpc getpqtransportinfo
pinned_args=()
if [ -n "$pinned" ]; then
  rpc getpeerinfo
  pinned_args=(--pinned "$pinned")
fi

python3 "$(dirname "$0")/pq_canary.py" sample \
  --rpc-dir "$rpc_dir" --out "$out" --host "$host" --time "$now" --utc "$utc" \
  ${pinned_args[@]+"${pinned_args[@]}"}
