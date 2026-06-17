#!/usr/bin/env bash
export LC_ALL=C
exec "$(dirname "${BASH_SOURCE[0]}")/gen-qbit-conf.sh" "$@"
