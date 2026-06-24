#!/bin/sh

set -eu

tracked_symlinks="$(git ls-files -s | awk '$1 == "120000" {print $4}')"

if [ -n "$tracked_symlinks" ]; then
    printf '%s\n' "Tracked symlinks are not allowed in this repository:" >&2
    printf '%s\n' "$tracked_symlinks" >&2
    exit 1
fi
