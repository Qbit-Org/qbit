#!/usr/bin/env bash
#
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
#
# Shared validation helpers for libbitcoinpqc evidence collection scripts.

export LC_ALL=C

repo_url_for() {
    case "$1" in
        http://*|https://*|git@*|ssh://*|*.git) printf '%s\n' "$1" ;;
        */*) printf 'https://github.com/%s.git\n' "$1" ;;
        *) printf '%s\n' "$1" ;;
    esac
}

validate_upstream_ref() {
    local upstream_repo="$1"
    local upstream_ref="$2"
    local output_dir="$3"
    local log_dir="$4"
    local meta_dir="$5"

    local repo_url
    repo_url="$(repo_url_for "$upstream_repo")"
    local check_dir="$output_dir/upstream-ref-check"
    local -a git_cmd=(git -C "$check_dir")
    local upstream_token="${UPSTREAM_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"
    if [[ "$repo_url" == https://github.com/* && -n "$upstream_token" ]]; then
        local basic_auth
        basic_auth="$(printf 'x-access-token:%s' "$upstream_token" | base64 | tr -d '\n')"
        git_cmd+=(-c "http.https://github.com/.extraheader=AUTHORIZATION: basic $basic_auth")
    fi
    rm -rf "$check_dir"
    mkdir -p "$check_dir"
    if git -C "$check_dir" init -q &&
       "${git_cmd[@]}" fetch --depth=1 "$repo_url" "$upstream_ref" > "$log_dir/upstream-ref.log" 2>&1; then
        git -C "$check_dir" rev-parse FETCH_HEAD > "$meta_dir/upstream-ref-commit.txt"
        rm -rf "$check_dir"
        return 0
    else
        rm -rf "$check_dir"
        return 1
    fi
}

validate_curated_subtree_ref() {
    local source_dir="$1"
    local curated_subtree_ref="$2"
    local log_dir="$3"

    : > "$log_dir/curated-subtree-ref.log"
    if git -C "$source_dir" cat-file -e "${curated_subtree_ref}^{commit}" 2>>"$log_dir/curated-subtree-ref.log"; then
        return 0
    elif git -C "$source_dir" fetch --depth=1 origin "$curated_subtree_ref" >>"$log_dir/curated-subtree-ref.log" 2>&1 &&
         git -C "$source_dir" cat-file -e "${curated_subtree_ref}^{commit}" 2>>"$log_dir/curated-subtree-ref.log"; then
        return 0
    else
        return 1
    fi
}
