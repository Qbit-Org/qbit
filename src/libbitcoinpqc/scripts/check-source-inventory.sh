#!/bin/sh

set -eu

fail=0
tmp_dir="${TMPDIR:-/tmp}/bitcoinpqc-source-inventory.$$"

cleanup() {
    rm -rf "$tmp_dir"
}

trap cleanup EXIT
mkdir -p "$tmp_dir"

list_direct_c_files() {
    dir="$1"
    for file in "$dir"/*.c; do
        if [ -f "$file" ]; then
            printf '%s\n' "$file"
        fi
    done | sort
}

check_inventory() {
    label="$1"
    expected="$2"
    actual="$3"

    if ! diff -u "$expected" "$actual"; then
        echo "Unexpected $label." >&2
        echo "Update CMakeLists.txt, docs/compiled-code-inventory.md, and this script for intentional source changes." >&2
        fail=1
    fi
}

cat > "$tmp_dir/expected-src" <<'EOF'
src/bitcoinpqc.c
src/test_helpers.c
EOF
list_direct_c_files src > "$tmp_dir/actual-src"
check_inventory "top-level src C source inventory" "$tmp_dir/expected-src" "$tmp_dir/actual-src"

cat > "$tmp_dir/expected-slh-dsa" <<'EOF'
src/slh_dsa/keygen.c
src/slh_dsa/sign.c
src/slh_dsa/utils.c
src/slh_dsa/validate.c
src/slh_dsa/verify.c
EOF
list_direct_c_files src/slh_dsa > "$tmp_dir/actual-slh-dsa"
check_inventory "SLH-DSA facade C source inventory" "$tmp_dir/expected-slh-dsa" "$tmp_dir/actual-slh-dsa"

if [ -e src/slh_dsa/slh_dsa.c ]; then
    echo "src/slh_dsa/slh_dsa.c is stale non-production integration code and must not be restored." >&2
    fail=1
fi

stale_reference_pattern='src/slh_dsa/slh_dsa\.c|slh_dsa_shake_128s|SPHINCS[+]-shake-128s'

if git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    git grep -n -E "$stale_reference_pattern" -- CMakeLists.txt src include > "$tmp_dir/stale-references" || true
else
    grep -R -n -E "$stale_reference_pattern" CMakeLists.txt src include > "$tmp_dir/stale-references" || true
fi

if [ -s "$tmp_dir/stale-references" ]; then
    cat "$tmp_dir/stale-references" >&2
    echo "Found stale SLH-DSA integration references in production paths." >&2
    fail=1
fi

exit "$fail"
