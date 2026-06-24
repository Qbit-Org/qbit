#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PARAM_FILE="sphincsplus/ref/params/params-sphincs-sha2-128s-bounded30.h"
SIG_FILE="include/libbitcoinpqc/slh_dsa.h"
FORS_FILE="sphincsplus/ref/fors.c"
WOTS_FILE="sphincsplus/ref/wots.c"

OUT_ROOT="${1:-.context/bench_runs}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="$OUT_ROOT/$RUN_ID"
RESULT_DIR="$OUT_DIR/results"
LOG_DIR="$OUT_DIR/logs"
TMP_DIR="$OUT_DIR/.tmp"
SUMMARY="$RESULT_DIR/summary.tsv"
TABLE_MD="$RESULT_DIR/comparison.md"

RUN_SMOKE_TESTS="${RUN_SMOKE_TESTS:-1}"
PARAM_BENCH_SAMPLES="${PARAM_BENCH_SAMPLES:-5}"
PARAM_BENCH_TARGET_MS="${PARAM_BENCH_TARGET_MS:-1500}"
PARAM_BENCH_MAX_INNER="${PARAM_BENCH_MAX_INNER:-50}"
CANDIDATE_IDS="${CANDIDATE_IDS:-}"

mkdir -p "$RESULT_DIR" "$LOG_DIR" "$TMP_DIR"

for cmd in git cargo jq perl awk; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd" >&2
    exit 1
  fi
done

BACKUP_PARAM="$TMP_DIR/orig_params.h"
BACKUP_SIG="$TMP_DIR/orig_slh_dsa.h"
BACKUP_FORS="$TMP_DIR/orig_fors.c"
BACKUP_WOTS="$TMP_DIR/orig_wots.c"
DEVELOP_PARAM="$TMP_DIR/develop_params.h"
DEVELOP_SIG="$TMP_DIR/develop_slh_dsa.h"
DEVELOP_FORS="$TMP_DIR/develop_fors.c"
DEVELOP_WOTS="$TMP_DIR/develop_wots.c"

cp "$PARAM_FILE" "$BACKUP_PARAM"
cp "$SIG_FILE" "$BACKUP_SIG"
cp "$FORS_FILE" "$BACKUP_FORS"
cp "$WOTS_FILE" "$BACKUP_WOTS"

git show develop:"$PARAM_FILE" > "$DEVELOP_PARAM"
git show develop:"$SIG_FILE" > "$DEVELOP_SIG"
git show develop:"$FORS_FILE" > "$DEVELOP_FORS"
git show develop:"$WOTS_FILE" > "$DEVELOP_WOTS"

restore_originals() {
  cp "$BACKUP_PARAM" "$PARAM_FILE"
  cp "$BACKUP_SIG" "$SIG_FILE"
  cp "$BACKUP_FORS" "$FORS_FILE"
  cp "$BACKUP_WOTS" "$WOTS_FILE"
}

trap restore_originals EXIT

apply_branch_wotsc_no_forsc() {
  local h="$1" d="$2" k="$3" a="$4"

  cp "$BACKUP_PARAM" "$PARAM_FILE"
  cp "$BACKUP_SIG" "$SIG_FILE"
  cp "$BACKUP_WOTS" "$WOTS_FILE"
  cp "$DEVELOP_FORS" "$FORS_FILE"

  perl -0pi -e "s/#define SPX_FULL_HEIGHT\\s+\\d+/#define SPX_FULL_HEIGHT $h/" "$PARAM_FILE"
  perl -0pi -e "s/#define SPX_D\\s+\\d+/#define SPX_D $d/" "$PARAM_FILE"
  perl -0pi -e "s/#define SPX_FORS_HEIGHT\\s+\\d+/#define SPX_FORS_HEIGHT $a/" "$PARAM_FILE"
  perl -0pi -e "s/#define SPX_FORS_TREES\\s+\\d+/#define SPX_FORS_TREES $k/" "$PARAM_FILE"
  perl -0pi -e "s/#define SPX_FORS_SIG_TREES\\s+.*/#define SPX_FORS_SIG_TREES SPX_FORS_TREES/" "$PARAM_FILE"
  perl -0pi -e "s/#define SPX_FORS_BYTES\\s+\\(\\(SPX_FORS_HEIGHT \\+ 1\\) \\* SPX_FORS_SIG_TREES \\* SPX_N\\)/#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)/" "$PARAM_FILE"

  local sig_size=$((16 + 16 * k * (a + 1) + 256 * d + 16 * h))
  perl -0pi -e "s/#define SLH_DSA_SIGNATURE_SIZE\\s+\\d+/#define SLH_DSA_SIGNATURE_SIZE $sig_size/" "$SIG_FILE"
}

apply_develop_baseline() {
  cp "$DEVELOP_PARAM" "$PARAM_FILE"
  cp "$DEVELOP_SIG" "$SIG_FILE"
  cp "$DEVELOP_FORS" "$FORS_FILE"
  cp "$DEVELOP_WOTS" "$WOTS_FILE"
}

printf "id\ttier\tmode\th\td\tk\ta\tkxa\tcat1\tsig_expected\tsig_actual\tkeygen_ms\tsign_ms\tverify_ms\tsmoke_test\tbench\n" > "$SUMMARY"

run_candidate() {
  local id="$1" tier="$2" mode="$3" h="$4" d="$5" k="$6" a="$7"
  local kxa=$((k * a))
  local cat1="no"
  local sig_expected="n/a"
  local smoke_status="skipped"
  local bench_status="fail"

  if (( kxa >= 128 )); then
    cat1="yes"
  fi

  case "$mode" in
    develop)
      apply_develop_baseline
      sig_expected=$((16 + 16 * k * (a + 1) + 288 * d + 16 * h))
      ;;
    branch_wotsc_no_forsc)
      apply_branch_wotsc_no_forsc "$h" "$d" "$k" "$a"
      sig_expected=$((16 + 16 * k * (a + 1) + 256 * d + 16 * h))
      ;;
    *)
      echo "unknown mode: $mode" >&2
      exit 1
      ;;
  esac

  if [[ "$RUN_SMOKE_TESTS" == "1" ]]; then
    if cargo test --release --test algorithm_tests test_keygen_sign_verify_roundtrip -- --exact > "$LOG_DIR/${id}_smoke.log" 2>&1; then
      smoke_status="pass"
    else
      smoke_status="fail"
    fi
  fi

  if PARAM_BENCH_SAMPLES="$PARAM_BENCH_SAMPLES" \
     PARAM_BENCH_TARGET_MS="$PARAM_BENCH_TARGET_MS" \
     PARAM_BENCH_MAX_INNER="$PARAM_BENCH_MAX_INNER" \
     cargo run --release --bin param_bench > "$RESULT_DIR/${id}.json" 2> "$LOG_DIR/${id}_bench.log"; then
    bench_status="pass"
  fi

  local sig_actual="n/a"
  local keygen_ms="n/a"
  local sign_ms="n/a"
  local verify_ms="n/a"
  if [[ -f "$RESULT_DIR/${id}.json" ]]; then
    sig_actual="$(jq -r '.signature_size' "$RESULT_DIR/${id}.json")"
    keygen_ms="$(jq -r '.keygen_ms' "$RESULT_DIR/${id}.json")"
    sign_ms="$(jq -r '.sign_ms' "$RESULT_DIR/${id}.json")"
    verify_ms="$(jq -r '.verify_ms' "$RESULT_DIR/${id}.json")"
  fi

  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$id" "$tier" "$mode" "$h" "$d" "$k" "$a" "$kxa" "$cat1" "$sig_expected" \
    "$sig_actual" "$keygen_ms" "$sign_ms" "$verify_ms" "$smoke_status" "$bench_status" \
    >> "$SUMMARY"
}

selected_candidate() {
  local id="$1"
  if [[ -z "$CANDIDATE_IDS" ]]; then
    return 0
  fi

  local needle=",$CANDIDATE_IDS,"
  [[ "$needle" == *",$id,"* ]]
}

# id tier mode h d k a
while read -r id tier mode h d k a; do
  [[ -z "$id" ]] && continue
  [[ "${id:0:1}" == "#" ]] && continue
  if ! selected_candidate "$id"; then
    continue
  fi
  run_candidate "$id" "$tier" "$mode" "$h" "$d" "$k" "$a"
done <<'EOF'
A Baseline develop 30 5 9 9
B Tier1 branch_wotsc_no_forsc 30 5 16 8
C Tier1 branch_wotsc_no_forsc 30 5 14 10
D Tier1 branch_wotsc_no_forsc 30 5 13 10
E Tier1 branch_wotsc_no_forsc 36 4 10 13
F Tier1 branch_wotsc_no_forsc 40 5 8 16
G Tier2 branch_wotsc_no_forsc 36 4 9 14
H Tier2 branch_wotsc_no_forsc 30 5 8 12
I Tier2 branch_wotsc_no_forsc 30 5 9 9
EOF

{
  echo "| ID | Tier | Mode | Params (h,d,k,a) | k×a | Cat 1? | Expected Sig (B) | Actual Sig (B) | Keygen (ms) | Sign (ms) | Verify (ms) | Smoke | Bench |"
  echo "|---|---|---|---|---:|:---:|---:|---:|---:|---:|---:|---|---|"
  tail -n +2 "$SUMMARY" | awk -F'\t' '{printf("| %s | %s | %s | %s,%s,%s,%s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",$1,$2,$3,$4,$5,$6,$7,$8,toupper($9),$10,$11,$12,$13,$14,$15,$16)}'
} > "$TABLE_MD"

echo "Wrote:"
echo "  $SUMMARY"
echo "  $TABLE_MD"
echo "  $RESULT_DIR/*.json"
echo "  $LOG_DIR/*.log"
