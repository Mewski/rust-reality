#!/usr/bin/env bash
# Focused library evidence for LINE→LANDING stage diagnosis (no Frozen, no gate weaken).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EVIDENCE="$(cd "$(dirname "$0")" && pwd)/evidence"
mkdir -p "$EVIDENCE"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/workspace/cargo-target-diag}"
cd "$ROOT"

filters=(
  stale_warm
  checkout_discards
  a_failed_dial
  landing_errno
  pressure_reclaims
  zero_byte_peer
  warm_nxr_sends
  idle_admission_limit
  unused_handoff_socket_expires
)

summary="$EVIDENCE/library_evidence_summary.tsv"
echo -e "filter\tverdict\tpassed\tfailed" >"$summary"
overall=0
for f in "${filters[@]}"; do
  log="$EVIDENCE/library_${f}.log"
  if cargo test --lib --locked "$f" -- --test-threads=4 >"$log" 2>&1; then
    passed=$(rg -o '[0-9]+ passed' "$log" | tail -1 | awk '{print $1}')
    echo -e "${f}\tPASS\t${passed:-0}\t0" >>"$summary"
  else
    echo -e "${f}\tFAIL\t0\t1" >>"$summary"
    overall=1
  fi
done
cat "$summary"
exit "$overall"
