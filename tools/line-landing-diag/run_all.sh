#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$DIR/evidence"
echo "== stage OS probes =="
python3 "$DIR/stage_os_probes.py"
echo "== intermittent refused race =="
python3 "$DIR/landing_flap_race.py"
echo "== library evidence =="
bash "$DIR/run_library_evidence.sh"
echo "== done; see $DIR/evidence =="
