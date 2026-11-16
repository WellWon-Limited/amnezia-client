#!/bin/bash
# Scanner local end-to-end lab, in one command (never part of an ordinary gate). Everything listens on 127.0.0.1;
# nothing is installed, no service and no app of the Mac is touched, no sudo. State and logs: $SCAN_LAB_DIR
# (default ~/avpn-build/scan-lab).
#
#   run-lab.sh                       prerequisites (backend worktree at origin/main, lab binaries, throwaway env),
#                                    fresh DB tribe_scanlab_e2e + private redis 48479 + edge fronts 48481..48489 +
#                                    backend 48480, seeding, harness build, scenarios A B C D S, byte analysis.
#                                    The lab is left UP for inspection: `lab.sh down` stops it.
#   SCENARIOS="A C" run-lab.sh       a subset;  KEEP_DB=1 reuses the running, seeded lab.
#   run-lab.sh --cleanup             lab down, DB dropped, backend worktree removed, lab app data removed.
# Scenarios: A Wi-Fi scan + a second scan on the stored manifest (304 + /v1/scan/token); B cellular with
# scan_budget_scan_bytes 614400; C «Остановить» mid-scan; D server switch v1_scanner off mid-run, then on + the
# NoScan report link (doctor schema 5 to /v1/bench/report); S = A with scan_stage2_stall_after_bytes 8192.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TESTS="$(cd "$HERE/.." && pwd)"
export SCAN_LAB_DIR="${SCAN_LAB_DIR:-$HOME/avpn-build/scan-lab}"
export SCAN_LAB_BACKEND="${SCAN_LAB_BACKEND:-$HOME/.worktrees/tribe-backend/scan-lab}"
L="$SCAN_LAB_DIR"
BE="$SCAN_LAB_BACKEND"
MAIN_REPO="${TRIBE_BACKEND_REPO:-$HOME/IdeaProjects/Tribe Backend}"
DB=tribe_scanlab_e2e
SCEN="${SCENARIOS:-A B C D S}"
APPDATA_LAB="$HOME/Library/Application Support/TribeScanLab/TribeScanLab"
mkdir -p "$L/logs" "$L/runs" "$L/world" "$L/bin"
py() { (cd "$BE" && source "$L/backend-env.sh" && uv run python "$HERE/lab_seed.py" "$@"); }

if [ "${1:-}" = "--cleanup" ]; then
  "$HERE/lab.sh" down
  psql -h 127.0.0.1 -U "$(whoami)" -d postgres -qc "drop database if exists $DB"
  [ -d "$BE" ] && git -C "$MAIN_REPO" worktree remove --force "$BE"
  rm -rf -- "${APPDATA_LAB:?}" "${L:?}/settings" "${L:?}/run"
  echo "cleanup done (scratch logs and evidence kept in $L)"
  exit 0
fi

# --- prerequisites -----------------------------------------------------------------------------------------------
if [ ! -d "$BE" ]; then
  git -C "$MAIN_REPO" fetch -q origin main && git -C "$MAIN_REPO" worktree add --detach "$BE" origin/main || exit 1
  (cd "$BE" && uv sync --quiet) || exit 1
fi
[ -f "$L/engine/lib-pkg/lib/libamnezia_xray.a" ] && [ -x "$L/bin/scanlab-world" ] \
  || "$HERE/make-lab-bins.sh" > "$L/logs/make-lab-bins.log" 2>&1 || { echo "lab binaries failed: $L/logs/make-lab-bins.log"; exit 1; }
if [ ! -f "$L/backend-env.sh" ]; then
  umask 077
  cat > "$L/backend-env.sh" <<EOT
# Scan lab e2e: env of the throwaway local backend (dev signing seed, own DB, own redis 48479). Throwaway secrets.
export APP_ENV=dev RUNTIME_ROLE=control TRIBE_ROLE=api BACKGROUND_LOOPS_ENABLED=false RUN_MIGRATIONS=0 MIGRATE_ONLY=0
export SECRET_KEY=$(openssl rand -hex 32)
export ADMIN_API_TOKEN=$(openssl rand -hex 24)
export UPSTREAM_SECRET_KEY=$(openssl rand -base64 32)
export DATABASE_URL=postgresql+asyncpg://tribe:tribe_dev@127.0.0.1:5432/$DB
export REDIS_URL=redis://127.0.0.1:48479/0
export TRUST_FORWARDED_FOR=1
export UPSTREAM_TUNNEL_API_BASE=https://probe.scanlab.test:48482
export UPSTREAM_TUNNEL_API_IPS='["127.0.0.1"]'
export SCAN_ASN_TABLE_PATH=$L/asn.bin
export EDGE_ENDPOINTS='["http://127.0.0.1:48481"]'
EOT
  umask 022
fi
[ -f "$L/asn.bin" ] || py asn "$L/asn.bin" || exit 1

# --- fresh lab ---------------------------------------------------------------------------------------------------
if [ "${KEEP_DB:-0}" != "1" ]; then
  "$HERE/lab.sh" down
  psql -h 127.0.0.1 -U "$(whoami)" -d postgres -qc "drop database if exists $DB" -c "create database $DB owner tribe" || exit 1
  (cd "$BE" && source "$L/backend-env.sh" && uv run alembic upgrade head > "$L/logs/alembic.log" 2>&1) || { echo "migration failed"; exit 1; }
  rm -rf -- "${L:?}/settings" "${L:?}/runs" "${L:?}/device.json" "${APPDATA_LAB:?}"
  mkdir -p "$L/runs"
  : > "$L/logs/world.jsonl"; : > "$L/logs/backend.log"
  "$HERE/lab.sh" up || exit 1
  "$HERE/admin_flags.sh" on
  "$HERE/admin_numbers.sh" null
  source "$L/backend-env.sh"
  # The provider source through the real admin API, then the REAL fetch pipeline with the documented test seams
  # (lab_seed.py fetch): the SSRF guard is untouched.
  SRC=$(curl -s -H "Authorization: Bearer $ADMIN_API_TOKEN" -H "Content-Type: application/json" -X POST http://127.0.0.1:48480/admin/upstreams \
    -d '{"display_name":"Lab provider","url":"https://sub.scanlab.test/sub","seats":10,"reserve":1,"tier":1,"cohort":"internal","enabled":true,"leak_guard":true,"min_app_version":{"ios":"5.1.109","macos":"5.1.109","android":"5.1.109","windows":"5.1.109"}}' \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
  py fetch "$SRC" "$(python3 -c "import json; print(json.load(open('$L/world/world.json'))['sub_url'])")"
  (cd "$TESTS" && TRIBE_SCAN_LAB=1 TRIBE_SCAN_ENGINE_PKG="$L/engine/lib-pkg" OUT="$L/bin/scan_lab_e2e" ./build_scan_lab_e2e.sh > "$L/logs/build-harness.log" 2>&1) \
    || { echo "harness build failed: $L/logs/build-harness.log"; exit 1; }
  TRIBE_SCAN_LAB=1 "$L/bin/scan_lab_e2e" register || exit 1
  DEV=$(psql -h 127.0.0.1 -U tribe -d $DB -Atc "select max(id) from devices")
  py admin "$DEV"
  py nodes 7:198.51.100.11:FI 8:198.51.100.12:DE
  py xray "$DEV" "$L/world/world.json" 7:own1 8:own2
  "$HERE/lab.sh" restart-backend # the egress map caches nodes for 60 s
fi

# --- scenarios ---------------------------------------------------------------------------------------------------
for S in $SCEN; do
  # each scenario: empty ledger / cache (lab INI) and no stored manifest (the lab app name's AppData)
  rm -rf -- "${L:?}/settings" "${APPDATA_LAB:?}/scan-manifests"
  [ "$S" = "B" ] && "$HERE/admin_numbers.sh" '{"scan_budget_scan_bytes": 614400}'
  [ "$S" = "S" ] && "$HERE/admin_numbers.sh" '{"scan_stage2_stall_after_bytes": 8192}'
  py budget > "$L/runs/$S.redis-before.json"
  wc -l < "$L/logs/world.jsonl" | tr -d ' ' > "$L/runs/$S.world-from"
  SCAN_LAB_SWITCH_OFF="$HERE/admin_flags.sh off" SCAN_LAB_SWITCH_ON="$HERE/admin_flags.sh on" \
    TRIBE_SCAN_LAB=1 TRIBE_SCAN_LAB_ROOTS="$L/world/lab-ca.pem" "$L/bin/scan_lab_e2e" scan "$S" > "$L/logs/run-$S.log" 2>&1
  echo "scenario $S: exit $?"
  sleep 2
  wc -l < "$L/logs/world.jsonl" | tr -d ' ' > "$L/runs/$S.world-to"
  py budget > "$L/runs/$S.redis-after.json"
  py leases > "$L/runs/$S.leases.json"
  { [ "$S" = "B" ] || [ "$S" = "S" ]; } && "$HERE/admin_numbers.sh" null
  [ "$S" = "D" ] && "$HERE/admin_flags.sh" on
  sleep 61 # past the probe leases' 60 s life (D leaves its leases to expire), the manual cooldown and the rate windows
  py leases > "$L/runs/$S.leases-after-61s.json"
done
psql -h 127.0.0.1 -U tribe -d $DB -Atc "select candidate_kind, candidate_id, network_key, ok_count, fail_count from path_outcomes order by 3,1,2" > "$L/runs/outcomes.txt"
psql -h 127.0.0.1 -U tribe -d $DB -Atc "select id, rtype, report->>'schema', report->'scan'->>'network_key', report->'scan'->'counts', report->'scan'->>'candidates', length(report::text) from bench_reports order by received_at" > "$L/runs/bench.txt" 2>&1
python3 -I "$HERE/analyze.py" "$L" $SCEN
