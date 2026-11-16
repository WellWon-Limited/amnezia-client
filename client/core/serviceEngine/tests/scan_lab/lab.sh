#!/bin/bash
# Scan lab e2e: start / stop / status of the local lab (backend, redis, world helper). Everything on 127.0.0.1.
#   lab.sh up       redis (48479), world helper (fronts 48481..48488, xray servers, subscription), backend (48480)
#   lab.sh down     stop all three
#   lab.sh status
set -uo pipefail
L="${SCAN_LAB_DIR:-$HOME/avpn-build/scan-lab}"
BE="${SCAN_LAB_BACKEND:-$HOME/.worktrees/tribe-backend/scan-lab}"
mkdir -p "$L/logs" "$L/world"

up_redis() {
  if redis-cli -p 48479 ping >/dev/null 2>&1; then echo "redis: already up"; return; fi
  redis-server --port 48479 --bind 127.0.0.1 --save '' --appendonly no --daemonize yes \
    --pidfile "$L/redis.pid" --logfile "$L/logs/redis.log" --dir "$L"
  sleep 0.5; redis-cli -p 48479 ping
}

up_world() {
  if pgrep -f "$L/bin/scanlab-world" >/dev/null; then echo "world: already up"; return; fi
  nohup "$L/bin/scanlab-world" -out "$L/world" -stall "${STALL_BYTES:-16384}" > "$L/logs/world.jsonl" 2> "$L/logs/world.err" &
  echo $! > "$L/world.pid"
  for _ in $(seq 1 50); do grep -q '"ev":"ready"' "$L/logs/world.jsonl" 2>/dev/null && break; sleep 0.1; done
  grep -q '"ev":"ready"' "$L/logs/world.jsonl" && echo "world: up (pid $(cat "$L/world.pid"))"
}

up_backend() {
  if lsof -nP -iTCP:48480 -sTCP:LISTEN >/dev/null 2>&1; then echo "backend: port 48480 busy (already up?)"; return; fi
  (cd "$BE" && source "$L/backend-env.sh" && nohup uv run uvicorn tribe_backend.main:app --host 127.0.0.1 --port 48480 \
    >> "$L/logs/backend.log" 2>&1 & echo $! > "$L/backend.pid")
  for _ in $(seq 1 60); do curl -s -o /dev/null http://127.0.0.1:48480/v1/config && break; sleep 0.25; done
  echo "backend: $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:48480/v1/config)"
}

down() {
  local p
  p=$(lsof -ti tcp:48480 -sTCP:LISTEN 2>/dev/null); [ -n "$p" ] && kill $p && echo "backend: stopped ($p)"
  [ -f "$L/world.pid" ] && kill "$(cat "$L/world.pid")" 2>/dev/null && echo "world: stopped"
  rm -f "$L/world.pid"
  [ -f "$L/redis.pid" ] && redis-cli -p 48479 shutdown nosave >/dev/null 2>&1 && echo "redis: stopped"
  sleep 1
  lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep -E ':(48479|48480|4848[1-9]) ' || echo "no lab listener left"
}

case "${1:-}" in
  up) up_redis; up_world; up_backend ;;
  restart-backend) p=$(lsof -ti tcp:48480 -sTCP:LISTEN 2>/dev/null); [ -n "$p" ] && kill $p; sleep 1.5; up_backend ;;
  down) down ;;
  status) lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep -E ':(48479|48480|4848[1-9]) '; pgrep -fl "$L/bin/scanlab-world" ;;
  *) echo "usage: $0 up|down|status"; exit 2 ;;
esac
