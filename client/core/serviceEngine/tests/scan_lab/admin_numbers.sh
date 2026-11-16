#!/bin/bash
# Scan lab: replace client_numbers (the WHOLE map) through the admin API. usage: admin_numbers.sh '<json object>'
set -euo pipefail
source "${SCAN_LAB_DIR:-$HOME/avpn-build/scan-lab}/backend-env.sh"
curl -s -H "Authorization: Bearer $ADMIN_API_TOKEN" -H "Content-Type: application/json" -X PATCH \
  -d "{\"client_numbers\": ${1:-null}}" http://127.0.0.1:48480/admin/config \
  | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin).get('client_numbers')))"
