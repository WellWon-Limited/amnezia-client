#!/bin/bash
# Scan lab: set the server switches through the admin API (client_features is replaced as a WHOLE map).
# usage: admin_flags.sh on|off   (off = v1_scanner false, the rest unchanged)
set -euo pipefail
source "${SCAN_LAB_DIR:-$HOME/avpn-build/scan-lab}/backend-env.sh"
A=(-s -H "Authorization: Bearer $ADMIN_API_TOKEN" -H "Content-Type: application/json")
cur=$(curl "${A[@]}" http://127.0.0.1:48480/admin/config)
scanner=$([ "${1:-on}" = "on" ] && echo true || echo false)
body=$(python3 -c "
import json,sys
c=json.loads(sys.argv[1]); f=dict(c.get('client_features_effective') or {})
f.update({'v1_scanner': $( [ "$scanner" = true ] && echo True || echo False ), 'v1_upstream_nodes': True, 'upstream_nodes': True, 'v1_xray_nodes': True})
print(json.dumps({'client_features': f}))" "$cur")
curl "${A[@]}" -X PATCH -d "$body" http://127.0.0.1:48480/admin/config | python3 -c "import json,sys; c=json.load(sys.stdin); print(json.dumps(c.get('client_features')))"
