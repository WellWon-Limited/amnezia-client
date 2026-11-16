"""Scan lab e2e: per scenario, the verdict table and the three-way byte comparison (app ledger, engine bytes_spent,
server side: the backend's own scan budget counters, the edge fronts' bytes, and the access-link meters)."""

import json
import sys
from collections import defaultdict

L = sys.argv[1]
SCEN = sys.argv[2:]
WORLD = json.load(open(f"{L}/world/world.json"))

def load_world(s):
    a = int(open(f"{L}/runs/{s}.world-from").read())
    b = int(open(f"{L}/runs/{s}.world-to").read())
    lines = open(f"{L}/logs/world.jsonl").read().splitlines()[a:b]
    return [json.loads(x) for x in lines if x.startswith("{")]


def redis_delta(s):
    before = json.load(open(f"{L}/runs/{s}.redis-before.json"))
    after = json.load(open(f"{L}/runs/{s}.redis-after.json"))
    out = defaultdict(int)
    for k, v in after.items():
        kind = "tok" if ":tok:" in k else "dev"
        field = k.rsplit(":", 1)[1]
        out[f"{kind}_{field}"] += int(v) - int(before.get(k, 0))
    return dict(out)


for s in SCEN:
    try:
        r = json.load(open(f"{L}/runs/{s}.json"))
    except FileNotFoundError:
        print(f"== {s}: no evidence")
        continue
    print(f"\n== scenario {s}: checks {r['checks']}, failed {r['failed']}")
    ev = r["events"]
    items = {}
    finals = []
    freeze = []
    starts = []
    for e in ev:
        if e["ev"] == "host_reply" and e.get("action") == "scan_poll":
            for it in e.get("items", []):
                if it.get("stage") == "data" or it.get("error"):
                    items[it["id"]] = it
            if e.get("final"):
                finals.append(e)
        if e["ev"] == "host_reply" and e.get("action") == "scan_freeze":
            freeze.append(e)
        if e["ev"] == "host_reply" and e.get("action") == "scan_cancel" and e.get("final"):
            finals.append(e)
        if e["ev"] == "host_request" and e.get("action") == "scan_start":
            starts.append(e)
    print("probe verdicts (engine items):")
    for k, it in items.items():
        print(f"  {k:22} stage={it.get('stage'):5} error={it.get('error') or '-':14} http={it.get('http_status')} body={it.get('bytes')} "
              f"sha_ok={it.get('sha_ok')} class={it.get('egress_class')} node={it.get('egress_node')} asn={it.get('egress_asn')} "
              f"net={it.get('net_token')} spent={it.get('spent_bytes')}")
    fv = r.get("final_view") or r.get("view_after_running_scan") or {}
    print("rows on screen:", [(x.get("id"), x.get("state"), x.get("speed")) for x in fv.get("rows", [])], "phase", fv.get("phase"),
          "empty", fv.get("empty"))
    for f in freeze:
        print(f"  freeze ack: spent={f.get('spent')} reserved={f.get('reserved')}")
    for f in finals:
        print(f"  final totals: bytes_spent={f.get('bytes_spent')} reason={f.get('reason')} phase={f.get('phase')}")
    for st in starts:
        print(f"  scan_start: max_bytes={st.get('max_bytes')} candidates={len(st.get('candidates', []))}")
    # app side
    app_bytes = []
    for e in ev:
        if e["ev"] == "journal" and " bytes=" in e["line"] and e["line"].startswith("api "):
            app_bytes.append(e["line"])
    app_sum = sum(int(x.split(" bytes=")[1].split()[0]) for x in app_bytes)
    print("app requests as the app counted them:", app_sum, "bytes over", len(app_bytes), "requests")
    for x in app_bytes:
        print("   ", x)
    ledger = r.get("ledger")
    ledger_sum = sum(int(x["bytes"]) for x in ledger) if isinstance(ledger, list) else ledger
    print("app ledger (avpn/scanBudget):", ledger)
    w = load_world(s)
    link = defaultdict(lambda: [0, 0, 0])
    front_conn = defaultdict(lambda: [0, 0, 0])
    front_req = defaultdict(lambda: [0, 0, 0])
    for e in w:
        if e.get("ev") == "link_close":
            x = link[e["server"]]
            x[0] += e["up"]; x[1] += e["down"]; x[2] += 1
        if e.get("ev") == "conn_close":
            x = front_conn[e["front"]]
            x[0] += e["wire_in"]; x[1] += e["wire_out"]; x[2] += 1
        if e.get("ev") == "req":
            x = front_req[(e["front"], e["path"])]
            x[0] += e.get("req_body", 0); x[1] += e["resp_body"]; x[2] += 1
    print("access link (device <-> proxy entry, counting relays):")
    tot_link = 0
    for k, (u, d, n) in sorted(link.items()):
        if k == "provC-last":
            print(f"  {k:12} up={u} down={d} conns={n}   (provider-internal hop, not the device's link)")
            continue
        tot_link += u + d
        print(f"  {k:12} up={u} down={d} total={u + d} conns={n}")
    print("  access-link total:", tot_link)
    print("edge fronts (TLS wire bytes at the backend's edge, per front):")
    tot_front = 0
    for k, (i, o, n) in sorted(front_conn.items()):
        tot_front += i + o
        print(f"  {k:8} in={i} out={o} total={i + o} conns={n}")
    print("  edge total:", tot_front)
    # The access front also serves the REALITY servers' own dest handshakes (server side, never on the device's
    # link): a connection is the engine's direct netinfo attempt when a /v1/netinfo request on that front completed
    # right before it closed.
    netinfo_bytes, last_netinfo = 0, None
    from datetime import datetime
    def ts(e):
        return datetime.strptime(e["t"], "%H:%M:%S.%f")
    for e in w:
        if e.get("ev") == "req" and e.get("front") == "access" and e.get("path") == "/v1/netinfo":
            last_netinfo = ts(e)
        elif e.get("ev") == "conn_close" and e.get("front") == "access" and last_netinfo is not None:
            if (ts(e) - last_netinfo).total_seconds() < 0.25 and e["wire_in"] + e["wire_out"] > 0:
                netinfo_bytes += e["wire_in"] + e["wire_out"]
                last_netinfo = None
    print("  of which the engine's direct netinfo attempts:", netinfo_bytes)
    print("edge requests (front, path): req_body / resp_body / count")
    for k, (i, o, n) in sorted(front_req.items()):
        print(f"  {k} {i} {o} {n}")
    print("backend scan budget counters (delta):", redis_delta(s))
    print("leases right after:", open(f"{L}/runs/{s}.leases.json").read().strip())
    try:
        print("leases 61 s later:", open(f"{L}/runs/{s}.leases-after-61s.json").read().strip())
    except FileNotFoundError:
        pass
    # One final total per host scan (scenario A runs two scans): the engine's bytes are their sum, the same span
    # the access-link and edge counters cover.
    per_scan = {}
    for i, f in enumerate(finals):
        per_scan[f.get("scan_id") or f"#{i}"] = f.get("bytes_spent") or 0
    engine_final = sum(per_scan.values()) if per_scan else None
    device_side = tot_link + netinfo_bytes
    print(f"THREE NUMBERS: app ledger={ledger_sum} (app requests {app_sum} + host charge)  engine bytes_spent={engine_final}"
          f"{f' (sum of {len(per_scan)} scans)' if len(per_scan) > 1 else ''}  "
          f"backend probe bytes charged={redis_delta(s).get('tok_bytes')}  | device-side probe bytes measured={device_side} "
          f"(access link {tot_link} + netinfo {netinfo_bytes})"
          + (f"  engine vs measured {100.0 * (engine_final - device_side) / device_side:+.1f}%" if engine_final and device_side else ""))
print("\noutcomes in the DB:\n" + open(f"{L}/runs/outcomes.txt").read())
print("bench reports in the DB:\n" + open(f"{L}/runs/bench.txt").read())
