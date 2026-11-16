"""Scan lab e2e: seeding and inspection of the throwaway local backend (run in the backend worktree's venv
with $SCAN_LAB_DIR/backend-env.sh sourced; run-lab.sh does this). Synthetic data only: documentation addresses, made-up ASNs.

  asn <path>                          write the lab ASN table (access / own nodes / provider exits)
  nodes <id:ip:cc> ...                insert healthy own Node rows whose endpoint host is the node's exit address
  admin <device_id>                   mark the device is_admin (SQL only, as in prod: no API)
  xray <device_id> <world.json> <node:server> ...  own Xray listeners + the device's provisioned bindings
  fetch <source_id> <local_sub_url>   run the REAL fetch pipeline of one source (upstream_fetch.run_fetch) with
                                      the documented test seams: a resolver answering a public address (the SSRF
                                      guard passes on it) and a transport that relays the request to the local
                                      subscription server. The guard itself is untouched.
  leases                              active upstream leases (released_at IS NULL AND expires_at > now())
  budget                              Redis scan budget counters (scan:bud:*)
  profiles <source_id>                the source's profiles (public id, label, state)
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import socket
import sys
from typing import Any

import httpx
from sqlalchemy import select, text

from tribe_backend import asn_table
from tribe_backend.config import settings
from tribe_backend.db import SessionLocal
from tribe_backend.models import Device, Node, NodeStatus, UpstreamProfile

FULL_AWG = {"Jc": 4, "Jmin": 50, "Jmax": 1000, "S1": 86, "S2": 57, "H1": 1234567, "H2": 2345678, "H3": 3456789, "H4": 4567890}

# Lab networks (documentation ranges; the edge fronts stamp them into X-Forwarded-For).
ACCESS = ("192.0.2.0", "192.0.2.255", 64500)  # the device's access network (home Wi-Fi ISP)
OWN = ("198.51.100.0", "198.51.100.255", 64501)  # our own nodes' exits
PROVIDER = ("203.0.113.0", "203.0.113.255", 64510)  # provider exits


def cmd_asn(path: str) -> None:
    ranges = [asn_table.AsnRange(ipaddress.ip_address(a), ipaddress.ip_address(b), n) for a, b, n in (ACCESS, OWN, PROVIDER)]
    asn_table.write_table(path, ranges)
    print(json.dumps({"asn_table": path, "ranges": [[a, b, n] for a, b, n in (ACCESS, OWN, PROVIDER)]}))


async def cmd_nodes(specs: list[str]) -> None:
    async with SessionLocal() as s:
        for spec in specs:
            nid, ip, cc = spec.split(":")
            node = await s.get(Node, int(nid))
            if node is None:
                node = Node(id=int(nid), region="lab", endpoint=f"{ip}:585", server_pubkey=f"lab-server-pubkey-{nid}",
                            weight=1, status=NodeStatus.healthy, awg_params=dict(FULL_AWG), label=f"Lab {nid}",
                            country_code=cc)
                s.add(node)
            print(json.dumps({"node": int(nid), "endpoint": f"{ip}:585", "cc": cc}))
        await s.commit()


async def cmd_admin(device_id: str) -> None:
    async with SessionLocal() as s:
        dev = await s.get(Device, int(device_id))
        assert dev is not None
        dev.is_admin = True
        await s.commit()
        print(json.dumps({"device": dev.id, "is_admin": True, "platform": dev.platform, "app_version": dev.app_version}))


FLOOR = {"ios": "5.1.109", "macos": "5.1.109", "android": "5.1.109", "windows": "5.1.109"}


async def cmd_xray(device_id: str, world_path: str, specs: list[str]) -> None:
    """Own Xray listeners exactly as the transport worker leaves them: a ready host linked to the legacy node
    (its public IPv4 = the node's exit address, the egress map's key), a ready+healthy v1-exposed VLESS+REALITY
    profile whose endpoint is the local REALITY server of world.json, and the device's PROVISIONED binding whose
    credential (AES-GCM, the binding key) is the lab UUID the local server accepts. Spec: node_id:world_server."""
    import uuid as _uuid
    from datetime import UTC, datetime, timedelta

    from tribe_backend.binding_secrets import BindingSecretCipher
    from tribe_backend.models import DeviceBinding, Location, TransportHost, TransportProfile

    world = json.load(open(world_path))
    servers = {sv["name"]: sv for sv in world["servers"]}
    now = datetime.now(UTC)
    cipher = BindingSecretCipher.from_settings()
    async with SessionLocal() as s:
        dev = await s.get(Device, int(device_id))
        assert dev is not None
        for spec in specs:
            nid, name = spec.split(":")
            sv = servers[name]
            node = await s.get(Node, int(nid))
            assert node is not None, f"node {nid} first"
            exit_ip = node.endpoint.rsplit(":", 1)[0]
            loc = Location(id=f"lab-{nid}", country_code=node.country_code or "FI", city_code="LAB",
                           display_key=f"location.lab.{nid}", visibility="public")
            s.add(loc)
            host = TransportHost(legacy_node_id=int(nid), management_address=exit_ip, management_port=22, ssh_user="root",
                                 ssh_host_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestScanLabHostPin", public_ipv4=exit_ip,
                                 region="lab", failure_domain=f"lab/{nid}", state="ready", inventory_at=now,
                                 image_facts={"xray_binary_path": "/usr/local/bin/xray", "xray_binary_sha256": "b" * 64,
                                              "awg_binary_sha256": "a" * 64, "default_egress_interface": "lo0"})
            s.add(host)
            await s.flush()
            prof = TransportProfile(
                id=f"xray-lab-{nid}", location_id=loc.id, primary_host_id=host.id, transport="xray",
                endpoint_host="127.0.0.1", endpoint_port=int(sv["port"]), server_engine="xray-core",
                server_engine_version="26.10.31", profile_kind="xray_vless_reality_vision_tcp", config_generation=1,
                server_secret_ref=f"file-profile:xray-lab-{nid}",
                public_config={"network": "tcp", "security": "reality", "flow": "xtls-rprx-vision",
                               "reality_public_key": sv["reality_public_key"], "short_id": sv["short_id"],
                               "server_name": sv["server_name"], "fingerprint": "chrome"},
                service_name=f"tribe-xray-lab-{nid}", config_path=f"/etc/tribe/profiles/xray-lab-{nid}.json",
                listener_port=int(sv["port"]), api_port=48000 + int(nid), cohort="general", state="ready",
                health_state="healthy", health_updated_at=now, v1_exposed=True, min_app_version=dict(FLOOR),
                expected_egress_ids=[f"lab/{nid}"], verification_context=f"xray-lab-{_uuid.uuid4().hex}")
            s.add(prof)
            await s.flush()
            b = DeviceBinding(id=_uuid.uuid4(), device_id=dev.id, device_ref=f"device:{dev.id}", profile_id=prof.id,
                              transport="xray", generation=1, state="provisioned", provisioned_at=now - timedelta(minutes=1),
                              credential_lease_until=now + timedelta(days=2))
            b.stats_email = f"tb-{b.id.hex}-g1@stats.invalid"
            enc = cipher.encrypt(world["uuid"], device_ref=b.device_ref, profile_id=prof.id, generation=1)
            b.credential_ciphertext, b.credential_nonce, b.credential_key_id = enc.ciphertext, enc.nonce, enc.key_id
            s.add(b)
            print(json.dumps({"node": int(nid), "listener": f"{nid}:xray", "server": name, "endpoint": f"127.0.0.1:{sv['port']}",
                              "exit": exit_ip, "host_id": host.id}))
        await s.commit()


class LocalRelay(httpx.AsyncBaseTransport):
    """Relays every request of the fetcher to the local subscription server (same path and headers)."""

    def __init__(self, target: str) -> None:
        self._target = httpx.URL(target)
        self._inner = httpx.AsyncHTTPTransport()
        self.seen: list[str] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(f"{request.method} {request.url.host}{request.url.path} ua={request.headers.get('user-agent', '')}")
        url = self._target.copy_with(query=request.url.query)
        relayed = httpx.Request(request.method, url, headers=[(k, v) for k, v in request.headers.items() if k.lower() != "host"])
        resp = await self._inner.handle_async_request(relayed)
        await resp.aread()
        return httpx.Response(resp.status_code, headers=resp.headers, content=resp.content, request=request)


async def cmd_fetch(source_id: int, local_url: str) -> None:
    from tribe_backend import upstream_fetch

    async def public_resolver(host: str, port: int) -> list[tuple[Any, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", port))]

    relay = LocalRelay(local_url)
    async with SessionLocal() as s:
        outcome = await upstream_fetch.run_fetch(s, source_id, transport=relay, resolver=public_resolver)
    print(json.dumps({"outcome": str(outcome), "relayed": relay.seen}, default=str))


async def cmd_leases() -> None:
    async with SessionLocal() as s:
        rows = (await s.execute(text(
            "select kind, count(*) from upstream_leases where released_at is null and expires_at > now() group by kind"))).all()
        total = (await s.execute(text("select kind, release_reason, count(*) from upstream_leases group by 1, 2"))).all()
    print(json.dumps({"active": {k: n for k, n in rows}, "all": [[k, r, n] for k, r, n in total]}))


async def cmd_budget() -> None:
    import redis.asyncio as aioredis

    r = aioredis.from_url(settings.redis_url)
    out = {}
    async for key in r.scan_iter("scan:bud:*"):
        out[key.decode()] = (await r.get(key)).decode()
    await r.aclose()
    print(json.dumps(out, sort_keys=True))


async def cmd_profiles(source_id: int) -> None:
    async with SessionLocal() as s:
        rows = (await s.execute(select(UpstreamProfile).where(UpstreamProfile.source_id == source_id))).scalars().all()
        for p in rows:
            print(json.dumps({c: getattr(p, c, None) for c in (
                "id", "public_id", "label", "present", "enabled", "tunnel_api_route", "leak_guard_state", "composite",
                "required_geo")}, default=str))


def main() -> None:
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "asn":
        cmd_asn(args[0])
    elif cmd == "nodes":
        asyncio.run(cmd_nodes(args))
    elif cmd == "admin":
        asyncio.run(cmd_admin(args[0]))
    elif cmd == "xray":
        asyncio.run(cmd_xray(args[0], args[1], args[2:]))
    elif cmd == "fetch":
        asyncio.run(cmd_fetch(int(args[0]), args[1]))
    elif cmd == "leases":
        asyncio.run(cmd_leases())
    elif cmd == "budget":
        asyncio.run(cmd_budget())
    elif cmd == "profiles":
        asyncio.run(cmd_profiles(int(args[0])))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    _ = hashlib  # keep import list stable
    main()
