#!/bin/bash
# Scan session edge (device round 19.11, Q1): the Scanner's API client (manifest, token, probe batch) takes its base
# from the same source as every other control-plane request, so the per-request edge rule (EdgeWalk.h::apiSessionEdgeFor,
# tested in edge_walk_check: no tunnel carrying -> the Russian entry, inside a tunnel -> the direct foreign edge) applies
# to it too: syncControlPlaneEdge -> ConfigService::setSessionEdge -> activeEdgeChanged -> m_baseUrl -> configureApi.
# AvpnEngineQml.cpp has no unit harness, so the forwarding is checked at source level.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$HERE/.."
FAC="$SE/AvpnEngineQml.cpp"
CFG="$SE/ConfigService.cpp"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
grep -qF 'scanner->configureApi(m_nam, [this]() { return m_baseUrl; }' "$FAC" \
    || bad "the Scanner's API base must be the facade's m_baseUrl (the control plane's active edge)"
grep -qF 'm_baseUrl = base;              // control plane' "$FAC" \
    || bad "m_baseUrl must follow ConfigService::activeEdgeChanged"
awk '/void ConfigService::setSessionEdge/{on=1} on{print} on&&/^}/{exit}' "$CFG" | grep -qF 'emit activeEdgeChanged(activeBaseUrl())' \
    || bad "a session-edge change must reach m_baseUrl (activeEdgeChanged)"
grep -qF 'm_configSvc->setSessionEdge(edge);' "$FAC" || bad "syncControlPlaneEdge must hand the route's edge to ConfigService"
[ "$fail" = 0 ] && echo "scan edge wiring: ok"
exit "$fail"
