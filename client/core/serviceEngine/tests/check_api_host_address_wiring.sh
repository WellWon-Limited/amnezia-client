#!/bin/bash
# AVPN (device round air-I review F4, 25.11): an address of our API edge is a public unicast address. The rule is
# ApiHostAddress.h (behaviour: api_host_address_check, scanner_facade_check base_ips_resolved_not_public, scan_core_check
# exclusion_no_public_base). What is checked here is where it is wired - each line fails if reverted:
#   A1  the one recording site (AvpnEngineQml::resolveApiCarveHosts) keeps only public answers, via recordApiHostAnswers;
#   A2  the Scanner's own two lookups keep only public answers (TribeScanner::finishResolve, ScanPathProberApi);
#   A3  without a public probe base address no proof by exclusion (ScanMachine evaluateExclusion "no_base_ip");
#   A4  a host still without a public address is asked again by the one owner of "the tunnel changed" (the api_reset
#       block), from one place; nothing drops the list.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$(cd "$HERE/.." && pwd)"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" | sed 's#[[:space:]]//.*##' || true; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
FACADE="$SE/AvpnEngineQml.cpp"
SCANNER="$SE/TribeScanner.cpp"
RACE="$SE/ScanPathProberApi.cpp"
MACHINE="$SE/ScanMachine.h"

# ---- A1 ----
rec="$(code "$FACADE" | awk '/^void AvpnEngineQml::resolveApiCarveHosts\(const QStringList &hosts\)/{f=1} f{print} f&&/^}$/{exit}')"
has "$rec" 'const int dropped = avpn::recordApiHostAnswers(m_apiHostIps, mine, info.addresses());' \
    || bad "A1: the lookup answers must be recorded through recordApiHostAnswers"
printf '%s\n' "$rec" | grep -qE 'for \(const QHostAddress &ip : info\.addresses\(\)\)' && bad "A1: the lookup answers are recorded unfiltered"
[ "$(code "$FACADE" | grep -cE 'm_apiHostIps\.append\(')" = "1" ] \
    || bad "A1: only the configured literal may be appended directly (found $(code "$FACADE" | grep -cE 'm_apiHostIps\.append\('))"

# ---- A2 ----
has "$(code "$SCANNER")" 'const QStringList base = scanBaseIpsOf(publicUnicastOnly(ips));' \
    && has "$(code "$SCANNER")" 'continueManifest(r.requestId, r.result, base);' \
    || bad "A2: the Scanner's own resolution must keep only public answers"
has "$(code "$RACE")" 's.baseIps = ipLiterals(publicUnicastOnly(ips));' || bad "A2: the race's own resolution must keep only public answers"

# ---- A3 ----
has "$(code "$MACHINE")" ': m_manifest.probeBaseIps.isEmpty() ? QStringLiteral("no_base_ip")' \
    || bad "A3: no public probe base address must mean no proof by exclusion"

# ---- A4 ----
owner="$(code "$FACADE" | awk '/if \(m_nam && newApiGeneration\(observedTunnelOf\(m_lastTunnelState\), observedTunnelOf\(s\)\)\) \{/{f=1} f{print} f&&/^    }$/{exit}')"
has "$owner" 'resolveApiCarveHostsStillMissing();' || bad "A4: the api_reset owner must ask the hosts still without a public address"
[ "$(code "$FACADE" | grep -cF 'resolveApiCarveHostsStillMissing();')" = "1" ] || bad "A4: one place asks them again"
code "$FACADE" | grep -qE 'm_apiHostIps(ByHost)?\.(clear|remove|removeAll|removeOne|take)\(' && bad "A4: nothing may drop the list"

[ "$fail" = "0" ] && echo "check_api_host_address_wiring: OK"
exit "$fail"
