#!/bin/bash
# Round mac-B (test Mac 25.11.2026): every AmneziaWG connect looped because the macOS network key read the path of the
# nw_path_monitor, which follows our own tunnel (status 1 -> 2, the gateway gone the moment AmneziaWG came up). The rule
# is tested by behaviour in network_key_physical_check.cpp (build_network_key_physical.sh: uplinkPhysicalFacts with the
# measured readings, the key, the generation owner). What is checked here is where the key's facts come from - each
# line fails if a tunnel-dependent fact reaches the key, the Scanner's generation or fingerprint again:
#   K1  the key's gateway is the monitor's pathGatewayHash (currentNetworkObservation), the subnet the physical
#       interfaces' (physicalSubnet skips virtual names);
#   K2  the monitor's facts are uplinkPhysicalFacts(readingOf(path)) - setPath gets exactly them;
#   K3  uplinkPhysicalFacts reads no tunnel-dependent part of the reading (the path's status, interfaces, gateways);
#   K4  UplinkMonitor.mm makes no hash of its own (no second rule beside the pure one);
#   K5  the routers come from the per-service IPv4 state (Router + InterfaceName) of SystemConfiguration;
#   K6  a route-table dump that fails while a tunnel adds routes is retried (ENOMEM), never read as "no default".
# Run by the check sweep (every check_*.sh of this directory).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SE="$HERE/.."
FAC="$SE/AvpnEngineQml.cpp"
MH="$SE/UplinkMonitor.h"
MM="$SE/UplinkMonitor.mm"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" | sed 's#[[:space:]]//.*##' || true; }
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }

# ---- K1 ----
obs="$(body "$FAC" 'avpn::path::NetworkObservation AvpnEngineQml::currentNetworkObservation() const')"
[ -n "$obs" ] || bad "K1: currentNetworkObservation() not found"
has "$obs" 'o.gateway = netKindInputs().gatewayHash;' || bad "K1: the key's gateway is not the monitor's physical routers"
[ "$(printf '%s\n' "$obs" | grep -c 'o.gateway')" = 1 ] || bad "K1: the key's gateway is set from more than one source"
has "$(body "$FAC" 'static NetKindInputs netKindInputs()')" 'in.gatewayHash = m->pathGatewayHash();' \
    || bad "K1: netKindInputs no longer takes pathGatewayHash"
sub="$(body "$FAC" 'static QString physicalSubnet(const QString &kind)')"
has "$sub" 'avpn::physicalIfaceNameVirtual(i.name())' || bad "K1: the subnet may be read from a virtual interface"

# ---- K2 ----
mm="$(code "$MM")"
has "$mm" 'const UplinkReading reading = readingOf(path);' || bad "K2: the path update does not take one reading"
has "$mm" 'const UplinkPhysicalFacts facts = uplinkPhysicalFacts(reading);' || bad "K2: the facts are not uplinkPhysicalFacts"
has "$mm" 'self->setPath(facts.hash, facts.kind, facts.gatewayHash, reading);' || bad "K2: setPath gets other facts"
[ "$(printf '%s\n' "$mm" | grep -c 'setPath(')" = 2 ] || bad "K2: setPath is called from another place"

# ---- K3 ----
rule="$(code "$MH" | awk '/^inline UplinkPhysicalFacts uplinkPhysicalFacts\(const UplinkReading &r\)/ { on = 1 } on { print } on && /^}$/ { exit }')"
[ -n "$rule" ] || bad "K3: uplinkPhysicalFacts not found"
for t in 'r.pathStatus' 'r.pathInterfaces' 'r.pathGateways'; do
    has "$rule" "$t" && bad "K3: the facts read a tunnel-dependent part of the reading ($t)"
done
has "$rule" 'uplinkIfnameVirtual(' || bad "K3: another app's VPN service may count as the physical network"

# ---- K4 ----
printf '%s\n' "$mm" | grep -q 'QCryptographicHash' && bad "K4: UplinkMonitor.mm hashes something itself (a second rule)"

# ---- K5 ----
routers="$(body "$MM" 'QStringList physicalServiceRouters()')"
has "$routers" 'SCDynamicStoreKeyCreateNetworkServiceEntity(nullptr, kSCDynamicStoreDomainState, kSCCompAnyRegex,' \
    || bad "K5: the routers are not the per-service state"
has "$routers" 'kSCPropNetIPv4Router' && has "$routers" 'kSCPropInterfaceName' || bad "K5: Router / InterfaceName not read"
has "$(body "$MM" 'UplinkReading readingOf(nw_path_t path)')" 'r.serviceRouters = physicalServiceRouters();' \
    || bad "K5: the reading has no routers"

# ---- K6 ----
dump="$(body "$MM" 'bool dumpRouteTable(std::vector<char> &buf)')"
has "$dump" 'if (errno != ENOMEM)' || bad "K6: a failed route dump is not retried"
has "$(body "$MM" 'std::vector<std::string> physicalDefaultRouteIfnames()')" 'if (!dumpRouteTable(buf)) return out;' \
    || bad "K6: the default-route walk does not use the retrying dump"

[ "$fail" = 0 ] && echo "check_network_key_physical_wiring: OK"
exit "$fail"
