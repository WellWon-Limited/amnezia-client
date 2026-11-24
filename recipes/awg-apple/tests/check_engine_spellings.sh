#!/bin/sh
# AVPN (awg-apple tribe.18): the RandomTrailers spellings TribeServiceTraffic treats as "on" must be exactly the ones the
# engine's own settings generator turns into random_trailers=1 (PacketTunnelSettingsGenerator.swift uapiBool), or the
# stall ladder sizes keepalives for trailers off while the engine runs with them (second review, G3).
# Usage: check_engine_spellings.sh <awg-apple build folder> <TribeRoaming.swift>
set -eu
gen="$1/Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift"
roaming=$2
engine=$(awk '/func uapiBool/ { on = 1 } on && /case "/ { print; exit }' "$gen" | grep -o '"[^"]*"' | tr -d '"' | sort | tr '\n' ' ')
ours=$(grep 'engineTrueSpellings: Set<String> = \[' "$roaming" | grep -o '"[^"]*"' | tr -d '"' | sort | tr '\n' ' ')
grep -q 'random_trailers=\\(Self.uapiBool(randomTrailers))' "$gen" || { echo "check_engine_spellings: the generator no longer passes RandomTrailers through uapiBool"; exit 1; }
[ -n "$engine" ] && [ "$engine" = "$ours" ] || { echo "check_engine_spellings: engine [$engine] != TribeServiceTraffic [$ours]"; exit 1; }
echo "check_engine_spellings: OK ($engine)"
