#!/bin/bash
# AVPN (round mac-C, 25.11.2026): a session the macOS GUI adopts from the root daemon after a restart acts like one it
# started (DaemonAdoptHint.h). The device round: mode -> Xray on an adopted AmneziaWG session did nothing until stop and
# connect - the adoption gave the engine no node and no transport. Each line below fails if a call site is reverted;
# the decisions themselves are tested by build_mac_daemon_adopt.sh on the real ServiceEngine.
#   A1  the daemon's status names its peer's endpoint (macOS only);
#   A2  the startup probe takes the daemon's words (daemonAdoptHintFromStatus) before the adoption runs;
#   A3  the macOS adoption gives the engine the hint {awg, endpoint}, names the node by it, and forgets the hint;
#   A4  the mode decision reads the live session's transport with the daemon's (liveSessionTransport);
#   A5  (review N4) the home card names only a pool row of that identity (transport + full endpoint) and otherwise
#       shows the session itself with its transport.
# Run by the check sweep (every check_*.sh of this directory).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
DAEMON="$ROOT/client/daemon/daemon.cpp"
FACADE="$ROOT/client/core/serviceEngine/AvpnEngineQml.cpp"
fail=0
bad() { echo "FAIL: $1"; fail=1; }
code() { grep -v '^[[:space:]]*//' "$1" || true; }
body() { code "$1" | awk -v sig="$2" 'index($0, sig) == 1 { on = 1 } on { print } on && /^}$/ { exit }'; }
has() { printf '%s\n' "$1" | grep -F -- "$2" > /dev/null; }
at() { printf '%s\n' "$1" | grep -nF -- "$2" | head -1 | cut -d: -f1 | sed 's/^$/0/'; }

# ---- A1 ------------------------------------------------------------------------------------------------------
st="$(body "$DAEMON" 'QJsonObject Daemon::getStatus() {')"
mac="$(printf '%s\n' "$st" | awk '/^#ifdef Q_OS_MACOS/ { on = 1; next } on && /^#endif/ { exit } on { print }')"
has "$mac" 'liveTunnelPeer(nullptr, &endpoint)' && has "$mac" 'json.insert("endpoint", endpoint);' \
  || bad "A1: the daemon's status does not name its peer's endpoint (macOS)"

# ---- A2 ------------------------------------------------------------------------------------------------------
probe="$(body "$FACADE" 'void AvpnEngineQml::probeDaemonTunnelOnStartup()')"
hint=$(at "$probe" 'm_daemonAdoptHint = avpn::daemonAdoptHintFromStatus(o);')
adopt=$(at "$probe" 'onConnectionStateChanged(Vpn::Connected);')
[ "${hint:-0}" -gt 0 ] && [ "${adopt:-0}" -gt "${hint:-0}" ] \
  || bad "A2: the startup probe does not take the daemon's hint before the adoption"

# ---- A3 ------------------------------------------------------------------------------------------------------
tryA="$(body "$FACADE" 'bool AvpnEngineQml::tryAdoptObservedTunnel(const char *why, bool ourStopPending)')"
macA="$(printf '%s\n' "$tryA" | awk '/^#elif defined\(Q_OS_MACOS\) && !defined\(MACOS_NE\)/ { on = 1; next } on && /^#(else|endif)/ { exit } on { print }')"
withHint=$(at "$macA" 'm_engine.adoptTunnelConnected(QString(), m_daemonAdoptHint.proto, m_daemonAdoptHint.endpoint);')
named=$(at "$macA" 'm_engine.tryIdentifyCurrentNode();')
forgot=$(at "$macA" 'm_daemonAdoptHint = avpn::DaemonAdoptHint();')
[ "${withHint:-0}" -gt 0 ] && [ "${named:-0}" -gt "${withHint:-0}" ] && [ "${forgot:-0}" -gt "${named:-0}" ] \
  || bad "A3: the macOS adoption does not adopt with the daemon's hint, name the node by it and forget the hint"
has "$macA" 'if (m_adoptedNoProto && !m_daemonAdoptHint.endpoint.isEmpty()) {' \
  || bad "A3: the hint is not limited to the daemon's own adoption"

# ---- A4 ------------------------------------------------------------------------------------------------------
mode="$(body "$FACADE" 'void AvpnEngineQml::setTransportMode(const QString &mode)')"
live=$(at "$mode" 'liveProto = avpn::liveSessionTransport(liveProto, m_adoptedNoProto);')
dec=$(at "$mode" 'avpn::isTunnelUpStateName(st), liveProto);')
[ "${live:-0}" -gt 0 ] && [ "${dec:-0}" -gt "${live:-0}" ] \
  || bad "A4: the mode decision does not read the daemon-adopted session's transport"

# ---- A5 (review N4) ------------------------------------------------------------------------------------------------
card="$(code "$FACADE" | awk '/QString hintOnlyProto;/ { on = 1 } on { print } on && /node\["proto"\]/ { exit }')"
has "$card" 'hintProto = hint.proto.isEmpty() ? QStringLiteral("awg") : hint.proto;' \
  && has "$card" 'hintedPoolRow(s.pool, hint.nodeId, hint.endpoint, hintProto);' \
  || bad "A5: the card guesses the adopted session's row without its transport"
has "$card" 'node["proto"]        = pick ? pick->proto : hintOnlyProto;' || bad "A5: the card hides the session's own transport"

[ "$fail" = "0" ] && echo "check_mac_daemon_adopt_wiring: ok"
exit "$fail"
