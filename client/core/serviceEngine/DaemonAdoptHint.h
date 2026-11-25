// client/core/serviceEngine/DaemonAdoptHint.h
// AVPN (macOS root daemon, round mac-C 25.11.2026): what a GUI that adopts the daemon's live tunnel knows about it.
//
// Before: the startup probe (AvpnEngineQml::probeDaemonTunnelOnStartup) adopted the daemon's tunnel with no hint at
// all (ServiceEngine::adoptTunnelConnected()), so the engine knew neither the session's node nor its transport. A
// session the app started carries its node; this one did not, and every decision that reads the live session went
// another way: a mode change to Xray was a no-op (decidePinOnTransportMode reads an unknown transport as "no
// mismatch" - test Mac 25.11 01:15Z: mode xray on an adopted AmneziaWG session, 20 s later the same amneziawg-go,
// exit country unchanged, until the user pressed stop and connect), the server list showed no current server.
//
// Now: the daemon's status names its peer's endpoint (Daemon::getStatus, macOS only), the GUI adopts with the hint
// {awg, endpoint} and the engine names the node by it (ServiceEngine::tryIdentifyCurrentNode - the rule the iOS
// session metadata already uses); a decision that reads the live session's transport takes AmneziaWG for a
// daemon-adopted session whose node is not named (an older daemon, a node no longer in the pool): the daemon runs
// AmneziaWG sessions only - Xray runs in the IPC server and ends with the GUI. Test: tests/build_mac_daemon_adopt.sh.
#pragma once

#include <QJsonObject>
#include <QString>

namespace avpn {

struct DaemonAdoptHint {
    QString proto;    // "awg" when the daemon holds a live tunnel, "" otherwise
    QString endpoint; // the daemon's peer "host:port"; "" = an older daemon that does not say it
};

// The daemon's {"type":"status"} reply -> the hint the adoption gives the engine.
inline DaemonAdoptHint daemonAdoptHintFromStatus(const QJsonObject &status)
{
    DaemonAdoptHint h;
    if (!status.value(QLatin1String("connected")).toBool())
        return h;
    h.proto = QStringLiteral("awg");
    const QString ep = status.value(QLatin1String("endpoint")).toString();
    if (!ep.isEmpty() && ep.size() <= 128 && ep.lastIndexOf(QLatin1Char(':')) > 0)
        h.endpoint = ep;
    return h;
}

// The transport of the live session for a decision of the facade (the transport mode): the engine's (its node's),
// else AmneziaWG for a session adopted from the daemon, else unknown ("").
inline QString liveSessionTransport(const QString &engineProto, bool adoptedFromDaemon)
{
    if (!engineProto.isEmpty())
        return engineProto;
    return adoptedFromDaemon ? QStringLiteral("awg") : QString();
}

} // namespace avpn
