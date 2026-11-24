#ifndef KILLSWITCH_H
#define KILLSWITCH_H

#include <QJsonObject>
#include <QSharedPointer>

#include "secureQSettings.h"

#ifdef Q_OS_MACOS
struct FirewallParams; // AVPN: client/platforms/macos/daemon/macosfirewall.h
#endif

class KillSwitch : public QObject
{
    Q_OBJECT
public:
    static KillSwitch *instance();
    bool init();
    bool refresh(bool enabled);
    bool disableKillSwitch();
    bool disableAllTraffic();
    bool enablePeerTraffic(const QJsonObject &configStr);
    bool enableKillSwitch(const QJsonObject &configStr, int vpnAdapterIndex);
    bool resetAllowedRange(const QStringList &ranges);
    bool addAllowedRange(const QStringList &ranges);
    bool isStrictKillSwitchEnabled();
#ifdef Q_OS_MACOS
    // AVPN (macOS pf state ownership, macospfanchors.h): the kill-switch session of the tunnel that is up -
    // the service's own record, never read back from pf. Opened by enableKillSwitch (Xray / OpenVPN) or
    // openTunnelSession (AmneziaWG, WireguardUtilsMacos::applyFirewallRules); closed by disableKillSwitch
    // (every stop, the service start, refresh(false)) together with the allowed ranges.
    // tunnelCreated: IpcServer::createTun brought up a tun for the session being built. The next session
    // opened takes it (enableKillSwitch: 200.allowVPN passes only it) or drops it (openTunnelSession); a stop
    // drops it. Deleting a tun (IpcServer::deleteTun) does not touch the session: a late delete of an older
    // session's device must not change the newer session, and a session ends at its stop, not at deleteTun.
    void tunnelCreated(const QString &ifname) { m_createdTun = ifname; }
    void openTunnelSession(const FirewallParams &params, const QString &tunnelIfname);
#endif

private:
    KillSwitch(QObject* parent) {};
    QStringList m_allowedRanges;
    QSharedPointer<SecureQSettings> m_appSettigns;
#ifdef Q_OS_MACOS
    bool m_sessionOpen = false; // AVPN
    QString m_createdTun;       // AVPN: brought up for the session being built, not taken yet
#endif

};

#endif // KILLSWITCH_H
