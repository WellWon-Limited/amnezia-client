#ifndef KILLSWITCH_H
#define KILLSWITCH_H

#include <QJsonObject>
#include <QSharedPointer>

#include "secureQSettings.h"

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
    // AVPN (macOS pf state ownership): the tun the current service-routed session (Xray) brought up
    // (IpcServer::createTun) until it deletes it (IpcServer::deleteTun). Its kill switch passes only this
    // interface (200.allowVPN); empty = unknown (OpenVPN) -> the static file.
    void setTunnelInterface(const QString &ifname) { m_tunnelIfname = ifname; }
    void clearTunnelInterface(const QString &ifname)
    {
        if (m_tunnelIfname == ifname)
            m_tunnelIfname.clear();
    }

private:
    KillSwitch(QObject* parent) {};
    QStringList m_allowedRanges;
    QSharedPointer<SecureQSettings> m_appSettigns;
    QString m_tunnelIfname; // AVPN

};

#endif // KILLSWITCH_H
