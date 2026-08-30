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
    // Normal macOS catalog-v2 outer guard.  These methods include PF readback and are never
    // equivalent to the legacy UI kill-switch preference.
    bool armNativeSessionGuard(const QJsonObject &configStr);
    bool quarantineNativeSessionGuard();
    bool releaseNativeSessionGuard();
    bool resetAllowedRange(const QStringList &ranges);
    bool addAllowedRange(const QStringList &ranges);
    bool isStrictKillSwitchEnabled();

private:
    KillSwitch(QObject* parent) {};
    QStringList m_allowedRanges;
    QSharedPointer<SecureQSettings> m_appSettigns;
    bool m_nativeSessionGuardOwned = false;

};

#endif // KILLSWITCH_H
