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
    // AVPN (round mac-D3, the kill switch across the app's own transitions): the app's lease on the person's intent
    // "VPN on" (IpcServer::setKillSwitchHold). ttlMs > 0 arms or renews it (bounded by kHoldMaxMs) with the API edge
    // addresses a provider leg's seat request needs; ttlMs <= 0 releases it. While it runs, a session stop keeps the
    // block (pf and every anchor) and only adds those addresses to the session's pass table; the next session's open
    // replaces the session anchors under the block. With no session open, its release or its end lifts the block.
    // The deadline is persisted: a service that starts inside it keeps the block a previous process left.
    // macOS only (the platform whose service owns a kill-switch session); elsewhere a no-op.
    bool setHold(int ttlMs, const QStringList &controlPlaneAddrs);
    void holdTick(); // the lease's end (its timer; the host check calls it with its clock)
    // The lease runs on the process's monotonic clock; the wall clock is only what is persisted for a restart (judged
    // once in init()). The host check replaces both.
    static void setClocksForTest(qint64 (*wallMs)(), qint64 (*monoMs)());
    bool holdTimerActive() const; // the host check: the lease's end is scheduled
    static constexpr int kHoldMaxMs = 15000;

private:
    KillSwitch(QObject* parent) {};
    QStringList m_allowedRanges;
    QSharedPointer<SecureQSettings> m_appSettigns;
#ifdef Q_OS_MACOS
    bool m_sessionOpen = false; // AVPN
    QString m_createdTun;       // AVPN: brought up for the session being built, not taken yet
    // AVPN (round mac-D3): the lease on the intent and the block it keeps between two sessions.
    bool holdActive() const;
    void keepBlockForNextSession();
    void liftHeldBlock(const char *why);
    void persistHold();
    void armHoldTimer();
    qint64 m_holdDeadlineMs = 0;     // monotonic clock (round mac-D4); 0 = no lease
    qint64 m_holdUntilWallMs = 0;    // the same deadline on the wall clock - persisted for a service restart only
    QStringList m_holdAddrs;         // the API edges a seat request needs while no session is open
    QStringList m_sessionAllowAddrs; // the pass table of the session that is (or was last) open
    bool m_blockHeld = false;        // the block of an ended session stays, owned by the lease
    class QTimer *m_holdTimer = nullptr;
#endif

};

#endif // KILLSWITCH_H
