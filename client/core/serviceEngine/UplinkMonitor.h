#pragma once
// AVPN (волна-3, 2026-09-28): физический аплинк устройства, БЕЗ учёта собственного туннеля.
//
// Зачем: на macOS QNetworkInformation смотрит на default route, а при поднятом VPN default —
// наш же utun: через 0,4 с после activate он сообщает «online», хотя маршрут по умолчанию на en0
// вернулся только через 43 с (журнал Mac 26.09 12:43). Все решения «есть ли сеть» (учёт попыток
// старта, пауза health-loop, повтор после сна) на этом сигнале врали. Здесь — nw_path_monitor с
// запретом интерфейсов типа other (utun/ipsec/ppp): виден только реальный uplink (Wi-Fi/Ethernet/
// сотовая). На остальных платформах — QNetworkInformation (там своя логика; iOS не
// использует этот монитор для решений о намерении).
//
// Android (review round 20 R1): the same fact from the platform's own physical-network set - networks with
// NET_CAPABILITY_INTERNET and NET_CAPABILITY_NOT_VPN, kept by NetworkState.kt ScanAppNetwork and told on every
// change (UplinkMonitor.cpp). The QNetworkInformation fallback there watched the default network of our own UID,
// which IS our VPN while it exists: every teardown of our own tunnel read as "no network" for 0.2-18 s.
//
// 5.1.108 (audit of 137): iOS also asks "is there a physical network" for the §25 stop of a dead
// adopted session (IosController::setUplinkProbe). The authoritative .mm cannot build on iOS - its
// source of truth is the route table (sysctl NET_RT_DUMP, <net/route.h>), which the iPhoneOS SDK does
// not ship, and nw_path_monitor alone is not trusted under a VPN (macOS, 28.09: "unsatisfied reason 0"
// under a foreign NE VPN with a live en0). So iOS keeps the QNetworkInformation fallback, and the
// question "physical path known to exist" (physicalUp) is answered strictly: unknown = no. up() keeps
// its old lenient meaning (unknown = up: never block a start or pause health on an unknown state).
#include <QList>
#include <QObject>
#include <QString>

namespace avpn {

// Fallback (QNetworkInformation) inputs, mirrored to keep the decision pure (tested without QtNetwork).
enum class UplinkReach { Unknown, Disconnected, Local, Site, Online };
enum class UplinkMedium { Unknown, Ethernet, WiFi, Cellular, Bluetooth };

// Is a PHYSICAL path known to exist (fallback)? Reachability must be known and not Disconnected, and
// the medium must be a physical one: Unknown reachability (the backend did not answer yet / cannot
// tell) and an Unknown medium (a path over our own utun reports no physical medium) are "no".
inline bool fallbackPhysicalUp(UplinkReach reach, UplinkMedium medium)
{
    if (reach == UplinkReach::Unknown || reach == UplinkReach::Disconnected)
        return false;
    return medium == UplinkMedium::Ethernet || medium == UplinkMedium::WiFi || medium == UplinkMedium::Cellular;
}

// Android (review round 20 R1): the physical source's answer when its watch starts (NetworkState.kt
// ScanAppNetwork.watchUplink): 1 = a physical network exists, 0 = none, -1 = nothing known yet, below -1 = no
// source (its callback could not be registered: the QNetworkInformation fallback stays). Nothing known is up - the
// monitor's contract "until the first event - true"; none is down: an app started without a network waits for one.
enum class PhysicalSourceStart { Up, Down, NoSource };
inline PhysicalSourceStart physicalSourceStart(int told)
{
    if (told < -1)
        return PhysicalSourceStart::NoSource;
    return told == 0 ? PhysicalSourceStart::Down : PhysicalSourceStart::Up;
}

// Device round of 142 (B2, iPhone Air, airplane mode with the tunnel up): the Connect screen kept «Connected» with the
// amber «трафик не проходит». The tunnel is kept through a network loss by design; the screen says so when the device
// is KNOWN to have no physical network (unknown = no: the caption never guesses). The fact per platform:
//  - an authoritative monitor (macOS nw_path_monitor without utun, Android's NOT_VPN set): its own answer;
//  - iOS: the app's own path monitor with virtual interfaces prohibited (IosScanHost.mm) - a path seen and no physical
//    interface on it. The QNetworkInformation fallback follows the default path, which is our utun: in airplane mode
//    it never said Disconnected (round 142, B2: no «uplink down» for the 49 s the phone was offline);
//  - elsewhere (Windows, Linux, the macOS NE build): the fallback saying Disconnected, which under our own adapter may
//    never come - there the caption may not show.
enum class AppPathFact { None, Physical, NoPhysical }; // None = no app path monitor, or no path seen yet
inline bool physicalUplinkKnownDown(bool authoritative, bool monitorUp, AppPathFact appPath)
{
    if (authoritative)
        return !monitorUp;
    if (appPath != AppPathFact::None)
        return appPath == AppPathFact::NoPhysical;
    return !monitorUp;
}

// AVPN Scanner (plan §2.11a): the physical uplink's kind when nw_path names no interface - under the Mac's
// own VPN the virtual interfaces are prohibited and the default route is our utun, so the path's kind is
// empty. The fallback is the route table's PHYSICAL default routes (UplinkMonitor.mm): each interface with its
// medium from SystemConfiguration (802.11 -> Wifi, Ethernet -> Ethernet, anything else -> Unknown). Wired
// wins over Wi-Fi (the medium macOS prefers when both carry a default route); none known -> "". Pure.
enum class UplinkIfaceMedium { Unknown, Wifi, Ethernet };

struct UplinkRouteIface {
    QString name;                                   // BSD name ("en0")
    UplinkIfaceMedium medium = UplinkIfaceMedium::Unknown;
};

// The interface the kind is taken from ("" = none with a known medium).
inline QString uplinkPhysicalIfname(const QList<UplinkRouteIface> &ifaces)
{
    for (const UplinkRouteIface &i : ifaces)
        if (i.medium == UplinkIfaceMedium::Ethernet)
            return i.name;
    for (const UplinkRouteIface &i : ifaces)
        if (i.medium == UplinkIfaceMedium::Wifi)
            return i.name;
    return QString();
}

inline QString uplinkPhysicalKind(const QList<UplinkRouteIface> &ifaces)
{
    const QString name = uplinkPhysicalIfname(ifaces);
    for (const UplinkRouteIface &i : ifaces)
        if (i.name == name && !name.isEmpty())
            return i.medium == UplinkIfaceMedium::Ethernet ? QStringLiteral("ethernet") : QStringLiteral("wifi");
    return QString();
}

class UplinkMonitor : public QObject
{
    Q_OBJECT
public:
    static UplinkMonitor *instance();
    // true — есть физический путь в сеть (без учёта VPN-интерфейсов). До первого события — true
    // (не блокировать старт при неизвестном состоянии).
    bool up() const { return m_up; }
    // Есть ли достоверный источник (nw_path_monitor на macOS, набор физических сетей NOT_VPN на Android).
    // false — фолбэк на QNetworkInformation.
    bool authoritative() const { return m_authoritative; }
    // 5.1.108: a physical path is KNOWN to exist (unknown = false). Authoritative source - up();
    // fallback - fallbackPhysicalUp(). For decisions that must not act on an unknown state (§25 stop).
    bool physicalUp() const { return m_authoritative ? m_up : m_physicalUp; }

    // AVPN Scanner (plan scanner-client-plan.md §2.11a): the app's element of the strict local network
    // generation tuple ({"app", epoch, counter} of ScanNetworkGeneration.h). pathEpoch() = a random id chosen
    // when this monitor started (0 = no source: the fallback .cpp has none); pathCounter() grows by one on
    // every change of the physical path (status, interface set, gateway set - compared as a local hash).
    // pathKind() "wifi" | "ethernet" | "cellular" | "" and pathGatewayHash() (16 hex, "" unknown) feed the
    // weak fingerprint. Never sent anywhere.
    quint64 pathEpoch() const { return m_pathEpoch; }
    qint64 pathCounter() const { return m_pathCounter; }
    QString pathKind() const { return m_pathKind; }
    QString pathGatewayHash() const { return m_pathGatewayHash; }

#if defined(Q_OS_ANDROID)
    // Android: the physical set became empty / non-empty (ScanAppNetwork.onPhysicalUplink, any thread); applied
    // on the monitor's thread in the order told.
    static void postPhysicalUp(bool up);
#endif

signals:
    void changed(bool up);
    void pathChanged(); // AVPN Scanner: pathCounter() or the path facts moved

private:
    explicit UplinkMonitor(QObject *parent = nullptr);
    ~UplinkMonitor() override;
    void start();
    void setUp(bool up, int reason = -1);
#if defined(Q_OS_ANDROID)
    bool startPhysical();
#endif

    bool m_up = true;
    bool m_authoritative = false;
    bool m_physicalUp = false; // fallback only: fallbackPhysicalUp() of the last reading
    // AVPN Scanner: the generation source (set only by the authoritative macOS monitor).
    void setPath(const QByteArray &hash, const QString &kind, const QString &gatewayHash);
    quint64 m_pathEpoch = 0;
    qint64 m_pathCounter = 0;
    QByteArray m_pathHash;
    QString m_pathKind;
    QString m_pathGatewayHash;
    void *m_impl = nullptr; // nw_path_monitor_t на macOS
};

} // namespace avpn
