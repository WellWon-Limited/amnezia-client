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
#include <QByteArray>
#include <QCryptographicHash>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>

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

// Round mac-B (test Mac 25.11, build 141): every AmneziaWG connect looped - one leg every 1.3 s. The facts of the
// physical network (the path engine's network key, the Scanner's generation and fingerprint) came from the
// nw_path_monitor with the virtual interface type prohibited, and that path is NOT a physical fact: the same monitor
// reads, measured on the test Mac (netfacts, hashes only):
//   own Xray (tun2socks utun, split routes 1/8..128/1)   status 1 (satisfied), interfaces en0, gateways = the router
//   own AmneziaWG (utun, 0/1 + 128/1)                     status 2 (unsatisfied), interfaces utun4 + en0, NO gateway
// so the key moved from wifi:<router|subnet> to wifi:<|subnet> the moment our own tunnel came up, the attempt owner
// took it for a new network, restarted the leg, the tunnel went down and the key came back. A foreign VPN's tunnel
// does the same to that path (28.09: "unsatisfied reason 0" under an NE VPN with a live en0).
// The rule: the facts are read only from sources that describe the physical network and that no tunnel - ours of
// any transport or another app's - writes:
//  - the routers of the physical network services (SystemConfiguration State:/Network/Service/<id>/IPv4: Router
//    with its InterfaceName, a physical interface only): the configuration the physical network gave the Mac
//    (DHCP or manual). Neither our daemon nor tun2socks registers a service; another app's VPN service has a
//    virtual interface (utun, ipsec, ppp) and is left out. Measured unchanged while AmneziaWG and Xray were up;
//  - the physical default routes of the route table (interface names only: the same interface keeps a default
//    route under our tunnel, scoped or not);
//  - the kind: the path's physical interface type when it names one, else the route table's (uplinkPhysicalKind).
// The path's status, its interface list and its gateways are not read: they follow the tunnel.
// Raw values never leave the device: the facts are hashes (gatewayHash: 16 hex of the sorted "ifname=router").
// A virtual interface (a VPN's or a system tunnel's) - never a physical network (the prefixes of UplinkMonitor.mm and
// the service's route monitor).
inline bool uplinkIfnameVirtual(const QString &name)
{
    static const char *const prefixes[] = {"utun", "ipsec", "ppp", "gif", "stf", "bridge", "awdl", "llw"};
    for (const char *p : prefixes)
        if (name.startsWith(QLatin1String(p)))
            return true;
    return false;
}

struct UplinkReading {
    QString pathKind;                   // "wifi" | "ethernet" | "cellular" | "" (nw_path_uses_interface_type)
    QList<UplinkRouteIface> routeIfaces; // the route table's physical default routes, their medium
    QStringList serviceRouters;          // "ifname=router" of every network service with a router (virtual ones too)
    // tunnel-dependent, NOT read by uplinkPhysicalFacts (kept in the reading so the tests can feed what the path
    // really said under each tunnel)
    int pathStatus = 0;                  // nw_path_get_status
    QStringList pathInterfaces;          // nw_path_enumerate_interfaces (physical names, "en0/1/<index>")
    QStringList pathGateways;            // nw_path_enumerate_gateways (hex of the sockaddr)
};

struct UplinkPhysicalFacts {
    QByteArray hash;     // the local identity of the physical network (the Scanner's "app" generation element)
    QString kind;        // "wifi" | "ethernet" | "cellular" | ""
    QString gatewayHash; // 16 hex of the physical routers, "" = none known
};

inline UplinkPhysicalFacts uplinkPhysicalFacts(const UplinkReading &r)
{
    UplinkPhysicalFacts f;
    f.kind = !r.pathKind.isEmpty() ? r.pathKind : uplinkPhysicalKind(r.routeIfaces);
    QStringList routeIfnames;
    for (const UplinkRouteIface &i : r.routeIfaces)
        if (!routeIfnames.contains(i.name))
            routeIfnames << i.name;
    routeIfnames.sort();
    QStringList routers;
    for (const QString &sr : r.serviceRouters)
        if (!uplinkIfnameVirtual(sr.section(QLatin1Char('='), 0, 0)) && !routers.contains(sr))
            routers << sr; // another app's VPN service (utun, ipsec, ppp) is not the physical network
    routers.sort();
    const QString in = f.kind + QLatin1Char('|') + routeIfnames.join(QLatin1Char(',')) + QLatin1Char('|')
                       + routers.join(QLatin1Char(','));
    f.hash = QCryptographicHash::hash(in.toUtf8(), QCryptographicHash::Sha256);
    if (!routers.isEmpty())
        f.gatewayHash = QString::fromLatin1(
            QCryptographicHash::hash(routers.join(QLatin1Char(',')).toUtf8(), QCryptographicHash::Sha256).toHex().left(16));
    return f;
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
    // every change of the physical network (uplinkPhysicalFacts: kind, physical default-route interfaces, physical
    // routers - compared as a local hash; never the path's status, interfaces or gateways, which follow the tunnel).
    // pathKind() "wifi" | "ethernet" | "cellular" | "" and pathGatewayHash() (16 hex, "" unknown) feed the
    // weak fingerprint and the path engine's network key. Never sent anywhere.
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
    void setPath(const QByteArray &hash, const QString &kind, const QString &gatewayHash, const UplinkReading &reading);
    QString m_pathSeen; // the last journal line of what the path said (round mac-B)
    quint64 m_pathEpoch = 0;
    qint64 m_pathCounter = 0;
    QByteArray m_pathHash;
    QString m_pathKind;
    QString m_pathGatewayHash;
    void *m_impl = nullptr; // nw_path_monitor_t на macOS
};

} // namespace avpn
