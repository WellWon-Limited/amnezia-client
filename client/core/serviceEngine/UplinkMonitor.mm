// AVPN (волна-3, 2026-09-28): физический аплинк на macOS через nw_path_monitor (см. UplinkMonitor.h).
#include "UplinkMonitor.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDebug>
#include <QMetaObject>
#include <QPointer>
#include <QRandomGenerator>
#include <QStringList>

#import <Network/Network.h>
#import <SystemConfiguration/SystemConfiguration.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <algorithm>
#include <string>
#include <vector>

namespace avpn {

namespace {
// Виртуальные интерфейсы (VPN/туннели) путём в интернет не считаются.
bool isVirtualIfname(const char* ifname)
{
    static const char* const prefixes[] = { "utun", "ipsec", "ppp", "gif", "stf", "bridge", "awdl", "llw" };
    for (const char* p : prefixes)
        if (strncmp(ifname, p, strlen(p)) == 0) return true;
    return false;
}
inline size_t saRoundUp(size_t len) { return len > 0 ? (1 + ((len - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t); }

// Есть ли в таблице маршрутов default (в т.ч. scoped, RTF_IFSCOPE) через ФИЗИЧЕСКИЙ интерфейс с
// IP-шлюзом. Это тот же критерий, что у монитора демона. nw_path_monitor под чужим NE-VPN
// (Happ, Tailscale) отвечает «unsatisfied» на всё физическое (замер 28.09: reason 0 при живом en0),
// поэтому таблица маршрутов — источник правды, nw_path — только триггер пересчёта.
// AVPN Scanner: the same walk, every physical default route's interface name (unique, route-table order).
std::vector<std::string> physicalDefaultRouteIfnames()
{
    int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0 };
    size_t len = 0;
    std::vector<std::string> out;
    if (sysctl(mib, 6, nullptr, &len, nullptr, 0) < 0 || len == 0) return out;
    std::vector<char> buf(len);
    if (sysctl(mib, 6, buf.data(), &len, nullptr, 0) < 0) return out;
    for (char* p = buf.data(); p < buf.data() + len;) {
        const rt_msghdr* rtm = reinterpret_cast<const rt_msghdr*>(p);
        if (rtm->rtm_msglen == 0) break;
        p += rtm->rtm_msglen;
        if (!(rtm->rtm_flags & RTF_UP) || !(rtm->rtm_flags & RTF_GATEWAY)) continue;
        if (!(rtm->rtm_addrs & RTA_DST) || !(rtm->rtm_addrs & RTA_GATEWAY)) continue;
        const char* sa = reinterpret_cast<const char*>(rtm + 1);
        const sockaddr *dst = nullptr, *gw = nullptr, *mask = nullptr;
        for (int i = 0; i < RTAX_MAX; ++i) {
            if (!(rtm->rtm_addrs & (1 << i))) continue;
            const sockaddr* s = reinterpret_cast<const sockaddr*>(sa);
            if (i == RTAX_DST) dst = s; else if (i == RTAX_GATEWAY) gw = s; else if (i == RTAX_NETMASK) mask = s;
            sa += saRoundUp(s->sa_len);
        }
        if (!dst || dst->sa_family != AF_INET) continue;
        if (reinterpret_cast<const sockaddr_in*>(dst)->sin_addr.s_addr != 0) continue;
        if (mask && mask->sa_len >= 8 && reinterpret_cast<const sockaddr_in*>(mask)->sin_addr.s_addr != 0) continue;
        if (!gw || gw->sa_family != AF_INET) continue;
        char ifn[IF_NAMESIZE] = { 0 };
        if (!if_indextoname(rtm->rtm_index, ifn)) continue;
        if (isVirtualIfname(ifn)) continue;
        if (std::find(out.begin(), out.end(), std::string(ifn)) == out.end())
            out.emplace_back(ifn);
    }
    return out;
}

bool physicalDefaultRouteExists() { return !physicalDefaultRouteIfnames().empty(); }

// AVPN Scanner (plan §2.11a): the physical path as a local hash (status + physical interfaces + gateways), its
// kind and a hash of the gateways. Read on the monitor's queue; nothing leaves the device.
// AVPN Scanner: an interface's medium from SystemConfiguration (802.11 -> Wifi, Ethernet -> Ethernet).
UplinkIfaceMedium mediumOfIfname(const std::string &bsd)
{
    UplinkIfaceMedium m = UplinkIfaceMedium::Unknown;
    CFArrayRef all = SCNetworkInterfaceCopyAll();
    if (!all)
        return m;
    for (CFIndex i = 0; i < CFArrayGetCount(all) && m == UplinkIfaceMedium::Unknown; ++i) {
        SCNetworkInterfaceRef ni = static_cast<SCNetworkInterfaceRef>(CFArrayGetValueAtIndex(all, i));
        CFStringRef name = SCNetworkInterfaceGetBSDName(ni);
        if (!name)
            continue;
        char buf[IF_NAMESIZE] = { 0 };
        if (!CFStringGetCString(name, buf, sizeof buf, kCFStringEncodingUTF8) || bsd != buf)
            continue;
        CFStringRef type = SCNetworkInterfaceGetInterfaceType(ni);
        if (type && CFEqual(type, kSCNetworkInterfaceTypeIEEE80211))
            m = UplinkIfaceMedium::Wifi;
        else if (type && CFEqual(type, kSCNetworkInterfaceTypeEthernet))
            m = UplinkIfaceMedium::Ethernet;
    }
    CFRelease(all);
    return m;
}

QList<UplinkRouteIface> physicalRouteIfaces()
{
    QList<UplinkRouteIface> out;
    for (const std::string &n : physicalDefaultRouteIfnames())
        out << UplinkRouteIface{QString::fromStdString(n), mediumOfIfname(n)};
    return out;
}

struct PathFacts {
    QByteArray hash;
    QString kind;
    QString gatewayHash;
};

PathFacts pathFactsOf(nw_path_t path)
{
    PathFacts f;
    __block QStringList ifaces;
    nw_path_enumerate_interfaces(path, ^bool(nw_interface_t iface) {
        const char *name = nw_interface_get_name(iface);
        if (name && !isVirtualIfname(name))
            ifaces << QString::fromLatin1(name) + QLatin1Char('/') + QString::number(int(nw_interface_get_type(iface)))
                          + QLatin1Char('/') + QString::number(nw_interface_get_index(iface));
        return true;
    });
    ifaces.sort();
    __block QStringList gateways;
    if (@available(macOS 13.0, *)) {
        nw_path_enumerate_gateways(path, ^bool(nw_endpoint_t gw) {
            const sockaddr *sa = nw_endpoint_get_address(gw);
            if (sa)
                gateways << QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(sa), sa->sa_len).toHex());
            return true;
        });
    }
    gateways.sort();
    if (nw_path_uses_interface_type(path, nw_interface_type_wifi))
        f.kind = QStringLiteral("wifi");
    else if (nw_path_uses_interface_type(path, nw_interface_type_wired))
        f.kind = QStringLiteral("ethernet");
    else if (nw_path_uses_interface_type(path, nw_interface_type_cellular))
        f.kind = QStringLiteral("cellular");
    // Under the Mac's own VPN the path names no interface (virtual ones are prohibited, the default route is
    // our utun): the kind comes from the route table's PHYSICAL default route, and its interface joins the
    // hash, so a switch between two physical uplinks under the tunnel counts as a path change.
    QString routeIf;
    if (f.kind.isEmpty()) {
        const QList<UplinkRouteIface> route = physicalRouteIfaces();
        f.kind = uplinkPhysicalKind(route);
        routeIf = uplinkPhysicalIfname(route);
    }
    const QString in = QString::number(int(nw_path_get_status(path))) + QLatin1Char('|') + ifaces.join(QLatin1Char(','))
                       + QLatin1Char('|') + gateways.join(QLatin1Char(',')) + QLatin1Char('|') + routeIf;
    f.hash = QCryptographicHash::hash(in.toUtf8(), QCryptographicHash::Sha256);
    if (!gateways.isEmpty())
        f.gatewayHash = QString::fromLatin1(QCryptographicHash::hash(gateways.join(QLatin1Char(',')).toUtf8(), QCryptographicHash::Sha256).toHex().left(16));
    return f;
}
} // namespace

UplinkMonitor *UplinkMonitor::instance()
{
    static UplinkMonitor *s_instance = new UplinkMonitor(QCoreApplication::instance());
    return s_instance;
}

UplinkMonitor::UplinkMonitor(QObject *parent) : QObject(parent)
{
    start();
}

UplinkMonitor::~UplinkMonitor()
{
    if (m_impl) {
        nw_path_monitor_cancel((nw_path_monitor_t)m_impl);
        nw_release((nw_path_monitor_t)m_impl);
        m_impl = nullptr;
    }
}

void UplinkMonitor::start()
{
    nw_path_monitor_t monitor = nw_path_monitor_create();
    if (!monitor) {
        qWarning() << "[uplink] nw_path_monitor_create failed — fallback to QNetworkInformation";
        return;
    }
    // Ключевое: интерфейсы типа other (utun/ipsec/ppp) не считаются путём в сеть. Пока VPN поднят,
    // монитор оценивает оставшиеся физические интерфейсы — это и есть «есть ли у Mac сеть».
    nw_path_monitor_prohibit_interface_type(monitor, nw_interface_type_other);
    dispatch_queue_t queue = dispatch_queue_create("hk.wellwon.vpn.uplink", DISPATCH_QUEUE_SERIAL);
    nw_path_monitor_set_queue(monitor, queue);
    QPointer<UplinkMonitor> self(this);
    nw_path_monitor_set_update_handler(monitor, ^(nw_path_t path) {
        const nw_path_status_t st = nw_path_get_status(path);
        bool up = st == nw_path_status_satisfied;
        int reason = -1;
        if (!up && st == nw_path_status_unsatisfied) {
            if (@available(macOS 14.0, *)) {
                reason = int(nw_path_get_unsatisfied_reason(path));
                if (reason == int(nw_path_unsatisfied_reason_vpn_inactive))
                    up = true; // «требуется VPN» — сеть есть
            }
        }
        // Источник правды — таблица маршрутов (см. physicalDefaultRouteExists); nw_path — триггер.
        if (!up)
            up = physicalDefaultRouteExists();
        const PathFacts facts = pathFactsOf(path); // AVPN Scanner: the generation source (§2.11a)
        // Колбэк — на своей очереди; в Qt-объект только через главный поток.
        QMetaObject::invokeMethod(QCoreApplication::instance(), [self, up, reason, facts]() {
            if (!self) return;
            self->setPath(facts.hash, facts.kind, facts.gatewayHash);
            self->setUp(up, reason);
        }, Qt::QueuedConnection);
    });
    m_up = physicalDefaultRouteExists(); // начальное состояние до первого события
    m_pathEpoch = QRandomGenerator::global()->generate64() | 1; // AVPN Scanner: a new epoch per monitor start
    nw_path_monitor_start(monitor);
    m_impl = monitor;
    m_authoritative = true;
}

// AVPN Scanner: the first reading of an epoch sets the hash; every later change of it counts one.
void UplinkMonitor::setPath(const QByteArray &hash, const QString &kind, const QString &gatewayHash)
{
    if (hash == m_pathHash && kind == m_pathKind && gatewayHash == m_pathGatewayHash)
        return;
    if (!m_pathHash.isEmpty() && hash != m_pathHash)
        ++m_pathCounter;
    m_pathHash = hash;
    m_pathKind = kind;
    m_pathGatewayHash = gatewayHash;
    emit pathChanged();
}

void UplinkMonitor::setUp(bool up, int reason)
{
    if (m_up == up)
        return;
    m_up = up;
    qInfo() << "[uplink]" << (up ? "up" : "down") << "reason" << reason;
    emit changed(up);
}

} // namespace avpn
