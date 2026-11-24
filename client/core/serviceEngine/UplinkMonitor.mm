// AVPN (волна-3, 2026-09-28): физический аплинк на macOS через nw_path_monitor (см. UplinkMonitor.h).
#include "UplinkMonitor.h"

#include <QCoreApplication>
#include <QDebug>
#include <QMetaObject>
#include <QPointer>
#include <QRandomGenerator>
#include <QStringList>

#import <Network/Network.h>
#import <SystemConfiguration/SystemConfiguration.h>

#include <errno.h>
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
// Round mac-B (25.11): while a tunnel installs its routes (AmneziaWG: the bypass list, thousands of routes) the table
// grows between the size query and the dump, and the dump fails with ENOMEM - measured on nearly every AmneziaWG leg
// (netfacts: the table unreadable for ~0.25 s). A failed read is not "no default route": the dump is retried with
// the new size, as route(8) and netstat(1) do.
bool dumpRouteTable(std::vector<char> &buf)
{
    int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0 };
    for (int attempt = 0; attempt < 8; ++attempt) {
        size_t len = 0;
        if (sysctl(mib, 6, nullptr, &len, nullptr, 0) < 0 || len == 0)
            return false;
        len += len / 8 + 4096; // room for what is added before the dump
        buf.assign(len, 0);
        if (sysctl(mib, 6, buf.data(), &len, nullptr, 0) == 0) {
            buf.resize(len);
            return true;
        }
        if (errno != ENOMEM)
            return false;
    }
    return false;
}

std::vector<std::string> physicalDefaultRouteIfnames()
{
    std::vector<std::string> out;
    std::vector<char> buf;
    if (!dumpRouteTable(buf)) return out;
    const size_t len = buf.size();
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

QString cfString(CFTypeRef v)
{
    if (!v || CFGetTypeID(v) != CFStringGetTypeID())
        return QString();
    return QString::fromCFString(static_cast<CFStringRef>(v));
}

// The routers the networks gave the Mac (UplinkMonitor.h uplinkPhysicalFacts keeps the physical ones): every
// per-service IPv4 state (SCDynamicStoreKeyCreateNetworkServiceEntity(State, any service, IPv4): kSCPropNetIPv4Router
// with kSCPropInterfaceName), as "ifname=router".
QStringList physicalServiceRouters()
{
    QStringList out;
    SCDynamicStoreRef store = SCDynamicStoreCreate(nullptr, CFSTR("hk.wellwon.vpn.uplink"), nullptr, nullptr);
    if (!store)
        return out;
    CFStringRef pattern = SCDynamicStoreKeyCreateNetworkServiceEntity(nullptr, kSCDynamicStoreDomainState, kSCCompAnyRegex,
                                                                      kSCEntNetIPv4);
    CFArrayRef patterns = CFArrayCreate(nullptr, reinterpret_cast<const void **>(&pattern), 1, &kCFTypeArrayCallBacks);
    CFDictionaryRef all = SCDynamicStoreCopyMultiple(store, nullptr, patterns);
    if (all) {
        const CFIndex n = CFDictionaryGetCount(all);
        std::vector<const void *> values(size_t(n), nullptr);
        CFDictionaryGetKeysAndValues(all, nullptr, values.data());
        for (const void *v : values) {
            if (!v || CFGetTypeID(v) != CFDictionaryGetTypeID())
                continue;
            CFDictionaryRef ipv4 = static_cast<CFDictionaryRef>(v);
            const QString ifname = cfString(CFDictionaryGetValue(ipv4, kSCPropInterfaceName));
            const QString router = cfString(CFDictionaryGetValue(ipv4, kSCPropNetIPv4Router));
            if (ifname.isEmpty() || router.isEmpty())
                continue; // a virtual service's router is dropped by uplinkPhysicalFacts
            out << ifname + QLatin1Char('=') + router;
        }
        CFRelease(all);
    }
    CFRelease(patterns);
    CFRelease(pattern);
    CFRelease(store);
    return out;
}

// The reading of one path update (UplinkMonitor.h UplinkReading): the facts come from uplinkPhysicalFacts, which
// reads the physical sources only; the path's own status, interfaces and gateways ride along for the journal line.
UplinkReading readingOf(nw_path_t path)
{
    UplinkReading r;
    __block QStringList ifaces;
    nw_path_enumerate_interfaces(path, ^bool(nw_interface_t iface) {
        const char *name = nw_interface_get_name(iface);
        if (name && !isVirtualIfname(name))
            ifaces << QString::fromLatin1(name) + QLatin1Char('/') + QString::number(int(nw_interface_get_type(iface)))
                          + QLatin1Char('/') + QString::number(nw_interface_get_index(iface));
        return true;
    });
    ifaces.sort();
    r.pathInterfaces = ifaces;
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
    r.pathGateways = gateways;
    r.pathStatus = int(nw_path_get_status(path));
    if (nw_path_uses_interface_type(path, nw_interface_type_wifi))
        r.pathKind = QStringLiteral("wifi");
    else if (nw_path_uses_interface_type(path, nw_interface_type_wired))
        r.pathKind = QStringLiteral("ethernet");
    else if (nw_path_uses_interface_type(path, nw_interface_type_cellular))
        r.pathKind = QStringLiteral("cellular");
    r.routeIfaces = physicalRouteIfaces();
    r.serviceRouters = physicalServiceRouters();
    return r;
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
        // AVPN Scanner: the generation source (§2.11a); round mac-B: physical sources only (uplinkPhysicalFacts)
        const UplinkReading reading = readingOf(path);
        const UplinkPhysicalFacts facts = uplinkPhysicalFacts(reading);
        // Колбэк — на своей очереди; в Qt-объект только через главный поток.
        QMetaObject::invokeMethod(QCoreApplication::instance(), [self, up, reason, facts, reading]() {
            if (!self) return;
            self->setPath(facts.hash, facts.kind, facts.gatewayHash, reading);
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
void UplinkMonitor::setPath(const QByteArray &hash, const QString &kind, const QString &gatewayHash,
                            const UplinkReading &reading)
{
    // One line per change of what the path itself says (round mac-B: our own tunnel moves it; the facts do not):
    // the path's status and interfaces, whether it lists a gateway, and the physical facts' short hash.
    const QString seen = QStringLiteral("status=%1 ifaces=%2 path_gateways=%3 facts=%4 kind=%5 routers=%6")
                             .arg(reading.pathStatus)
                             .arg(reading.pathInterfaces.size())
                             .arg(reading.pathGateways.size())
                             .arg(QString::fromLatin1(hash.toHex().left(8)), kind.isEmpty() ? QStringLiteral("-") : kind)
                             .arg(reading.serviceRouters.size());
    if (seen != m_pathSeen) {
        m_pathSeen = seen;
        qInfo().noquote() << "[uplink] path" << seen;
    }
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
