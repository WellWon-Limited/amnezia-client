// AVPN (волна-3, 2026-09-28): физический аплинк на macOS через nw_path_monitor (см. UplinkMonitor.h).
#include "UplinkMonitor.h"

#include <QCoreApplication>
#include <QDebug>
#include <QMetaObject>
#include <QPointer>

#import <Network/Network.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
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
bool physicalDefaultRouteExists()
{
    int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0 };
    size_t len = 0;
    if (sysctl(mib, 6, nullptr, &len, nullptr, 0) < 0 || len == 0) return false;
    std::vector<char> buf(len);
    if (sysctl(mib, 6, buf.data(), &len, nullptr, 0) < 0) return false;
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
        return true;
    }
    return false;
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
        // Колбэк — на своей очереди; в Qt-объект только через главный поток.
        QMetaObject::invokeMethod(QCoreApplication::instance(), [self, up, reason]() {
            if (self) self->setUp(up, reason);
        }, Qt::QueuedConnection);
    });
    m_up = physicalDefaultRouteExists(); // начальное состояние до первого события
    nw_path_monitor_start(monitor);
    m_impl = monitor;
    m_authoritative = true;
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
