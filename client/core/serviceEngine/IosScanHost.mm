// client/core/serviceEngine/IosScanHost.mm
// AVPN serviceEngine - the iOS probe host of the Scanner (IosScanHost.h): IScanHost over
// IosController::sendScanMessage, and the app process's "app" element of the strict generation tuple from its own
// nw_path_monitor. Plan scanner-client-plan.md v2.2 §2.3, §2.11a; lane L4. Compiled for iOS only
// (client/cmake/avpn.cmake, if(IOS)). This file is MRC like the other platform .mm files of the app.
//
// Nothing here touches the tunnel: no connect, no stop, no restart. A message while the extension does not run
// is answered {"error":"no_vpn"} here; the extension is never started from here (IScanHost.h).
//
// Upstream Amnezia has no counterpart.
#include "IosScanHost.h"

#include "platforms/ios/ios_controller.h"

#include <QCoreApplication>
#include <QDebug>
#include <QObject>
#include <QTimer>

#include <mutex>

#import <Foundation/Foundation.h>
#import <Network/Network.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>

namespace avpn {

// --- the app process's path monitor ("app" source) ------------------------------------------------------------

namespace {

bool iosVirtualInterfaceName(const QString &name)
{
    // The same list as PacketTunnelProvider.isVirtualInterfaceName: our utun, other VPNs, bridges.
    static const char *prefixes[] = {"utun", "ipsec", "ppp", "tun", "tap", "bridge"};
    for (const char *p : prefixes)
        if (name.startsWith(QLatin1String(p)))
            return true;
    return false;
}

QStringList iosInterfaceAddresses(const QStringList &names)
{
    QStringList out;
    if (names.isEmpty())
        return out;
    struct ifaddrs *head = nullptr;
    if (getifaddrs(&head) != 0 || !head)
        return out;
    for (struct ifaddrs *e = head; e; e = e->ifa_next) {
        if (!e->ifa_addr || !e->ifa_name)
            continue;
        const int family = e->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6)
            continue;
        const QString name = QString::fromUtf8(e->ifa_name);
        if (!names.contains(name))
            continue;
        char host[NI_MAXHOST] = {0};
        const socklen_t len = family == AF_INET ? socklen_t(sizeof(struct sockaddr_in)) : socklen_t(sizeof(struct sockaddr_in6));
        if (getnameinfo(e->ifa_addr, len, host, sizeof(host), nullptr, 0, NI_NUMERICHOST) != 0)
            continue;
        out << name + QLatin1Char('/') + QString::fromUtf8(host);
    }
    freeifaddrs(head);
    return out;
}

const char *iosInterfaceTypeName(nw_interface_type_t t)
{
    switch (t) {
    case nw_interface_type_wifi: return "wifi";
    case nw_interface_type_cellular: return "cellular";
    case nw_interface_type_wired: return "wired";
    default: return "other";
    }
}

class AppPathMonitor
{
public:
    static AppPathMonitor &instance()
    {
        static AppPathMonitor *m = new AppPathMonitor(); // lives as long as the process
        return *m;
    }

    bool element(ScanNetSource &out)
    {
        std::lock_guard<std::mutex> g(m_lock);
        if (!m_gen.seen())
            return false;
        out = m_gen.element();
        return true;
    }

    void setChanged(std::function<void()> fn)
    {
        std::lock_guard<std::mutex> g(m_lock);
        m_changed = std::move(fn);
    }

    QString kind()
    {
        std::lock_guard<std::mutex> g(m_lock);
        return m_kind;
    }

    // The most preferred physical interface of the last path (0 = none) and whether that path is usable.
    unsigned bindIndex(bool *satisfied)
    {
        std::lock_guard<std::mutex> g(m_lock);
        if (satisfied)
            *satisfied = m_satisfied;
        return m_bindIndex;
    }

private:
    AppPathMonitor() : m_gen(randomEpoch())
    {
        m_queue = dispatch_queue_create("org.tribe.scan.app-path", DISPATCH_QUEUE_SERIAL);
        m_monitor = nw_path_monitor_create();
        // Our own utun and any other VPN are type `other`: the path seen here is the physical one.
        nw_path_monitor_prohibit_interface_type(m_monitor, nw_interface_type_other);
        nw_path_monitor_set_queue(m_monitor, m_queue);
        nw_path_monitor_set_update_handler(m_monitor, ^(nw_path_t path) { observe(path); });
        nw_path_monitor_start(m_monitor);
    }

    static quint64 randomEpoch()
    {
        quint64 e = 0;
        arc4random_buf(&e, sizeof(e));
        return e;
    }

    void observe(nw_path_t path)
    {
        const bool satisfied = nw_path_get_status(path) == nw_path_status_satisfied;
        __block QStringList interfaces;
        __block QStringList names;
        __block unsigned firstIndex = 0; // enumeration order = preference order: the first one is the path's own
        nw_path_enumerate_interfaces(path, ^bool(nw_interface_t iface) {
            const nw_interface_type_t type = nw_interface_get_type(iface);
            const QString name = QString::fromUtf8(nw_interface_get_name(iface));
            if (type == nw_interface_type_loopback || type == nw_interface_type_other || iosVirtualInterfaceName(name)
                || !nw_path_uses_interface_type(path, type))
                return true;
            interfaces << QStringLiteral("%1:%2:%3").arg(QLatin1String(iosInterfaceTypeName(type)), name)
                              .arg(nw_interface_get_index(iface));
            names << name;
            if (firstIndex == 0)
                firstIndex = unsigned(nw_interface_get_index(iface));
            return true;
        });
        const QByteArray signature = iosAppPathSignature(satisfied, interfaces, iosInterfaceAddresses(names));
        std::function<void()> changed;
        {
            std::lock_guard<std::mutex> g(m_lock);
            const bool first = !m_gen.seen();
            m_kind = iosAppPathKind(interfaces); // the same interfaces the signature names
            m_bindIndex = firstIndex;
            m_satisfied = satisfied;
            if (m_gen.observe(signature) || first)
                changed = m_changed;
        }
        if (changed) {
            if (QCoreApplication *app = QCoreApplication::instance())
                QMetaObject::invokeMethod(app, [changed] { changed(); }, Qt::QueuedConnection);
        }
    }

    std::mutex m_lock;
    IosAppNetGeneration m_gen;
    QString m_kind; // iosAppPathKind of the last path
    unsigned m_bindIndex = 0; // the last path's most preferred physical interface (0 = none)
    bool m_satisfied = false;
    std::function<void()> m_changed;
    dispatch_queue_t m_queue = nullptr;
    nw_path_monitor_t m_monitor = nullptr;
};

} // namespace

bool IosScanHost::appGeneration(ScanNetSource &out) { return AppPathMonitor::instance().element(out); }

QString IosScanHost::appPathKind() { return AppPathMonitor::instance().kind(); }

unsigned IosScanHost::appBindInterfaceIndex(bool *satisfied) { return AppPathMonitor::instance().bindIndex(satisfied); }

void IosScanHost::setAppGenerationChanged(std::function<void()> onChanged)
{
    AppPathMonitor::instance().setChanged(std::move(onChanged));
}

// --- the host -------------------------------------------------------------------------------------------------

struct IosScanHost::State
{
    IosScanHost *host = nullptr;
    QObject context; // receiver of IosController's signal and the queued replies (GUI thread, no moc needed)
    bool available = false;
    bool hasGen = false;
    ScanNetSource gen;
};

IosScanHost::IosScanHost() : m_state(std::make_shared<State>())
{
    m_state->host = this;
    m_state->available = IosController::Instance()->scanHostRunning();
    AppPathMonitor::instance(); // the "app" source starts with the host
    const std::weak_ptr<State> weak = m_state;
    QObject::connect(IosController::Instance(), &IosController::connectionStateChanged, &m_state->context,
                     [weak](Vpn::ConnectionState) {
                         const std::shared_ptr<State> s = weak.lock();
                         if (!s || !s->host)
                             return;
                         const bool now = IosController::Instance()->scanHostRunning();
                         if (now == s->available)
                             return;
                         s->available = now;
                         const bool hadGen = s->hasGen;
                         if (!now)
                             s->hasGen = false; // the extension's monitor element is not known while it is down
                         IosScanHost *h = s->host;
                         if (hadGen && !now && h->onGenerationChanged)
                             h->onGenerationChanged();
                         if (h->onAvailabilityChanged)
                             h->onAvailabilityChanged();
                     });
}

IosScanHost::~IosScanHost()
{
    m_state->host = nullptr; // a late reply finds no host (its callback holds only a weak pointer)
}

ScanHostAvailability IosScanHost::availability() const
{
    return IosController::Instance()->scanHostRunning() ? ScanHostAvailability::Available : ScanHostAvailability::NeedsVpn;
}

void IosScanHost::sendMessage(const QByteArray &request, ReplyFn reply)
{
    if (!reply)
        return;
    const std::weak_ptr<State> weak = m_state;
    IosController::Instance()->sendScanMessage(
        request, iosScanReplyTimeoutMs(request),
        [weak, reply](IosController::ScanSendResult result, const QByteArray &bytes) {
            // On the controller's (GUI) thread, queued: never from inside sendMessage.
            switch (result) {
            case IosController::ScanSendResult::Reply: {
                ScanNetSource g;
                const std::shared_ptr<State> s = weak.lock();
                if (s && s->host && iosScanReplyGen(bytes, g) && (!s->hasGen || s->gen != g)) {
                    s->hasGen = true;
                    s->gen = g;
                    if (s->host->onGenerationChanged)
                        s->host->onGenerationChanged();
                }
                reply(bytes);
                return;
            }
            case IosController::ScanSendResult::NeedsVpn:
                reply(iosScanNoVpnReply());
                return;
            case IosController::ScanSendResult::NoReply:
            case IosController::ScanSendResult::Timeout:
                qWarning() << "IosScanHost: no answer from the extension"
                           << (result == IosController::ScanSendResult::Timeout ? "(timeout)" : "(no reply)");
                reply(QByteArray());
                return;
            }
        });
}

bool IosScanHost::generation(ScanNetSource &out) const
{
    if (!m_state->hasGen || !IosController::Instance()->scanHostRunning())
        return false;
    out = m_state->gen;
    return true;
}

void IosScanHost::stopAll()
{
    if (!IosController::Instance()->scanHostRunning())
        return;
    IosController::Instance()->sendScanMessage(iosScanStopAllRequest(), iosScanReplyTimeoutMs(iosScanStopAllRequest()),
                                               [](IosController::ScanSendResult, const QByteArray &) {});
}

} // namespace avpn
