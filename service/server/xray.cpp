#include "xray.h"
#include "tribe_scan.h" // AVPN (round mac-D3): the Xray routes' ownership record
#include "core/utils/networkUtilities.h"
#ifdef Q_OS_MAC
#include "router_mac.h"
#endif

#include <QDebug>
#include <QNetworkInterface>
#include <QCoreApplication>
#include <amnezia_xray.h>
#include <qdebug.h>

#ifdef Q_OS_DARWIN
    #include <arpa/inet.h>
    #include <cerrno>
    #include <cstddef>
    #include <cstdint>
    #include <cstring>
    #include <ifaddrs.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <sys/socket.h>
#endif
#ifdef Q_OS_WIN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    // AVPN (upstream nodes): ConvertInterfaceAliasToLuid + GetIfEntry2 (netioapi.h, pulled in by
    // iphlpapi.h; same include order as router_win.h); the service links iphlpapi (CMakeLists LIBS).
    #include <iphlpapi.h>
#endif
#ifdef Q_OS_LINUX
    #include <sys/socket.h>
    #include "xray_defs.h"
#endif

// AVPN: чтение сырых счётчиков интерфейса tun2socks для runtimeStatus (macOS-демон).
#include <QDateTime>
#include "xrayassets.h" // AVPN: geo data only from the service's own directory
#include <QRegularExpression>

namespace {

struct IfaceCounters {
    bool found = false;
    quint64 rxBytes = 0;
    quint64 txBytes = 0;
};

#ifdef Q_OS_MACOS
// Дефолт = tunName из client/core/protocols/xrayProtocol.cpp (macOS); клиент обязан передавать
// фактическое имя, дефолт — страховка для пустого хинта.
const char kDefaultXrayTunIface[] = "utun22";

IfaceCounters readIfaceCounters(const QString &ifaceName)
{
    IfaceCounters result;
    if (ifaceName.isEmpty()) {
        return result;
    }
    ifaddrs *addresses = nullptr;
    if (getifaddrs(&addresses) != 0 || addresses == nullptr) {
        return result;
    }
    const QByteArray wanted = ifaceName.toLocal8Bit();
    for (const ifaddrs *entry = addresses; entry != nullptr; entry = entry->ifa_next) {
        // AF_LINK-запись несёт if_data; у AF_INET/AF_INET6 того же имени ifa_data пуст.
        if (entry->ifa_name == nullptr || entry->ifa_data == nullptr
            || entry->ifa_addr == nullptr || entry->ifa_addr->sa_family != AF_LINK
            || wanted != entry->ifa_name) {
            continue;
        }
        const auto *data = static_cast<const if_data *>(entry->ifa_data);
        result.found = true;
        result.rxBytes = data->ifi_ibytes;
        result.txBytes = data->ifi_obytes;
        break;
    }
    freeifaddrs(addresses);
    return result;
}
#endif

#ifdef Q_OS_WIN
// AVPN (upstream nodes): default = tunName of client/core/protocols/xrayProtocol.cpp on Windows.
// tun2socks "-device tun://tun2" creates a wintun adapter whose alias is "tun2"; the same alias is
// what RouterWin::createTun and DnsUtilsWindows::updateResolvers resolve for this tunnel.
const char kDefaultXrayTunIface[] = "tun2";

// Raw counters of the wintun adapter, resolved alias -> LUID on every call: tun2socks recreates
// the adapter (a new LUID) when it restarts, so a LUID or an index kept from an earlier call could
// name a gone or a reused interface. Both calls are local IP Helper queries (no network I/O).
IfaceCounters readIfaceCounters(const QString &ifaceAlias)
{
    IfaceCounters result;
    if (ifaceAlias.isEmpty()) {
        return result;
    }
    NET_LUID luid = {};
    if (ConvertInterfaceAliasToLuid(reinterpret_cast<const wchar_t *>(ifaceAlias.utf16()), &luid) != NO_ERROR) {
        return result; // no adapter with this alias: tunnel not up yet or already torn down
    }
    MIB_IF_ROW2 row = {};
    row.InterfaceLuid = luid;
    if (GetIfEntry2(&row) != NO_ERROR) {
        return result; // the adapter vanished between the two calls
    }
    result.found = true;
    // In = packets tun2socks writes into the adapter (from the tunnel), Out = packets the system
    // sends into it (into the tunnel): the same directions as ifi_ibytes/ifi_obytes of utun on macOS.
    result.rxBytes = row.InOctets;
    result.txBytes = row.OutOctets;
    return result;
}
#endif

// Имя интерфейса от клиента: только [A-Za-z0-9] до IFNAMSIZ-1 (16), иначе игнорируем хинт.
bool isSaneIfaceName(const QString &name)
{
    static const QRegularExpression re(QStringLiteral("^[A-Za-z0-9]{1,15}$"));
    return re.match(name).hasMatch();
}

} // namespace

bool Xray::startXray(const QString &cfg)
{
    qDebug() << "Xray::startXray()";
#ifdef Q_OS_MACOS
    // AVPN: a start runs only on a closed core. The bindings keep one instance and configure
    // overwrites it without closing it (xraysession.h), so an instance still open here would keep its
    // inbound, its outbound connections and the uplink routes beside the new one.
    if (m_core.beforeStart() == avpn::XrayCoreSession::StartStep::CloseOpenFirst) {
        qWarning() << "[xray] start: the previous core instance is still open - closing it first";
        stopXray();
    }
#endif
    // AVPN (upstream nodes): never let the core fall back to a foreign geo copy (xrayassets.h).
    if (const QStringList missing = avpn::xrayMissingAssets(cfg, QCoreApplication::applicationDirPath());
        !missing.isEmpty()) {
        qWarning() << "[xray] refusing config: asset files missing next to the service:" << missing;
        return false;
    }
    const auto gatewayAndIface = NetworkUtilities::getGatewayAndIface();
    const QString defaultGateway = gatewayAndIface.first;
    const QNetworkInterface defaultIface = gatewayAndIface.second;
#ifdef Q_OS_LINUX
    m_defaultIfaceName = defaultIface.name().toUtf8();
#else
    m_defaultIfaceIdx = defaultIface.index();
#endif
    if (defaultIface.index() > 0) {
        qDebug() << "[xray] using uplink interface:" << defaultIface.name() << "(" << defaultIface.index() << ")";
    }
#ifdef Q_OS_MACOS
    // AVPN (diag): getGatewayAndIface (macOS) scans the IPv4 routes, then the IPv6 ones, and an IPv6
    // gateway route of the second pass overwrites the IPv4 default (gateway AND interface index) - then
    // routeAddXray gets an IPv6 gateway for its IPv4 routes.
    qDebug() << "[xray] uplink gateway family:"
             << (defaultGateway.isEmpty() ? "none" : (defaultGateway.contains(QLatin1Char(':')) ? "v6" : "v4"));
    m_bindOk = 0;
    m_bindFailed = 0;
    m_bindFirstErrno = 0;
    m_droppedInfoLines = 0;
#endif

#ifdef Q_OS_MAC
    m_uplinkIfaceName = defaultIface.name();
    m_uplinkGateway = defaultGateway;
    if (!m_uplinkIfaceName.isEmpty()) {
        // AVPN (round mac-D3): the pair is recorded before it is added, so a service killed under this session removes
        // it at its next start (tribe_scan.h kTribeXrayRoutesRecord) instead of leaving it to a later session.
        if (!avpn::tribeXrayRoutesWillBeAdded(m_uplinkIfaceName, m_uplinkGateway))
            qWarning() << "[xray] the uplink routes could not be recorded (not IPv4, or the record is not writable)";
        const bool installed = RouterMac::Instance().routeAddXray(m_uplinkIfaceName, m_uplinkGateway);
        if (!installed) {
            qWarning() << "[xray] failed to install xray routes on" << m_uplinkIfaceName;
        }
    }
#endif

    if (auto err = amnezia_xray_setsockcallback(ctxSockCallback, this); err != nullptr) {
        qDebug() << "[xray] sockopt failed: " << err;
        amnezia_xray_free(err);
        return false;
    }

    amnezia_xray_setloghandler(ctxLogHandler, this);

#ifdef Q_OS_MACOS
    // AVPN (diag): with the service log on, the core reports its failed dials and DNS failures
    // (Info level); only those Info lines reach the log (logHandler).
    const avpn::XrayDiagConfig diag = avpn::xrayDiagConfig(cfg, m_diagnostics);
    m_levelRaised = diag.raised;
    qDebug().noquote() << "[xray] core config:" << avpn::xrayConfigSummary(diag.config, diag.level)
                       << (diag.raised ? "(level raised for the service log)" : "");
    QByteArray bytes = diag.config.toUtf8();
#else
    QByteArray bytes = cfg.toUtf8();
#endif
    if (auto err = amnezia_xray_configure(bytes.data()); err != nullptr) {
        qDebug() << "[xray] configuration failed: " << err;
        amnezia_xray_free(err);
        return false;
    }
#ifdef Q_OS_MACOS
    m_core.onConfigured(); // AVPN: from here the instance holds features and is closed exactly once
#endif

    if (auto err = amnezia_xray_start(); err != nullptr) {
        qDebug() << "[xray] failed to start: " << err;
        amnezia_xray_free(err);
        return false;
    }

    // AVPN: новая сессия — свежий аккумулятор (база = первый замер в runtimeStatus).
    m_running = true;
    m_startedAtMs = QDateTime::currentMSecsSinceEpoch();
    m_since.start();
    m_traffic.reset();

    return true;
}

bool Xray::stopXray()
{
    qDebug() << "Xray::stopXray()";
    // AVPN: сессия закрыта запросом клиента — статистика дальше не копится.
    m_running = false;
    bool success = true;
#ifdef Q_OS_MACOS
    // AVPN: one close per instance (xraysession.h). XrayProtocol stops twice (its failover stop, then
    // its destructor); the second close of the same instance made the core answer "inbound: failed to
    // close all resources" although the first close had succeeded.
    const bool closeCore = m_core.beforeStop() == avpn::XrayCoreSession::StopStep::Close;
    if (!closeCore) {
        qDebug() << "[xray] stop: no open core instance - nothing to close";
    }
#else
    const bool closeCore = true;
#endif
    if (closeCore) {
        if (auto err = amnezia_xray_stop(); err != nullptr) {
            qDebug() << "[xray] failed to stop: " << err;
            amnezia_xray_free(err);
            success = false;
        }
#ifdef Q_OS_MACOS
        m_core.onClosed();
        if (success) {
            qDebug() << "[xray] core instance closed";
        }
        // AVPN (diag): how the core's sockets were pinned to the uplink this session.
        qDebug() << "[xray] session sockets bound to the uplink: ok" << m_bindOk.load() << "failed" << m_bindFailed.load()
                 << "first errno" << m_bindFirstErrno.load() << "| core info lines filtered out:" << m_droppedInfoLines.load();
        m_levelRaised = false;
#endif
    }

#ifdef Q_OS_MAC
    if (!m_uplinkIfaceName.isEmpty()) {
        RouterMac::Instance().routeDeleteXray(m_uplinkIfaceName, m_uplinkGateway);
        avpn::tribeXrayRoutesDeleted(); // AVPN (round mac-D3)
    }
    m_uplinkIfaceName.clear();
    m_uplinkGateway.clear();
#endif

    return success;
}

// AVPN
QJsonObject Xray::runtimeStatus(const QString &ifaceHint)
{
    QJsonObject status;
    status.insert(QStringLiteral("running"), m_running);
    status.insert(QStringLiteral("since_ms"), m_running ? static_cast<qint64>(m_since.elapsed()) : 0);
    status.insert(QStringLiteral("started_at_ms"), m_running ? m_startedAtMs : 0);

    QString iface = isSaneIfaceName(ifaceHint) ? ifaceHint : QString();
#ifdef Q_OS_MACOS
    if (iface.isEmpty()) {
        iface = QString::fromLatin1(kDefaultXrayTunIface);
    }
    status.insert(QStringLiteral("unsupported"), false);
    status.insert(QStringLiteral("source"), QStringLiteral("darwin_getifaddrs_if_data"));
    IfaceCounters counters;
    if (m_running) {
        counters = readIfaceCounters(iface);
        if (counters.found) {
            m_traffic.sample(counters.rxBytes, counters.txBytes);
        }
    }
    status.insert(QStringLiteral("iface_found"), counters.found);
#elif defined(Q_OS_WIN)
    // AVPN (upstream nodes): the wintun adapter of tun2socks, same contract as the macOS branch
    // (cumulative since the session start, reset-safe; no adapter = iface_found false, not unsupported).
    if (iface.isEmpty()) {
        iface = QString::fromLatin1(kDefaultXrayTunIface);
    }
    status.insert(QStringLiteral("unsupported"), false);
    status.insert(QStringLiteral("source"), QStringLiteral("windows_getifentry2"));
    IfaceCounters counters;
    if (m_running) {
        counters = readIfaceCounters(iface);
        if (counters.found) {
            m_traffic.sample(counters.rxBytes, counters.txBytes);
        }
    }
    status.insert(QStringLiteral("iface_found"), counters.found);
#else
    // Linux: no counter source for the tun2socks interface - honest zeros + unsupported.
    status.insert(QStringLiteral("unsupported"), true);
    status.insert(QStringLiteral("source"), QStringLiteral("unavailable"));
    status.insert(QStringLiteral("iface_found"), false);
#endif
    status.insert(QStringLiteral("iface"), iface);
    status.insert(QStringLiteral("rx_bytes"), static_cast<qint64>(m_running ? m_traffic.totalRx : 0));
    status.insert(QStringLiteral("tx_bytes"), static_cast<qint64>(m_running ? m_traffic.totalTx : 0));
    status.insert(QStringLiteral("resets"), static_cast<qint64>(m_running ? m_traffic.resets : 0));
    return status;
}

void Xray::logHandler(char* str)
{
    // AVPN (diag): an Info line we asked for only to see failures passes only when it reports one.
    QString line = QString::fromUtf8(str);
    if (!avpn::xrayKeepCoreLine(line, m_levelRaised.load())) {
        ++m_droppedInfoLines;
        return;
    }
    QMetaObject::invokeMethod(qApp, [str = std::move(line)] {
        qDebug() << "[xray]" << str;
    }, Qt::QueuedConnection);
}

void Xray::sockCallback(uintptr_t fd)
{
#ifdef Q_OS_MAC
    if (m_defaultIfaceIdx > 0) {
        // AVPN (diag): an AF_INET socket takes IP_BOUND_IF, an AF_INET6 one IPV6_BOUND_IF; a socket
        // neither pins stays on the main table - whose 0/1 and 128/1 lead into the tunnel.
        const int v4 = setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &m_defaultIfaceIdx, sizeof(m_defaultIfaceIdx));
        const int v4errno = v4 == 0 ? 0 : errno;
        const int v6 = setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &m_defaultIfaceIdx, sizeof(m_defaultIfaceIdx));
        if (v4 == 0 || v6 == 0) {
            ++m_bindOk;
        } else if (m_bindFailed++ == 0) {
            m_bindFirstErrno = v4errno;
            QMetaObject::invokeMethod(qApp, [v4errno, idx = m_defaultIfaceIdx] {
                qWarning() << "[xray] a core socket could not be bound to uplink index" << idx << "errno" << v4errno;
            }, Qt::QueuedConnection);
        }
    }
#endif
#ifdef Q_OS_WIN
    if (DWORD idx = m_defaultIfaceIdx; idx > 0) {
        setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, reinterpret_cast<char *>(&idx), sizeof(idx));
        idx = htonl(idx); // IP_UNICAST_IF expects index in network byte order
        setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, reinterpret_cast<char *>(&idx), sizeof(idx));
    }
#endif
#ifdef Q_OS_LINUX
    if (!m_defaultIfaceName.isEmpty()) {
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, m_defaultIfaceName.data(), m_defaultIfaceName.size());
        setsockopt(fd, SOL_SOCKET, SO_MARK, &amnezia::xray::xrayTrafficMark, sizeof(amnezia::xray::xrayTrafficMark));
    }
#endif
}
