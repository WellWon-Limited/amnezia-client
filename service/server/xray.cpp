#include "xray.h"
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
#endif
#ifdef Q_OS_LINUX
    #include <sys/socket.h>
    #include "xray_defs.h"
#endif

// AVPN: чтение сырых счётчиков интерфейса tun2socks для runtimeStatus (macOS-демон).
#include <QDateTime>
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

#ifdef Q_OS_MAC
    m_uplinkIfaceName = defaultIface.name();
    m_uplinkGateway = defaultGateway;
    if (!m_uplinkIfaceName.isEmpty()) {
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

    QByteArray bytes = cfg.toUtf8();
    if (auto err = amnezia_xray_configure(bytes.data()); err != nullptr) {
        qDebug() << "[xray] configuration failed: " << err;
        amnezia_xray_free(err);
        return false;
    }

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
    if (auto err = amnezia_xray_stop(); err != nullptr) {
        qDebug() << "[xray] failed to stop: " << err;
        amnezia_xray_free(err);
        success = false;
    }

#ifdef Q_OS_MAC
    if (!m_uplinkIfaceName.isEmpty()) {
        RouterMac::Instance().routeDeleteXray(m_uplinkIfaceName, m_uplinkGateway);
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
#else
    // Windows/Linux: счётчики utun через getifaddrs недоступны — честные нули + unsupported.
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
    QMetaObject::invokeMethod(qApp, [str = QString::fromUtf8(str)] {
        qDebug() << "[xray]" << str;
    }, Qt::QueuedConnection);
}

void Xray::sockCallback(uintptr_t fd)
{
#ifdef Q_OS_MAC
    if (m_defaultIfaceIdx > 0) {
        setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &m_defaultIfaceIdx, sizeof(m_defaultIfaceIdx));
        setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &m_defaultIfaceIdx, sizeof(m_defaultIfaceIdx));
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
