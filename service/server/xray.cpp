#include "xray.h"

#include "core/utils/networkUtilities.h"
#ifdef Q_OS_MAC
#include "router_mac.h"
#endif

#include <QCoreApplication>
#include <QDebug>
#include <QMutexLocker>
#include <QNetworkInterface>
#include <QUuid>
#include <amnezia_xray.h>

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
#include <unistd.h>
#endif
#ifdef Q_OS_WIN
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#ifdef Q_OS_LINUX
#include <sys/socket.h>
#include "xray_defs.h"
#endif

#ifndef TRIBE_XRAY_BINDINGS_VERSION
#define TRIBE_XRAY_BINDINGS_VERSION ""
#endif
#ifndef TRIBE_XRAY_CORE_VERSION
#define TRIBE_XRAY_CORE_VERSION ""
#endif
#ifndef TRIBE_XRAY_BINDINGS_ABI
#define TRIBE_XRAY_BINDINGS_ABI ""
#endif

namespace {

struct InterfaceStats {
    bool available = false;
    quint64 rxBytes = 0;
    quint64 txBytes = 0;
    quint64 rxPackets = 0;
    quint64 txPackets = 0;
};

InterfaceStats readInterfaceStats(const QString &interfaceName)
{
    InterfaceStats result;
#ifdef Q_OS_DARWIN
    if (interfaceName.isEmpty()) {
        return result;
    }

    ifaddrs *addresses = nullptr;
    if (getifaddrs(&addresses) != 0 || addresses == nullptr) {
        return result;
    }

    for (const ifaddrs *entry = addresses; entry != nullptr; entry = entry->ifa_next) {
        if (entry->ifa_name == nullptr || entry->ifa_data == nullptr
                || QString::fromLocal8Bit(entry->ifa_name) != interfaceName) {
            continue;
        }
        const auto *data = static_cast<const if_data *>(entry->ifa_data);
        result.available = true;
        result.rxBytes = data->ifi_ibytes;
        result.txBytes = data->ifi_obytes;
        result.rxPackets = data->ifi_ipackets;
        result.txPackets = data->ifi_opackets;
        break;
    }
    freeifaddrs(addresses);
#else
    Q_UNUSED(interfaceName)
#endif
    return result;
}

QString decimal(quint64 value)
{
    return QString::number(value);
}

} // namespace

bool Xray::isCanonicalSessionId(const QString &sessionId) const
{
    const QUuid parsed(sessionId);
    return !parsed.isNull()
            && parsed.toString(QUuid::WithoutBraces).toLower() == sessionId;
}

bool Xray::startXray(const QString &cfg)
{
    return startXrayInternal(QUuid::createUuid().toString(QUuid::WithoutBraces).toLower(), cfg);
}

bool Xray::startXraySession(const QString &sessionId, const QString &cfg)
{
    if (!isCanonicalSessionId(sessionId)) {
        qWarning() << "Xray start rejected: non-canonical session id";
        return false;
    }
    return startXrayInternal(sessionId, cfg);
}

bool Xray::startXrayInternal(const QString &sessionId, const QString &cfg)
{
    qDebug() << "Xray::startXrayInternal";
    static constexpr qsizetype maxConfigBytes = 512 * 1024;
    if (cfg.trimmed().isEmpty() || cfg.toUtf8().size() > maxConfigBytes) {
        qWarning() << "Xray start rejected: empty or oversized configuration";
        return false;
    }

    quint64 generation = 0;
    {
        QMutexLocker locker(&m_stateMutex);
        if (m_coreStarted || m_quarantined
#ifdef Q_OS_MAC
                || m_routesInstalled
#endif
        ) {
            qWarning() << "Xray start rejected: previous native session not cleanly stopped";
            return false;
        }
        m_sessionId = sessionId;
        m_runtimeState = QStringLiteral("starting");
        m_failureReason.clear();
        m_haveLastStats = false;
        m_lastRxBytes = m_lastTxBytes = 0;
        m_lastRxPackets = m_lastTxPackets = 0;
        m_counterResetCount = 0;
        generation = ++m_generationCounter;
        auto context = std::make_unique<SocketCallbackContext>();
        context->owner = this;
        context->generation = generation;
        m_callbackContexts.push_back(std::move(context));
    }
    m_activeGeneration.store(generation, std::memory_order_release);
    m_socketProtectionAttempted.store(false, std::memory_order_release);
    m_socketProtectionSucceeded.store(false, std::memory_order_release);
    m_socketProtectionFailed.store(false, std::memory_order_release);

    const auto gatewayAndIface = NetworkUtilities::getGatewayAndIface();
    const QString defaultGateway = gatewayAndIface.first;
    const QNetworkInterface defaultIface = gatewayAndIface.second;
#ifdef Q_OS_LINUX
    m_defaultIfaceName = defaultIface.name().toUtf8();
#else
    m_defaultIfaceIdx.store(defaultIface.index(), std::memory_order_release);
#endif
    if (!defaultIface.isValid() || defaultIface.index() <= 0) {
        QMutexLocker locker(&m_stateMutex);
        m_runtimeState = QStringLiteral("failed");
        m_failureReason = QStringLiteral("uplink_interface_unavailable");
        m_quarantined = false;
        return false;
    }
    qDebug() << "[xray] using uplink interface:" << defaultIface.name()
             << "(" << defaultIface.index() << ")";

#ifdef Q_OS_MAC
    m_uplinkIfaceName = defaultIface.name();
    m_uplinkGateway = defaultGateway;
    if (m_uplinkGateway.isEmpty()
            || !RouterMac::Instance().routeAddXray(m_uplinkIfaceName, m_uplinkGateway)) {
        const bool cleanupSucceeded = m_uplinkGateway.isEmpty()
                || RouterMac::Instance().routeDeleteXray(m_uplinkIfaceName, m_uplinkGateway);
        QMutexLocker locker(&m_stateMutex);
        m_routesInstalled = !cleanupSucceeded;
        m_runtimeState = QStringLiteral("failed");
        m_failureReason = QStringLiteral("escape_route_install_failed");
        m_quarantined = !cleanupSucceeded;
        return false;
    }
    {
        QMutexLocker locker(&m_stateMutex);
        m_routesInstalled = true;
    }

    // Prove both Darwin families can be scoped before reporting ready.
    if (!preflightSocketProtection(defaultIface.index())) {
        const bool routesRemoved = RouterMac::Instance().routeDeleteXray(
                m_uplinkIfaceName, m_uplinkGateway);
        QMutexLocker locker(&m_stateMutex);
        m_routesInstalled = !routesRemoved;
        m_runtimeState = QStringLiteral("failed");
        m_failureReason = QStringLiteral("socket_protection_preflight_failed");
        m_quarantined = !routesRemoved;
        return false;
    }
#endif

    SocketCallbackContext *callbackContext = nullptr;
    {
        QMutexLocker locker(&m_stateMutex);
        callbackContext = m_callbackContexts.back().get();
    }
    if (auto err = amnezia_xray_setsockcallback(ctxSockCallback, callbackContext); err != nullptr) {
        qWarning() << "[xray] failed to install socket callback (details redacted)";
        amnezia_xray_free(err);
        stopXrayInternal(sessionId, true);
        QMutexLocker locker(&m_stateMutex);
        m_runtimeState = QStringLiteral("failed");
        m_failureReason = QStringLiteral("socket_callback_install_failed");
        return false;
    }

    amnezia_xray_setloghandler(ctxLogHandler, this);

    QByteArray bytes = cfg.toUtf8();
    if (auto err = amnezia_xray_configure(bytes.data()); err != nullptr) {
        qWarning() << "[xray] configuration failed (details redacted)";
        amnezia_xray_free(err);
        stopXrayInternal(sessionId, true);
        QMutexLocker locker(&m_stateMutex);
        m_runtimeState = QStringLiteral("failed");
        m_failureReason = QStringLiteral("core_configure_failed");
        return false;
    }

    if (auto err = amnezia_xray_start(); err != nullptr) {
        qWarning() << "[xray] start failed (details redacted)";
        amnezia_xray_free(err);
        stopXrayInternal(sessionId, true);
        QMutexLocker locker(&m_stateMutex);
        m_runtimeState = QStringLiteral("failed");
        m_failureReason = QStringLiteral("core_start_failed");
        return false;
    }

    bool running = false;
    QString readinessFailure;
    {
        QMutexLocker locker(&m_stateMutex);
        m_coreStarted = true;
        if (QStringLiteral(TRIBE_XRAY_BINDINGS_VERSION).isEmpty()
                || QStringLiteral(TRIBE_XRAY_CORE_VERSION).isEmpty()
                || QStringLiteral(TRIBE_XRAY_BINDINGS_ABI) != QStringLiteral("amnezia-xray-c-v1")) {
            m_runtimeState = QStringLiteral("failed");
            m_failureReason = QStringLiteral("engine_metadata_unavailable");
        } else if (m_socketProtectionFailed.load(std::memory_order_acquire)) {
            m_runtimeState = QStringLiteral("failed");
            m_failureReason = QStringLiteral("socket_protection_failed");
        } else {
            m_runtimeState = QStringLiteral("running");
        }
        running = m_runtimeState == QStringLiteral("running");
        readinessFailure = m_failureReason;
    }
    if (!running) {
        const bool stopped = stopXrayInternal(sessionId, true);
        if (stopped) {
            QMutexLocker locker(&m_stateMutex);
            m_runtimeState = QStringLiteral("failed");
            m_failureReason = readinessFailure;
        }
    }
    return running;
}

bool Xray::stopXray()
{
    QString sessionId;
    {
        QMutexLocker locker(&m_stateMutex);
        sessionId = m_sessionId;
    }
    return stopXrayInternal(sessionId, false);
}

bool Xray::stopXraySession(const QString &sessionId)
{
    if (!isCanonicalSessionId(sessionId)) {
        return false;
    }
    return stopXrayInternal(sessionId, true);
}

bool Xray::stopXrayInternal(const QString &sessionId, bool requireExactSession)
{
    qDebug() << "Xray::stopXrayInternal";
    bool coreStarted = false;
#ifdef Q_OS_MAC
    QString uplinkIface;
    QString uplinkGateway;
    bool routesInstalled = false;
#endif
    {
        QMutexLocker locker(&m_stateMutex);
        if (requireExactSession && (sessionId.isEmpty() || sessionId != m_sessionId)) {
            qWarning() << "Ignoring stale Xray stop request";
            return false;
        }
        if (m_sessionId.isEmpty()) {
            return true;
        }
        m_runtimeState = QStringLiteral("stopping");
        m_failureReason.clear();
        coreStarted = m_coreStarted;
#ifdef Q_OS_MAC
        uplinkIface = m_uplinkIfaceName;
        uplinkGateway = m_uplinkGateway;
        routesInstalled = m_routesInstalled;
#endif
    }

    bool coreStopped = true;
    if (coreStarted) {
        if (auto err = amnezia_xray_stop(); err != nullptr) {
            qWarning() << "[xray] stop failed (details redacted)";
            amnezia_xray_free(err);
            coreStopped = false;
        }
    }

    // Never remove physical escape routes while a core that may still be
    // alive can emit sockets.
    bool routesRemoved = true;
#ifdef Q_OS_MAC
    if (coreStopped && routesInstalled) {
        routesRemoved = RouterMac::Instance().routeDeleteXray(uplinkIface, uplinkGateway);
    } else if (!coreStopped && routesInstalled) {
        routesRemoved = false;
    }
#endif

    const bool stopped = coreStopped && routesRemoved;
    {
        QMutexLocker locker(&m_stateMutex);
        if (coreStopped) {
            m_coreStarted = false;
            m_activeGeneration.store(0, std::memory_order_release);
        }
#ifdef Q_OS_MAC
        if (routesRemoved) {
            m_routesInstalled = false;
            m_uplinkIfaceName.clear();
            m_uplinkGateway.clear();
        }
#endif
        m_quarantined = !stopped;
        m_runtimeState = stopped ? QStringLiteral("stopped") : QStringLiteral("failed");
        m_failureReason = stopped ? QString() : (coreStopped
                ? QStringLiteral("escape_route_remove_failed")
                : QStringLiteral("core_stop_failed"));
    }
    return stopped;
}

QJsonObject Xray::runtimeStatusV1(const QString &sessionId)
{
    QJsonObject status;
    status.insert(QStringLiteral("type"), QStringLiteral("tunnel_runtime_status_v1"));
    status.insert(QStringLiteral("schema"), 1);
    status.insert(QStringLiteral("protocol"), QStringLiteral("xray"));
    QJsonObject core;
    core.insert(QStringLiteral("adapter"), QStringLiteral("amnezia-xray-bindings"));
    core.insert(QStringLiteral("adapter_version"), QStringLiteral(TRIBE_XRAY_BINDINGS_VERSION));
    core.insert(QStringLiteral("version"), QStringLiteral(TRIBE_XRAY_CORE_VERSION));
    core.insert(QStringLiteral("declared_core_version"), QStringLiteral(TRIBE_XRAY_CORE_VERSION));
    core.insert(QStringLiteral("runtime_core_version"), QJsonValue::Null);
    core.insert(QStringLiteral("runtime_version_probed"), false);
    core.insert(QStringLiteral("abi"), QStringLiteral(TRIBE_XRAY_BINDINGS_ABI));
    status.insert(QStringLiteral("core"), core);

#ifdef Q_OS_MAC
    const InterfaceStats stats = readInterfaceStats(QStringLiteral("utun22"));
#else
    const InterfaceStats stats = readInterfaceStats(QString());
#endif
    QMutexLocker locker(&m_stateMutex);
    status.insert(QStringLiteral("session_id"), m_sessionId);

    QString state = m_runtimeState;
    QString reason = m_failureReason;
    if (!sessionId.isEmpty() && sessionId != m_sessionId) {
        state = QStringLiteral("stale_session");
        reason = QStringLiteral("session_mismatch");
    } else if (m_socketProtectionFailed.load(std::memory_order_acquire)
               && state != QStringLiteral("stopped")) {
        state = QStringLiteral("failed");
        reason = QStringLiteral("socket_protection_failed");
    }
    status.insert(QStringLiteral("runtime_state"), state);
    if (!reason.isEmpty()) {
        status.insert(QStringLiteral("failure_reason"), reason);
        if (reason == QLatin1String("core_stop_failed")
                || reason == QLatin1String("escape_route_remove_failed")) {
            status.insert(QStringLiteral("teardown_state"), QStringLiteral("stop_failed"));
        }
    }

    quint64 rxBytesDelta = 0;
    quint64 txBytesDelta = 0;
    quint64 rxPacketsDelta = 0;
    quint64 txPacketsDelta = 0;
    if (stats.available) {
        if (m_haveLastStats) {
            const bool reset = stats.rxBytes < m_lastRxBytes || stats.txBytes < m_lastTxBytes
                    || stats.rxPackets < m_lastRxPackets || stats.txPackets < m_lastTxPackets;
            if (reset) {
                // A reset rebases the raw sample; never underflow or invent a
                // process-lifetime-sized delta.
                rxBytesDelta = txBytesDelta = 0;
                rxPacketsDelta = txPacketsDelta = 0;
            } else {
                rxBytesDelta = stats.rxBytes - m_lastRxBytes;
                txBytesDelta = stats.txBytes - m_lastTxBytes;
                rxPacketsDelta = stats.rxPackets - m_lastRxPackets;
                txPacketsDelta = stats.txPackets - m_lastTxPackets;
            }
            if (reset) {
                ++m_counterResetCount;
            }
        }
        m_haveLastStats = true;
        m_lastRxBytes = stats.rxBytes;
        m_lastTxBytes = stats.txBytes;
        m_lastRxPackets = stats.rxPackets;
        m_lastTxPackets = stats.txPackets;
    }
    QJsonObject counters;
    counters.insert(QStringLiteral("available"), stats.available);
    counters.insert(QStringLiteral("source"), stats.available
            ? QStringLiteral("darwin_getifaddrs_if_data") : QStringLiteral("unavailable"));
    counters.insert(QStringLiteral("epoch"), m_sessionId);
    counters.insert(QStringLiteral("rx_bytes"), decimal(stats.rxBytes));
    counters.insert(QStringLiteral("tx_bytes"), decimal(stats.txBytes));
    counters.insert(QStringLiteral("rx_packets"), decimal(stats.rxPackets));
    counters.insert(QStringLiteral("tx_packets"), decimal(stats.txPackets));
    counters.insert(QStringLiteral("rx_bytes_delta"), decimal(rxBytesDelta));
    counters.insert(QStringLiteral("tx_bytes_delta"), decimal(txBytesDelta));
    counters.insert(QStringLiteral("rx_packets_delta"), decimal(rxPacketsDelta));
    counters.insert(QStringLiteral("tx_packets_delta"), decimal(txPacketsDelta));
    counters.insert(QStringLiteral("reset_count"), decimal(m_counterResetCount));
    status.insert(QStringLiteral("counters"), counters);
    status.insert(QStringLiteral("rx_bytes"), decimal(stats.rxBytes));
    status.insert(QStringLiteral("tx_bytes"), decimal(stats.txBytes));

#ifdef Q_OS_MAC
    const bool protectionFailed = m_socketProtectionFailed.load(std::memory_order_acquire);
    const bool protectionSucceeded = m_socketProtectionSucceeded.load(std::memory_order_acquire);
    status.insert(QStringLiteral("socket_protection"), protectionFailed
            ? QStringLiteral("failed") : (protectionSucceeded
                    ? QStringLiteral("verified") : QStringLiteral("pending")));
#else
    status.insert(QStringLiteral("socket_protection"), QStringLiteral("not_applicable"));
#endif
    return status;
}

void Xray::logHandler(char* str)
{
    Q_UNUSED(str);
    // Core logs can contain bearer UUID/SNI/config material and are
    // attacker-amplifiable. Typed lifecycle status is the supported
    // diagnostic channel; release builds intentionally suppress payloads.
}

#ifdef Q_OS_MAC
bool Xray::preflightSocketProtection(int interfaceIndex)
{
    m_socketProtectionAttempted.store(true, std::memory_order_release);
    bool success = interfaceIndex > 0;
    for (const int family : {AF_INET, AF_INET6}) {
        const int fd = ::socket(family, SOCK_STREAM, 0);
        if (fd < 0) {
            success = false;
            continue;
        }
        const int option = family == AF_INET ? IP_BOUND_IF : IPV6_BOUND_IF;
        const int level = family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
        if (::setsockopt(fd, level, option, &interfaceIndex, sizeof(interfaceIndex)) != 0) {
            success = false;
        }
        ::close(fd);
    }
    m_socketProtectionSucceeded.store(success, std::memory_order_release);
    m_socketProtectionFailed.store(!success, std::memory_order_release);
    return success;
}
#endif

void Xray::sockCallback(uintptr_t descriptor, quint64 generation)
{
    if (generation == 0 || generation != m_activeGeneration.load(std::memory_order_acquire)) {
        return;
    }

#ifdef Q_OS_MAC
    m_socketProtectionAttempted.store(true, std::memory_order_release);
    const int interfaceIndex = m_defaultIfaceIdx.load(std::memory_order_acquire);
    sockaddr_storage address{};
    socklen_t addressLength = sizeof(address);
    bool success = interfaceIndex > 0
            && ::getsockname(static_cast<int>(descriptor),
                             reinterpret_cast<sockaddr *>(&address), &addressLength) == 0;
    if (success) {
        int level = 0;
        int option = 0;
        if (address.ss_family == AF_INET) {
            level = IPPROTO_IP;
            option = IP_BOUND_IF;
        } else if (address.ss_family == AF_INET6) {
            level = IPPROTO_IPV6;
            option = IPV6_BOUND_IF;
        } else {
            success = false;
        }
        if (success) {
            success = ::setsockopt(static_cast<int>(descriptor), level, option,
                                   &interfaceIndex, sizeof(interfaceIndex)) == 0;
        }
    }
    if (success) {
        m_socketProtectionSucceeded.store(true, std::memory_order_release);
    } else {
        m_socketProtectionFailed.store(true, std::memory_order_release);
        QMutexLocker locker(&m_stateMutex);
        if (generation == m_activeGeneration.load(std::memory_order_acquire)) {
            m_runtimeState = QStringLiteral("failed");
            m_failureReason = QStringLiteral("socket_protection_failed");
        }
    }
#endif
#ifdef Q_OS_WIN
    DWORD idx = static_cast<DWORD>(m_defaultIfaceIdx.load(std::memory_order_acquire));
    if (idx > 0) {
        setsockopt(descriptor, IPPROTO_IPV6, IPV6_UNICAST_IF,
                   reinterpret_cast<char *>(&idx), sizeof(idx));
        idx = htonl(idx);
        setsockopt(descriptor, IPPROTO_IP, IP_UNICAST_IF,
                   reinterpret_cast<char *>(&idx), sizeof(idx));
    }
#endif
#ifdef Q_OS_LINUX
    if (!m_defaultIfaceName.isEmpty()) {
        setsockopt(descriptor, SOL_SOCKET, SO_BINDTODEVICE,
                   m_defaultIfaceName.data(), m_defaultIfaceName.size());
        setsockopt(descriptor, SOL_SOCKET, SO_MARK, &amnezia::xray::xrayTrafficMark,
                   sizeof(amnezia::xray::xrayTrafficMark));
    }
#endif
}
