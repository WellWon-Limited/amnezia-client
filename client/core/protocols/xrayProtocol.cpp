#include "xrayProtocol.h"

#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/ipcClient.h"
#include "core/utils/networkUtilities.h"
#include "core/utils/serialization/serialization.h"
#include "ipc.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkInterface>
#include <QPointer>
#include <QUuid>

#include <exception>
#include <limits>

#ifdef Q_OS_MACOS
static const QString tunName = QStringLiteral("utun22");
#else
static const QString tunName = QStringLiteral("tun2");
#endif

namespace {

bool canonicalUint64(const QJsonValue &value, quint64 *result)
{
    if (result == nullptr || !value.isString()) {
        return false;
    }
    const QString text = value.toString();
    if (text.isEmpty() || (text.size() > 1 && text.startsWith(QLatin1Char('0')))
            || text.size() > 20) {
        return false;
    }
    for (const QChar character : text) {
        if (character < QLatin1Char('0') || character > QLatin1Char('9')) {
            return false;
        }
    }
    bool ok = false;
    const quint64 parsed = text.toULongLong(&ok, 10);
    if (!ok || QString::number(parsed) != text) {
        return false;
    }
    *result = parsed;
    return true;
}

quint64 saturatingAdd(quint64 lhs, quint64 rhs)
{
    if (rhs > std::numeric_limits<quint64>::max() - lhs) {
        return std::numeric_limits<quint64>::max();
    }
    return lhs + rhs;
}

bool isCanonicalUuid(const QString &value)
{
    const QUuid uuid(value);
    return !uuid.isNull() && uuid.toString(QUuid::WithoutBraces).toLower() == value;
}

} // namespace

XrayProtocol::XrayProtocol(const QJsonObject &configuration, QObject *parent)
    : XrayProtocol(configuration, QString{}, false, parent)
{
}

XrayProtocol::XrayProtocol(const QJsonObject &configuration,
                           const QString &expectedRuntimeSessionId,
                           bool externallyGuarded,
                           QObject *parent)
    : VpnProtocol(configuration, parent),
      m_runtimeSessionId(expectedRuntimeSessionId),
      m_externallyGuarded(externallyGuarded)
{
    m_vpnGateway = amnezia::protocols::xray::defaultLocalAddr;
    m_vpnLocalAddress = amnezia::protocols::xray::defaultLocalAddr;
    m_routeGateway = NetworkUtilities::getGatewayAndIface().first;

    m_routeMode = static_cast<amnezia::RouteMode>(
            configuration.value(amnezia::configKey::splitTunnelType).toInt());
    m_remoteAddress = NetworkUtilities::getIPAddress(
            m_rawConfig.value(amnezia::configKey::hostName).toString());

    const QString primaryDns = configuration.value(amnezia::configKey::dns1).toString();
    m_dnsServers.push_back(QHostAddress(primaryDns));
    if (primaryDns != amnezia::protocols::dns::amneziaDnsIp) {
        const QString secondaryDns = configuration.value(amnezia::configKey::dns2).toString();
        m_dnsServers.push_back(QHostAddress(secondaryDns));
    }

    QJsonObject wrapper = configuration.value(
            ProtocolUtils::key_proto_config_data(Proto::Xray)).toObject();
    if (wrapper.isEmpty()) {
        wrapper = configuration.value(
                ProtocolUtils::key_proto_config_data(Proto::SSXray)).toObject();
    }
    if (wrapper.isEmpty()) {
        qWarning() << "Xray config wrapper is empty";
        return;
    }

    const QJsonDocument configDocument = QJsonDocument::fromJson(
            wrapper.value(amnezia::configKey::config).toString().toUtf8());
    if (!configDocument.isObject()) {
        qWarning() << "Xray config is not a JSON object";
        return;
    }
    m_xrayConfig = configDocument.object();

    m_runtimeTimer.setInterval(1000);
    m_runtimeTimer.setSingleShot(false);
    connect(&m_runtimeTimer, &QTimer::timeout, this, [this]() {
        pollRuntimeStatus(m_runtimeSessionId, m_operationGeneration);
    });
}

XrayProtocol::~XrayProtocol()
{
    qDebug() << "XrayProtocol::~XrayProtocol()";
    XrayProtocol::stop();
}

QJsonObject XrayProtocol::runtimeStatus() const
{
    return m_runtimeStatus;
}

QString XrayProtocol::runtimeSessionId() const
{
    return m_runtimeSessionId;
}

ErrorCode XrayProtocol::start()
{
    qDebug() << "XrayProtocol::start()";
    if (m_xrayConfig.isEmpty()) {
        return ErrorCode::XrayExecutableCrashed;
    }

    amnezia::serialization::inbounds::InboundCredentials credentials;
    try {
        credentials = amnezia::serialization::inbounds::EnsureInboundAuth(m_xrayConfig);
    } catch (const std::exception &exception) {
        Q_UNUSED(exception);
        qCritical() << "EnsureInboundAuth failed (details redacted)";
        return ErrorCode::InternalError;
    }
    m_socksUser = credentials.username;
    m_socksPassword = credentials.password;
    m_socksPort = credentials.port;

    // Patch only inbound listen fields.  A global string replacement can
    // corrupt endpoint/SNI or unrelated policy fields.
    QJsonArray inbounds = m_xrayConfig.value(QStringLiteral("inbounds")).toArray();
    for (qsizetype index = 0; index < inbounds.size(); ++index) {
        QJsonObject inbound = inbounds.at(index).toObject();
        if (inbound.value(QStringLiteral("listen")).toString()
                == amnezia::protocols::xray::defaultLocalAddr) {
            inbound.insert(QStringLiteral("listen"),
                           amnezia::protocols::xray::defaultLocalListenAddr);
            inbounds.replace(index, inbound);
        }
    }
    m_xrayConfig.insert(QStringLiteral("inbounds"), inbounds);

    QString xrayConfig = QJsonDocument(m_xrayConfig).toJson(QJsonDocument::Compact);
    if (xrayConfig.isEmpty()) {
        return ErrorCode::XrayExecutableCrashed;
    }
    if (xrayConfig.contains(QStringLiteral("Mozilla/5.0"), Qt::CaseInsensitive)) {
        xrayConfig.replace(QStringLiteral("Mozilla/5.0"),
                           amnezia::protocols::xray::defaultFingerprint,
                           Qt::CaseInsensitive);
    }

    m_runtimeTimer.stop();
    m_stopping = false;
    m_tunReadySeen = false;
    m_tun2socksRetryCount = 0;
    m_haveRawCounters = false;
    m_lastRawRx = m_lastRawTx = 0;
    m_normalizedRx = m_normalizedTx = 0;
    m_lastResetCount = 0;
    m_counterEpoch.clear();
    const quint64 generation = ++m_operationGeneration;
    const QString sessionId = m_runtimeSessionId.isEmpty()
            ? QUuid::createUuid().toString(QUuid::WithoutBraces).toLower()
            : m_runtimeSessionId;
    if (!isCanonicalUuid(sessionId)) {
        return ErrorCode::InternalError;
    }
    m_runtimeSessionId = sessionId;
    m_runtimeStatus = {};

    return IpcClient::withInterface(
            [&](QSharedPointer<IpcInterfaceReplica> iface) {
                auto reply = iface->xrayStartSession(sessionId, xrayConfig);
                if (!reply.waitForFinished(5000) || !reply.returnValue()) {
                    const QJsonObject failedStatus = queryRuntimeStatus(sessionId);
                    acceptRuntimeStatus(failedStatus, sessionId, false);
                    qCritical() << "Failed to start exact Xray native session";
                    return ErrorCode::XrayExecutableCrashed;
                }
                const ErrorCode result = startTun2Socks(sessionId, generation);
                if (result != ErrorCode::NoError) {
                    stop();
                }
                return result;
            },
            []() { return ErrorCode::AmneziaServiceConnectionFailed; });
}

void XrayProtocol::stop()
{
    if (m_stopping
            || m_runtimeStatus.value(QStringLiteral("runtime_state"))
                   == QLatin1String("stopped")) {
        return;
    }
    qDebug() << "XrayProtocol::stop()";
    m_stopping = true;
    m_runtimeTimer.stop();
    ++m_operationGeneration; // invalidates every queued process/poll callback

    const QString sessionId = m_runtimeSessionId;
    const auto process = m_tun2socksProcess;
    QObject::disconnect(m_tunReadyConnection);
    QObject::disconnect(m_tunFinishedConnection);
    if (process) {
        process->blockSignals(true);
    }
    m_tun2socksProcess.reset();

    if (!sessionId.isEmpty()) {
        setConnectionState(Vpn::ConnectionState::Disconnecting);
    }

    const bool processStopped = stopTun2Socks(process);
    const bool nativeStopped = sessionId.isEmpty() || IpcClient::withInterface(
            [&](QSharedPointer<IpcInterfaceReplica> iface) {
                auto reply = iface->xrayStopSession(sessionId);
                return reply.waitForFinished(5000) && reply.returnValue();
            });

    QJsonObject terminalStatus;
    bool terminalValid = sessionId.isEmpty();
    if (!sessionId.isEmpty()) {
        terminalStatus = queryRuntimeStatus(sessionId);
        // Validate and retain the exact daemon receipt, but do not publish a
        // terminal until local routes/DNS/TUN and the kill switch have reached
        // their own teardown postcondition.
        terminalValid = acceptRuntimeStatus(terminalStatus, sessionId, false, false);
    }

    bool routingCleaned = false;
    if (processStopped && nativeStopped) {
        routingCleaned = cleanupRouting();
    }

    const bool stopped = processStopped && nativeStopped && routingCleaned
            && terminalValid
            && terminalStatus.value(QStringLiteral("runtime_state")).toString()
                    == QLatin1String("stopped");
    if (stopped && !sessionId.isEmpty()) {
        m_runtimeStatus = terminalStatus;
        emit runtimeStatusChanged(terminalStatus);
    } else if (!sessionId.isEmpty() && terminalValid) {
        terminalStatus.insert(QStringLiteral("runtime_state"), QStringLiteral("failed"));
        terminalStatus.insert(QStringLiteral("teardown_state"), QStringLiteral("stop_failed"));
        terminalStatus.insert(QStringLiteral("failure_reason"), !processStopped
                ? QStringLiteral("tun2socks_stop_failed") : (!nativeStopped
                        ? QStringLiteral("core_stop_failed")
                        : QStringLiteral("local_route_cleanup_failed")));
        m_runtimeStatus = terminalStatus;
        emit runtimeStatusChanged(terminalStatus);
    }

    m_stopping = false;
    if (stopped || sessionId.isEmpty()) {
        setConnectionState(Vpn::ConnectionState::Disconnected);
    } else {
        setLastError(ErrorCode::InternalError);
    }
}

ErrorCode XrayProtocol::startTun2Socks(const QString &sessionId, quint64 generation)
{
    const auto process = IpcClient::CreatePrivilegedProcess();
    if (!process || !process->waitForSource()) {
        return ErrorCode::AmneziaServiceConnectionFailed;
    }
    if (!isCurrentSession(sessionId, generation)) {
        return ErrorCode::InternalError;
    }

    m_tun2socksProcess = process;
    m_tunReadySeen = false;
    const QString proxyUrl = QStringLiteral("socks5://%1:%2@127.0.0.1:%3")
            .arg(m_socksUser, m_socksPassword, QString::number(m_socksPort));
    process->setProgram(PermittedProcess::Tun2Socks);
    process->setArguments({QStringLiteral("-device"),
                           QStringLiteral("tun://%1").arg(tunName),
                           QStringLiteral("-proxy"), proxyUrl});

    const QWeakPointer<IpcProcessInterfaceReplica> weakProcess = process.toWeakRef();
    const auto outputBuffer = QSharedPointer<QByteArray>::create();
    m_tunReadyConnection = connect(
            process.data(), &IpcProcessInterfaceReplica::readyReadStandardError, this,
            [this, weakProcess, outputBuffer, sessionId, generation]() {
                const auto exactProcess = weakProcess.toStrongRef();
                if (!exactProcess || !isCurrentSession(
                            sessionId, generation, exactProcess.data())) {
                    return;
                }
                auto pending = exactProcess->readAllStandardError();
                if (!pending.waitForFinished(1000)) {
                    return;
                }
                outputBuffer->append(pending.returnValue());
                if (outputBuffer->size() > 65536) {
                    outputBuffer->remove(0, outputBuffer->size() - 65536);
                }
                if (m_tunReadySeen
                        || !outputBuffer->contains("[STACK] tun://")
                        || !outputBuffer->contains("<-> socks5://")) {
                    return;
                }

                m_tunReadySeen = true;
                QObject::disconnect(m_tunReadyConnection); // exact stderr connection, once
                if (const ErrorCode routingError = setupRouting();
                        routingError != ErrorCode::NoError) {
                    failCurrentSession(routingError, sessionId, generation);
                    return;
                }

                const QJsonObject status = queryRuntimeStatus(sessionId);
                if (!acceptRuntimeStatus(status, sessionId, true)
                        || status.value(QStringLiteral("runtime_state")).toString()
                                != QLatin1String("running")) {
                    failCurrentSession(ErrorCode::XrayExecutableCrashed,
                                       sessionId, generation);
                    return;
                }
                m_tun2socksRetryCount = 0;
                setConnectionState(Vpn::ConnectionState::Connected);
                m_runtimeTimer.start();
            },
            Qt::QueuedConnection);

    m_tunFinishedConnection = connect(
            process.data(), &IpcProcessInterfaceReplica::finished, this,
            [this, weakProcess, outputBuffer, sessionId, generation](
                    int exitCode, QProcess::ExitStatus exitStatus) {
                const auto exactProcess = weakProcess.toStrongRef();
                if (!exactProcess || !isCurrentSession(
                            sessionId, generation, exactProcess.data())) {
                    return;
                }
                QObject::disconnect(m_tunReadyConnection);
                QObject::disconnect(m_tunFinishedConnection);

                auto stdoutReply = exactProcess->readAllStandardOutput();
                if (stdoutReply.waitForFinished(1000)) {
                    outputBuffer->append(stdoutReply.returnValue());
                }
                const bool resourceBusy = outputBuffer->contains("resource busy");
                exactProcess->close();
                if (m_tun2socksProcess.data() == exactProcess.data()) {
                    m_tun2socksProcess.reset();
                }

                if (resourceBusy && !m_tunReadySeen
                        && m_tun2socksRetryCount < maxTun2SocksRetries) {
                    ++m_tun2socksRetryCount;
                    QTimer::singleShot(tun2socksRetryDelayMs, this,
                                       [this, sessionId, generation]() {
                        if (!isCurrentSession(sessionId, generation)) {
                            return;
                        }
                        const ErrorCode error = startTun2Socks(sessionId, generation);
                        if (error != ErrorCode::NoError) {
                            failCurrentSession(error, sessionId, generation);
                        }
                    });
                    return;
                }

                qCritical() << "Tun2socks exited for active Xray session"
                            << sessionId << exitCode << exitStatus;
                failCurrentSession(ErrorCode::Tun2SockExecutableCrashed,
                                   sessionId, generation);
            },
            Qt::QueuedConnection);

    process->start();
    auto started = process->waitForStarted(5000);
    if (!started.waitForFinished(6000) || !started.returnValue()) {
        QObject::disconnect(m_tunReadyConnection);
        QObject::disconnect(m_tunFinishedConnection);
        process->blockSignals(true);
        process->close();
        if (m_tun2socksProcess.data() == process.data()) {
            m_tun2socksProcess.reset();
        }
        return ErrorCode::Tun2SockExecutableCrashed;
    }
    return ErrorCode::NoError;
}

bool XrayProtocol::stopTun2Socks(
        const QSharedPointer<IpcProcessInterfaceReplica> &process)
{
    if (!process) {
        return true;
    }
    auto stateReply = process->state();
    if (stateReply.waitForFinished(1500)
            && stateReply.returnValue() == QProcess::NotRunning) {
        process->close();
        return true;
    }
#ifndef Q_OS_WIN
    process->terminate();
    auto wait = process->waitForFinished(1500);
    bool stopped = wait.waitForFinished(2500) && wait.returnValue();
    if (!stopped) {
        process->kill();
        auto killed = process->waitForFinished(1500);
        stopped = killed.waitForFinished(2500) && killed.returnValue();
    }
#else
    process->kill();
    auto killed = process->waitForFinished(1500);
    const bool stopped = killed.waitForFinished(2500) && killed.returnValue();
#endif
    auto finalState = process->state();
    const bool provenStopped = finalState.waitForFinished(1500)
            && finalState.returnValue() == QProcess::NotRunning;
    process->close();
    Q_UNUSED(stopped);
    return provenStopped;
}

QJsonObject XrayProtocol::queryRuntimeStatus(const QString &sessionId) const
{
    if (sessionId.isEmpty()) {
        return {};
    }
    return IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
        auto reply = iface->xrayRuntimeStatusV1(sessionId);
        if (!reply.waitForFinished(3000)) {
            return QJsonObject{};
        }
        return reply.returnValue();
    });
}

bool XrayProtocol::acceptRuntimeStatus(const QJsonObject &status,
                                       const QString &sessionId,
                                       bool updateCounters,
                                       bool publish)
{
    const QJsonObject core = status.value(QStringLiteral("core")).toObject();
    const QJsonObject counters = status.value(QStringLiteral("counters")).toObject();
    const QString state = status.value(QStringLiteral("runtime_state")).toString();
    const QString counterEpoch = counters.value(QStringLiteral("epoch")).toString();
    const QString returnedSession = status.value(QStringLiteral("session_id")).toString();
    const QString adapterVersion = core.value(QStringLiteral("adapter_version")).toString();
    const QString coreVersion = core.value(QStringLiteral("version")).toString();
    const bool stateValid = state == QLatin1String("starting")
            || state == QLatin1String("running")
            || state == QLatin1String("stopping")
            || state == QLatin1String("stopped")
            || state == QLatin1String("reconnecting")
            || state == QLatin1String("failed");

    quint64 rxBytes = 0;
    quint64 txBytes = 0;
    quint64 ignored = 0;
    quint64 resetCount = 0;
    bool countersValid = canonicalUint64(counters.value(QStringLiteral("rx_bytes")), &rxBytes)
            && canonicalUint64(counters.value(QStringLiteral("tx_bytes")), &txBytes)
            && canonicalUint64(counters.value(QStringLiteral("rx_packets")), &ignored)
            && canonicalUint64(counters.value(QStringLiteral("tx_packets")), &ignored)
            && canonicalUint64(counters.value(QStringLiteral("rx_bytes_delta")), &ignored)
            && canonicalUint64(counters.value(QStringLiteral("tx_bytes_delta")), &ignored)
            && canonicalUint64(counters.value(QStringLiteral("rx_packets_delta")), &ignored)
            && canonicalUint64(counters.value(QStringLiteral("tx_packets_delta")), &ignored)
            && canonicalUint64(counters.value(QStringLiteral("reset_count")), &resetCount);

    bool valid = status.value(QStringLiteral("type")).toString()
                    == QLatin1String("tunnel_runtime_status_v1")
            && status.value(QStringLiteral("schema")).isDouble()
            && status.value(QStringLiteral("schema")).toDouble() == 1.0
            && returnedSession == sessionId && isCanonicalUuid(returnedSession)
            && status.value(QStringLiteral("protocol")).toString() == QLatin1String("xray")
            && core.value(QStringLiteral("adapter")).toString()
                    == QLatin1String("amnezia-xray-bindings")
            && core.value(QStringLiteral("abi")).toString()
                    == QLatin1String("amnezia-xray-c-v1")
            && !adapterVersion.isEmpty() && adapterVersion != QLatin1String("unknown")
            && !coreVersion.isEmpty() && coreVersion != QLatin1String("unknown")
            && core.value(QStringLiteral("runtime_version_probed")).isBool()
            && stateValid && countersValid && counterEpoch == sessionId
            && counters.value(QStringLiteral("available")).isBool()
            && !counters.value(QStringLiteral("source")).toString().isEmpty();
#ifdef Q_OS_MACOS
    const QString protection = status.value(QStringLiteral("socket_protection")).toString();
    valid = valid && ((state == QLatin1String("running")
                       && protection == QLatin1String("verified"))
                      || (state != QLatin1String("running")
                          && (protection == QLatin1String("verified")
                              || protection == QLatin1String("failed")
                              || protection == QLatin1String("pending"))));
#endif
    if (!valid) {
        qWarning() << "Rejected incompatible/stale macOS Xray runtime status";
        return false;
    }

    if (m_haveRawCounters && resetCount < m_lastResetCount) {
        return false;
    }
    if (updateCounters && counters.value(QStringLiteral("available")).toBool()) {
        if (!m_haveRawCounters) {
            m_normalizedRx = rxBytes;
            m_normalizedTx = txBytes;
            m_haveRawCounters = true;
        } else if (rxBytes >= m_lastRawRx && txBytes >= m_lastRawTx) {
            m_normalizedRx = saturatingAdd(m_normalizedRx, rxBytes - m_lastRawRx);
            m_normalizedTx = saturatingAdd(m_normalizedTx, txBytes - m_lastRawTx);
        }
        // Backwards raw values are a rebase with zero delta, never underflow.
        m_lastRawRx = rxBytes;
        m_lastRawTx = txBytes;
        m_lastResetCount = resetCount;
        m_counterEpoch = counterEpoch;
        setBytesChanged(m_normalizedRx, m_normalizedTx);
    }

    m_runtimeStatus = status;
    if (publish) {
        emit runtimeStatusChanged(status);
    }
    return true;
}

void XrayProtocol::pollRuntimeStatus(const QString &sessionId, quint64 generation)
{
    if (!isCurrentSession(sessionId, generation)) {
        return;
    }
    const QJsonObject status = queryRuntimeStatus(sessionId);
    if (!acceptRuntimeStatus(status, sessionId, true)) {
        failCurrentSession(ErrorCode::XrayExecutableCrashed, sessionId, generation);
        return;
    }
    const QString state = status.value(QStringLiteral("runtime_state")).toString();
    if (state != QLatin1String("running")) {
        failCurrentSession(ErrorCode::XrayExecutableCrashed, sessionId, generation);
    }
}

void XrayProtocol::failCurrentSession(ErrorCode error, const QString &sessionId,
                                      quint64 generation)
{
    if (!isCurrentSession(sessionId, generation)) {
        return;
    }
    stop();
    setLastError(error);
}

bool XrayProtocol::isCurrentSession(const QString &sessionId, quint64 generation,
                                    const IpcProcessInterfaceReplica *process) const
{
    return !m_stopping && generation == m_operationGeneration
            && sessionId == m_runtimeSessionId
            && (process == nullptr || m_tun2socksProcess.data() == process);
}

bool XrayProtocol::cleanupRouting()
{
    return IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
        bool success = true;
        auto clearRoutes = iface->clearSavedRoutes();
        success = clearRoutes.waitForFinished(3000) && clearRoutes.returnValue() && success;

        auto deleteTun = iface->deleteTun(tunName);
        success = deleteTun.waitForFinished(3000) && deleteTun.returnValue() && success;

        auto restoreResolvers = iface->restoreResolvers();
        success = restoreResolvers.waitForFinished(3000)
                && restoreResolvers.returnValue() && success;

        auto startRoutingIpv6 = iface->StartRoutingIpv6();
        success = startRoutingIpv6.waitForFinished(3000)
                && startRoutingIpv6.returnValue() && success;

        // Legacy owns its kill switch. Catalog-v2 has an already-armed outer
        // root/PF lease which must survive AWG<->Xray inner replacement.
        if (success && !m_externallyGuarded) {
            auto disableKillSwitch = iface->disableKillSwitch();
            success = disableKillSwitch.waitForFinished(3000)
                    && disableKillSwitch.returnValue();
        }
        return success;
    });
}

ErrorCode XrayProtocol::setupRouting()
{
    return IpcClient::withInterface(
            [this](QSharedPointer<IpcInterfaceReplica> iface) -> ErrorCode {
#ifdef Q_OS_WIN
                const int inetAdapterIndex = NetworkUtilities::AdapterIndexTo(
                        QHostAddress(m_remoteAddress));
#endif
                auto createTun = iface->createTun(
                        tunName, amnezia::protocols::xray::defaultLocalAddr);
                if (!createTun.waitForFinished() || !createTun.returnValue()) {
                    return ErrorCode::InternalError;
                }

                auto updateResolvers = iface->updateResolvers(tunName, m_dnsServers);
                if (!updateResolvers.waitForFinished() || !updateResolvers.returnValue()) {
                    return ErrorCode::InternalError;
                }

#ifdef Q_OS_WIN
                int vpnAdapterIndex = -1;
                for (const QNetworkInterface &networkInterface : QNetworkInterface::allInterfaces()) {
                    for (const QNetworkAddressEntry &address : networkInterface.addressEntries()) {
                        if (m_vpnLocalAddress == address.ip().toString()) {
                            vpnAdapterIndex = networkInterface.index();
                        }
                    }
                }
#else
                static const int vpnAdapterIndex = 0;
#endif
                const bool killSwitchEnabled = QVariant(
                        m_rawConfig.value(configKey::killSwitchOption).toString()).toBool();
                if (!m_externallyGuarded && killSwitchEnabled && vpnAdapterIndex != -1) {
                    QJsonObject config = m_rawConfig;
                    config.insert(QStringLiteral("vpnServer"), m_remoteAddress);
                    auto enable = iface->enableKillSwitch(config, vpnAdapterIndex);
                    if (!enable.waitForFinished() || !enable.returnValue()) {
                        return ErrorCode::InternalError;
                    }
                }

                if (m_routeMode == amnezia::RouteMode::VpnAllSites) {
                    static const QStringList subnets = {
                        QStringLiteral("1.0.0.0/8"), QStringLiteral("2.0.0.0/7"),
                        QStringLiteral("4.0.0.0/6"), QStringLiteral("8.0.0.0/5"),
                        QStringLiteral("16.0.0.0/4"), QStringLiteral("32.0.0.0/3"),
                        QStringLiteral("64.0.0.0/2"), QStringLiteral("128.0.0.0/1")
                    };
                    auto addRoutes = iface->routeAddList(m_vpnGateway, subnets);
                    if (!addRoutes.waitForFinished()
                            || addRoutes.returnValue() != subnets.count()) {
                        return ErrorCode::InternalError;
                    }
                }

                auto stopRoutingIpv6 = iface->StopRoutingIpv6();
                if (!stopRoutingIpv6.waitForFinished() || !stopRoutingIpv6.returnValue()) {
                    return ErrorCode::InternalError;
                }

#ifdef Q_OS_WIN
                if (inetAdapterIndex != -1 && vpnAdapterIndex != -1) {
                    QJsonObject config = m_rawConfig;
                    config.insert(QStringLiteral("inetAdapterIndex"), inetAdapterIndex);
                    config.insert(QStringLiteral("vpnAdapterIndex"), vpnAdapterIndex);
                    config.insert(QStringLiteral("vpnGateway"), m_vpnGateway);
                    config.insert(QStringLiteral("vpnServer"), m_remoteAddress);
                    auto enablePeerTraffic = iface->enablePeerTraffic(config);
                    if (!enablePeerTraffic.waitForFinished()
                            || !enablePeerTraffic.returnValue()) {
                        return ErrorCode::InternalError;
                    }
                }
#endif
                return ErrorCode::NoError;
            },
            []() { return ErrorCode::AmneziaServiceConnectionFailed; });
}
