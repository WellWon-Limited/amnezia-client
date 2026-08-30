/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "daemon.h"

#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QMetaEnum>
#include <QTimer>
#include <QUuid>

#include "leakdetector.h"
#include "logger.h"
#ifdef Q_OS_MACOS
#  include "../platforms/macos/daemon/splitdnsresolverfiles.h" // AVPN (Tribe split-DNS)
#endif

constexpr const char* JSON_ALLOWEDIPADDRESSRANGES = "allowedIPAddressRanges";
constexpr int HANDSHAKE_POLL_MSEC = 250;

#ifndef TRIBE_AWG_ENGINE_VERSION
#define TRIBE_AWG_ENGINE_VERSION "unknown"
#endif
#ifndef TRIBE_AWG_CORE_VERSION
#define TRIBE_AWG_CORE_VERSION TRIBE_AWG_ENGINE_VERSION
#endif
#ifndef TRIBE_AWG_UAPI_ABI
#define TRIBE_AWG_UAPI_ABI "unknown"
#endif

#ifdef Q_OS_WIN
// AVPN win-fix (BUG-12, 2026-07-30): размер порции фонового досева исключений.
// Одна порция = 64 префикса ≈ 0.14с работы (маршруты ~3200/с, WFP-фильтры ~540/с по замеру
// на живом стенде), то есть короче периода handshake-поллера (250мс) — поллер успевает
// отдать клиенту `connected`, пока досев идёт фоном.
constexpr int EXCLUSION_CHUNK_SIZE = 64;
#endif

namespace {

Logger logger("Daemon");

Daemon* s_daemon = nullptr;

}  // namespace

Daemon::Daemon(QObject* parent) : QObject(parent) {
  MZ_COUNT_CTOR(Daemon);

  logger.debug() << "Daemon created";

  Q_ASSERT(s_daemon == nullptr);
  s_daemon = this;

  m_handshakeTimer.setSingleShot(true);
  connect(&m_handshakeTimer, &QTimer::timeout, this, &Daemon::checkHandshake);

#ifdef Q_OS_WIN
  // AVPN win-fix (BUG-12): тик фонового досева исключений (см. startDeferredExclusions)
  m_exclusionSeedTimer.setSingleShot(true);
  m_exclusionSeedTimer.setInterval(0);
  connect(&m_exclusionSeedTimer, &QTimer::timeout, this,
          &Daemon::seedExclusionChunk);
#endif
}

Daemon::~Daemon() {
  MZ_COUNT_DTOR(Daemon);

  logger.debug() << "Daemon released";

  Q_ASSERT(s_daemon == this);
  s_daemon = nullptr;
}

// static
Daemon* Daemon::instance() {
  Q_ASSERT(s_daemon);
  return s_daemon;
}

bool Daemon::activateExactSession(const InterfaceConfig& config,
                                  const QString& sessionId) {
  const QUuid uuid(sessionId);
  if (uuid.isNull()
      || uuid.toString(QUuid::WithoutBraces).toLower() != sessionId
      || (!m_nativeSessionId.isEmpty()
          && m_nativeRuntimeState != QLatin1String("stopped"))) {
    return false;
  }
  m_nativeSessionId = sessionId;
  m_nativeRuntimeState = QStringLiteral("starting");
  m_nativeFailureReason.clear();
  m_nativeLastRx = m_nativeLastTx = m_nativeResetCount = 0;
  m_nativeHaveCounters = false;
  if (!activate(config)) {
    m_nativeRuntimeState = QStringLiteral("failed");
    m_nativeFailureReason = QStringLiteral("awg_activate_failed");
    return false;
  }
  return true;
}

bool Daemon::deactivateExactSession(const QString& sessionId) {
  if (sessionId.isEmpty() || sessionId != m_nativeSessionId
      || m_nativeRuntimeState == QLatin1String("stopped")) {
    return false;
  }
  m_nativeRuntimeState = QStringLiteral("stopping");
  const bool stopped = deactivate(true) && !wgutils()->interfaceExists()
                       && m_connections.isEmpty() && m_excludedAddrSet.isEmpty();
  m_nativeRuntimeState = stopped ? QStringLiteral("stopped")
                                 : QStringLiteral("failed");
  m_nativeFailureReason = stopped ? QString() : QStringLiteral("awg_teardown_failed");
  return stopped;
}

QJsonObject Daemon::runtimeStatusV1(const QString& sessionId) {
  const QUuid uuid(sessionId);
  if (uuid.isNull()
      || uuid.toString(QUuid::WithoutBraces).toLower() != sessionId
      || sessionId != m_nativeSessionId) {
    return {};
  }

  quint64 rx = m_nativeLastRx;
  quint64 tx = m_nativeLastTx;
  quint64 rxDelta = 0;
  quint64 txDelta = 0;
  quint64 handshakeSeconds = 0;
  bool available = false;
  if (wgutils()->interfaceExists() && !m_connections.isEmpty()) {
    const QString publicKey = m_connections.first().m_config.m_serverPublicKey;
    const QList<WireguardUtils::PeerStatus> peers = wgutils()->getPeerStatus();
    for (const WireguardUtils::PeerStatus& peer : peers) {
      if (peer.m_pubkey != publicKey) continue;
      available = peer.m_rxBytes >= 0 && peer.m_txBytes >= 0;
      if (available) {
        rx = quint64(peer.m_rxBytes);
        tx = quint64(peer.m_txBytes);
        if (m_nativeHaveCounters) {
          if (rx >= m_nativeLastRx && tx >= m_nativeLastTx) {
            rxDelta = rx - m_nativeLastRx;
            txDelta = tx - m_nativeLastTx;
          } else {
            ++m_nativeResetCount;
          }
        }
        m_nativeHaveCounters = true;
        m_nativeLastRx = rx;
        m_nativeLastTx = tx;
      }
      if (peer.m_handshake > 0) {
        handshakeSeconds = quint64(peer.m_handshake) / 1000;
        if (m_nativeRuntimeState == QLatin1String("starting"))
          m_nativeRuntimeState = QStringLiteral("running");
      }
      break;
    }
  }
  if (m_nativeRuntimeState == QLatin1String("running") && !available) {
    m_nativeRuntimeState = QStringLiteral("failed");
    m_nativeFailureReason = QStringLiteral("awg_uapi_status_unavailable");
  }

  const QJsonObject core{
      {QStringLiteral("adapter"), QStringLiteral("awg-go")},
      {QStringLiteral("version"), QStringLiteral(TRIBE_AWG_CORE_VERSION)},
      {QStringLiteral("runtime_version_probed"), false},
      {QStringLiteral("abi"), QStringLiteral(TRIBE_AWG_UAPI_ABI)},
  };
  const QJsonObject counters{
      {QStringLiteral("available"), available},
      {QStringLiteral("source"), available ? QStringLiteral("awg_uapi_peer_status")
                                            : QStringLiteral("unavailable")},
      {QStringLiteral("epoch"), m_nativeSessionId},
      {QStringLiteral("rx_bytes"), QString::number(rx)},
      {QStringLiteral("tx_bytes"), QString::number(tx)},
      {QStringLiteral("rx_packets"), QStringLiteral("0")},
      {QStringLiteral("tx_packets"), QStringLiteral("0")},
      {QStringLiteral("rx_bytes_delta"), QString::number(rxDelta)},
      {QStringLiteral("tx_bytes_delta"), QString::number(txDelta)},
      {QStringLiteral("rx_packets_delta"), QStringLiteral("0")},
      {QStringLiteral("tx_packets_delta"), QStringLiteral("0")},
      {QStringLiteral("reset_count"), QString::number(m_nativeResetCount)},
  };
  QJsonObject status{
      {QStringLiteral("type"), QStringLiteral("tunnel_runtime_status_v1")},
      {QStringLiteral("schema"), 1},
      {QStringLiteral("session_id"), m_nativeSessionId},
      {QStringLiteral("protocol"), QStringLiteral("awg")},
      {QStringLiteral("runtime_state"), m_nativeRuntimeState},
      {QStringLiteral("core"), core},
      {QStringLiteral("counters"), counters},
      {QStringLiteral("rx_bytes"), QString::number(rx)},
      {QStringLiteral("tx_bytes"), QString::number(tx)},
      {QStringLiteral("last_handshake_time_sec"), handshakeSeconds > 0
           ? QJsonValue(QString::number(handshakeSeconds)) : QJsonValue::Null},
  };
  if (!m_nativeFailureReason.isEmpty())
    status.insert(QStringLiteral("failure_reason"), m_nativeFailureReason);
  return status;
}

bool Daemon::activate(const InterfaceConfig& config) {
  Q_ASSERT(wgutils() != nullptr);

  // There are 3 possible scenarios in which this method is called:
  //
  // 1. the VPN is off: the method tries to enable the VPN.
  // 2. the VPN is on and the platform doesn't support the server-switching:
  //    this method calls deactivate() and then it continues as 1.
  // 3. the VPN is on and the platform supports the server-switching: this
  //    method calls switchServer().
  //
  // At the end, if the activation succeds, the `connected` signal is emitted.
  // If the activation abort's for any reason `the `activationFailure` signal is
  // emitted.
  logger.debug() << "Activating interface";
  auto emit_failure_guard = qScopeGuard([this] { emit activationFailure(); });

  if (m_connections.contains(config.m_hopType)) {
    if (supportServerSwitching(config)) {
      logger.debug() << "Already connected. Server switching supported.";

      if (!switchServer(config)) {
        return false;
      }

      if (!dnsutils()->restoreResolvers()) {
        return false;
      }

      if (!maybeUpdateResolvers(config)) {
        return false;
      }

      bool status = run(Switch, config);
      logger.debug() << "Connection status:" << status;
      if (status) {
        m_connections[config.m_hopType] = ConnectionState(config);
        m_handshakeTimer.start(HANDSHAKE_POLL_MSEC);
        emit_failure_guard.dismiss();
        return true;
      }
      return false;
    }

    logger.warning() << "Already connected. Server switching not supported.";
    if (!deactivate(false)) {
      return false;
    }

    Q_ASSERT(!m_connections.contains(config.m_hopType));
    if (activate(config)) {
      emit_failure_guard.dismiss();
      return true;
    }
    return false;
  }

  prepareActivation(config);

  // Bring up the wireguard interface if not already done.
  if (!wgutils()->interfaceExists()) {
    // Create the interface.
    if (!wgutils()->addInterface(config)) {
      logger.error() << "Interface creation failed.";
      return false;
    }
  }

  // Bring the interface up.
  if (supportIPUtils()) {
    if (!iputils()->addInterfaceIPs(config)) {
      return false;
    }
    if (!iputils()->setMTUAndUp(config)) {
      return false;
    }
  }

  // Configure routing for excluded addresses.
  // AVPN win-fix: bulk-окно — на Windows схлопывает O(N²) пересчёт таблицы (RU-direct ~8.6k
  // префиксов = «бесконечный коннект»); на прочих платформах begin/end — no-op, поведение как было.
#ifdef Q_OS_WIN
  // AVPN win-fix (BUG-12, 2026-07-30): на Windows массовый список исключений НЕ сеем здесь —
  // он уходит в фоновый досев после подъёма туннеля (startDeferredExclusions ниже). Иначе
  // маршруты (~2.7с) плюс WFP-разрешения kill-switch (~16с, внутри updatePeer) держат event
  // loop демона ~19с, handshake-поллер не тикает, клиент по своему сторожу шлёт deactivate —
  // ровно в тот момент, когда туннель уже готов. Список исключений вырезаем и из конфига,
  // который отдаём в updatePeer, чтобы enablePeerTraffic не крутил тот же цикл синхронно.
  const QStringList deferredExclusions = config.m_excludedAddresses;
  InterfaceConfig fastConfig = config;
  fastConfig.m_excludedAddresses.clear();
  const InterfaceConfig& peerConfig = fastConfig;
#else
  wgutils()->beginBulkExclusion();
  for (const QString& i : config.m_excludedAddresses) {
    addExclusionRoute(IPAddress(i));
  }
  wgutils()->endBulkExclusion();
  const InterfaceConfig& peerConfig = config;
#endif

  // Add the peer to this interface.
  if (!wgutils()->updatePeer(peerConfig)) {
    logger.error() << "Peer creation failed.";
    return false;
  }

  if (!maybeUpdateResolvers(config)) {
    return false;
  }

  // set routing
  for (const IPAddress& ip : config.m_allowedIPAddressRanges) {
    if (!wgutils()->updateRoutePrefix(ip)) {
      logger.debug() << "Routing configuration failed for" << ip.toString();
      return false;
    }
  }

  bool status = run(Up, config);
  logger.debug() << "Connection status:" << status;
  if (status) {
    m_connections[config.m_hopType] = ConnectionState(config);
    m_handshakeTimer.start(HANDSHAKE_POLL_MSEC);
#ifdef Q_OS_WIN
    // AVPN win-fix (BUG-12): туннель поднят и поллер взведён — теперь можно досеивать
    // исключения фоном, не мешая клиенту получить `connected`.
    startDeferredExclusions(deferredExclusions, config.m_serverPublicKey);
#endif
    emit_failure_guard.dismiss();
    return true;
  }
  return false;
}

#ifdef Q_OS_WIN
// AVPN win-fix (BUG-12, 2026-07-30) — фоновый досев исключений RU-direct.
// Инвариант CONNECT-INVARIANTS §15 соблюдён: весь массовый посев по-прежнему идёт внутри
// одного bulk-окна (оно открывается перед первой порцией и закрывается после последней),
// метрика и протокол маршрутов не меняются, purge сирот на месте.
// Безопасность: пока досев не закончен, ещё не разрешённые адреса идут ЧЕРЕЗ туннель —
// kill-switch остаётся fail-closed, прямых утечек мимо VPN не возникает.
void Daemon::startDeferredExclusions(const QStringList& addresses,
                                     const QString& pubkey) {
  cancelDeferredExclusions();
  if (addresses.isEmpty()) {
    return;
  }

  m_deferredExclusions = addresses;
  m_deferredExclusionsPubkey = pubkey;
  logger.debug() << "Deferred exclusion seeding scheduled for"
                 << addresses.count() << "prefixes";

  wgutils()->beginBulkExclusion();
  m_exclusionBulkOpen = true;
  m_exclusionSeedTimer.start();
}

void Daemon::seedExclusionChunk() {
  // Туннель успели опустить (deactivate/switchServer) — досев больше не нужен.
  if (m_connections.isEmpty() || m_deferredExclusions.isEmpty()) {
    cancelDeferredExclusions();
    return;
  }

  QStringList chunk;
  const int take = qMin(EXCLUSION_CHUNK_SIZE, m_deferredExclusions.count());
  chunk.reserve(take);
  for (int i = 0; i < take; ++i) {
    chunk.append(m_deferredExclusions.takeFirst());
  }

  // Сначала разрешение в файрволе, затем маршрут: обратный порядок на мгновение оставил бы
  // адрес с маршрутом «напрямую», но без allow-фильтра — kill-switch дропал бы такой трафик.
  if (!wgutils()->allowExcludedTrafficChunk(chunk, m_deferredExclusionsPubkey)) {
    logger.warning() << "Exclusion chunk rejected by firewall; aborting seeding";
    cancelDeferredExclusions();
    return;
  }
  for (const QString& i : chunk) {
    addExclusionRoute(IPAddress(i));
  }

  if (m_deferredExclusions.isEmpty()) {
    logger.debug() << "Deferred exclusion seeding finished";
    cancelDeferredExclusions();
    return;
  }
  m_exclusionSeedTimer.start();
}

void Daemon::cancelDeferredExclusions() {
  m_exclusionSeedTimer.stop();
  m_deferredExclusions.clear();
  m_deferredExclusionsPubkey.clear();
  if (m_exclusionBulkOpen) {
    // Окно обязано закрыться на ЛЮБОМ выходе (инвариант §15) — иначе кэш таблицы маршрутов
    // останется висеть, а captured-routes не пересчитаются.
    wgutils()->endBulkExclusion();
    m_exclusionBulkOpen = false;
  }
}
#endif

bool Daemon::maybeUpdateResolvers(const InterfaceConfig& config) {
  if ((config.m_hopType == InterfaceConfig::MultiHopExit) ||
      (config.m_hopType == InterfaceConfig::SingleHop)) {
    QList<QHostAddress> resolvers;
    resolvers.append(QHostAddress(config.m_primaryDnsServer));
    if (!config.m_secondaryDnsServer.isEmpty()) {
        resolvers.append(QHostAddress(config.m_secondaryDnsServer));
    }

    // If the DNS is not the Gateway, it's a user defined DNS
    // thus, not add any other :)
    if (config.m_primaryDnsServer == config.m_serverIpv4Gateway) {
      resolvers.append(QHostAddress(config.m_serverIpv6Gateway));
    }

    if (!dnsutils()->updateResolvers(wgutils()->interfaceName(), resolvers)) {
      return false;
    }

#ifdef Q_OS_MACOS
    // AVPN (Tribe split-DNS): RU-суффиксы → отдельный резолвер мимо туннеля (/etc/resolver/*).
    // apply = реконсиляция (пустой список → только очистка). См. splitdnsresolverfiles.h.
    SplitDnsResolverFiles::apply(config.m_splitDnsSuffixes, config.m_splitDnsServer);
#endif
  }

  return true;
}

// static
bool Daemon::parseStringList(const QJsonObject& obj, const QString& name,
                             QStringList& list) {
  if (obj.contains(name)) {
    QJsonValue value = obj.value(name);
    if (!value.isArray()) {
      logger.error() << name << "is not an array";
      return false;
    }
    QJsonArray array = value.toArray();
    for (const QJsonValue& i : array) {
      if (!i.isString()) {
        logger.error() << name << "must contain only strings";
        return false;
      }
      list.append(i.toString());
    }
  }
  return true;
}

bool Daemon::addExclusionRoute(const IPAddress& prefix) {
  if (m_excludedAddrSet.contains(prefix)) {
    m_excludedAddrSet[prefix]++;
    return true;
  }
  if (!wgutils()->addExclusionRoute(prefix)) {
    return false;
  }
  m_excludedAddrSet[prefix] = 1;
  return true;
}

bool Daemon::delExclusionRoute(const IPAddress& prefix) {
  Q_ASSERT(m_excludedAddrSet.contains(prefix));
  if (m_excludedAddrSet[prefix] > 1) {
    m_excludedAddrSet[prefix]--;
    return true;
  }
  m_excludedAddrSet.remove(prefix);
  return wgutils()->deleteExclusionRoute(prefix);
}

// static
bool Daemon::parseConfig(const QJsonObject& obj, InterfaceConfig& config) {
#define GETVALUE(name, where, jsontype)                           \
  if (!obj.contains(name)) {                                      \
    logger.debug() << name << " missing in the jsonConfig input"; \
    return false;                                                 \
  } else {                                                        \
    QJsonValue value = obj.value(name);                           \
    if (value.type() != QJsonValue::jsontype) {                   \
      logger.error() << name << " is not a " #jsontype;           \
      return false;                                               \
    }                                                             \
    where = value.to##jsontype();                                 \
  }

  GETVALUE("privateKey", config.m_privateKey, String);
  GETVALUE("serverPublicKey", config.m_serverPublicKey, String);
  GETVALUE("serverPort", config.m_serverPort, Double);

  config.m_serverPskKey = obj.value("serverPskKey").toString();

  if (!obj.contains("deviceMTU") || obj.value("deviceMTU").toString().toInt() == 0)
  {
    config.m_deviceMTU = 1420;
  } else {
    config.m_deviceMTU = obj.value("deviceMTU").toString().toInt();
#ifdef Q_OS_WINDOWS
// For Windows min MTU value is 1280 (the smallest MTU legal with IPv6).
    if (config.m_deviceMTU < 1280) {
      config.m_deviceMTU = 1280;
    }
#endif
  }

  config.m_persistentKeepalive = obj.value("persistentKeepalive").toString();

  config.m_deviceIpv4Address = obj.value("deviceIpv4Address").toString();
  config.m_deviceIpv6Address = obj.value("deviceIpv6Address").toString();
  if (config.m_deviceIpv4Address.isNull() &&
      config.m_deviceIpv6Address.isNull()) {
    logger.warning() << "no device addresses found in jsonConfig input";
    return false;
  }
  config.m_serverIpv4AddrIn = obj.value("serverIpv4AddrIn").toString();
  config.m_serverIpv6AddrIn = obj.value("serverIpv6AddrIn").toString();
  if (config.m_serverIpv4AddrIn.isNull() &&
      config.m_serverIpv6AddrIn.isNull()) {
    logger.error() << "no server addresses found in jsonConfig input";
    return false;
  }
  config.m_serverIpv4Gateway = obj.value("serverIpv4Gateway").toString();
  config.m_serverIpv6Gateway = obj.value("serverIpv6Gateway").toString();

  if (!obj.contains("primaryDnsServer")) {
    config.m_primaryDnsServer = QString();
  } else {
    QJsonValue value = obj.value("primaryDnsServer");
    if (!value.isString()) {
      logger.error() << "dnsServer is not a string";
      return false;
    }
    config.m_primaryDnsServer = value.toString();
  }

  if (!obj.contains("secondaryDnsServer")) {
    config.m_secondaryDnsServer = QString();
  } else {
    QJsonValue value = obj.value("secondaryDnsServer");
    if (!value.isString()) {
      logger.error() << "dnsServer is not a string";
      return false;
    }
    config.m_secondaryDnsServer = value.toString();
  }

  if (!obj.contains("hopType")) {
    config.m_hopType = InterfaceConfig::SingleHop;
  } else {
    QJsonValue value = obj.value("hopType");
    if (!value.isString()) {
      logger.error() << "hopType is not a string";
      return false;
    }

    bool okay;
    QByteArray vdata = value.toString().toUtf8();
    QMetaEnum meta = QMetaEnum::fromType<InterfaceConfig::HopType>();
    config.m_hopType =
        InterfaceConfig::HopType(meta.keyToValue(vdata.constData(), &okay));
    if (!okay) {
      logger.error() << "hopType" << value.toString() << "is not valid";
      return false;
    }
  }

  if (!obj.contains(JSON_ALLOWEDIPADDRESSRANGES)) {
    logger.error() << JSON_ALLOWEDIPADDRESSRANGES
                   << "missing in the jsonconfig input";
    return false;
  } else {
    QJsonValue value = obj.value(JSON_ALLOWEDIPADDRESSRANGES);
    if (!value.isArray()) {
      logger.error() << JSON_ALLOWEDIPADDRESSRANGES << "is not an array";
      return false;
    }

    QJsonArray array = value.toArray();
    for (const QJsonValue& i : array) {
      if (!i.isObject()) {
        logger.error() << JSON_ALLOWEDIPADDRESSRANGES
                       << "must contain only objects";
        return false;
      }

      QJsonObject ipObj = i.toObject();

      QJsonValue address = ipObj.value("address");
      if (!address.isString()) {
        logger.error() << JSON_ALLOWEDIPADDRESSRANGES
                       << "objects must have a string address";
        return false;
      }

      QJsonValue range = ipObj.value("range");
      if (!range.isDouble()) {
        logger.error() << JSON_ALLOWEDIPADDRESSRANGES
                       << "object must have a numberic range";
        return false;
      }

      QJsonValue isIpv6 = ipObj.value("isIpv6");
      if (!isIpv6.isBool()) {
        logger.error() << JSON_ALLOWEDIPADDRESSRANGES
                       << "object must have a boolean isIpv6";
        return false;
      }

      config.m_allowedIPAddressRanges.append(
          IPAddress(QHostAddress(address.toString()), range.toInt()));
    }

    // Sort allowed IPs by decreasing prefix length.
    std::sort(config.m_allowedIPAddressRanges.begin(),
              config.m_allowedIPAddressRanges.end(),
              [&](const IPAddress& a, const IPAddress& b) -> bool {
                return a.prefixLength() > b.prefixLength();
              });
  }

  if (!parseStringList(obj, "excludedAddresses", config.m_excludedAddresses)) {
    return false;
  }
  if (!parseStringList(obj, "vpnDisabledApps", config.m_vpnDisabledApps)) {
    return false;
  }
  if (!parseStringList(obj, "allowedDnsServers", config.m_allowedDnsServers)) {
    return false;
  }
  // AVPN (Tribe split-DNS): опциональные поля (нет в конфиге = выключено, парс не валим)
  if (obj.contains("splitDnsSuffixes") &&
      !parseStringList(obj, "splitDnsSuffixes", config.m_splitDnsSuffixes)) {
    return false;
  }
  config.m_splitDnsServer = obj.value("splitDnsServer").toString();

  config.m_killSwitchEnabled = QVariant(obj.value("killSwitchOption").toString()).toBool();

  if (const auto jc = obj.value("Jc"); !jc.isUndefined()) {
    config.m_junkPacketCount = jc.toString();
  }
  if (const auto jmin = obj.value("Jmin"); !jmin.isUndefined()) {
    config.m_junkPacketMinSize = jmin.toString();
  }
  if (const auto jmax = obj.value("Jmax"); !jmax.isUndefined()) {
    config.m_junkPacketMaxSize = jmax.toString();
  }
  if (const auto s1 = obj.value("S1"); !s1.isUndefined()) {
    config.m_initPacketJunkSize = s1.toString();
  }
  if (const auto s2 = obj.value("S2"); !s2.isUndefined()) {
    config.m_responsePacketJunkSize = s2.toString();
  }
  if (const auto s3 = obj.value("S3"); !s3.isUndefined()) {
    config.m_cookieReplyPacketJunkSize = s3.toString();
  }
  if (const auto s4 = obj.value("S4"); !s4.isUndefined()) {
    config.m_transportPacketJunkSize = s4.toString();
  }

  if (const auto h1 = obj.value("H1"); !h1.isUndefined()) {
    config.m_initPacketMagicHeader = h1.toString();
  }
  if (const auto h2 = obj.value("H2"); !h2.isUndefined()) {
    config.m_responsePacketMagicHeader = h2.toString();
  }
  if (const auto h3 = obj.value("H3"); !h3.isUndefined()) {
    config.m_underloadPacketMagicHeader = h3.toString();
  }
  if (const auto h4 = obj.value("H4"); !h4.isUndefined()) {
    config.m_transportPacketMagicHeader = h4.toString();
  }

  if (const auto i1 = obj.value("I1"); !i1.isUndefined()) {
    config.m_specialJunk["I1"] = i1.toString();
  }
  if (const auto i2 = obj.value("I2"); !i2.isUndefined()) {
    config.m_specialJunk["I2"] = i2.toString();
  }
  if (const auto i3 = obj.value("I3"); !i3.isUndefined()) {
    config.m_specialJunk["I3"] = i3.toString();
  }
  if (const auto i4 = obj.value("I4"); !i4.isUndefined()) {
    config.m_specialJunk["I4"] = i4.toString();
  }
  if (const auto i5 = obj.value("I5"); !i5.isUndefined()) {
    config.m_specialJunk["I5"] = i5.toString();
  }

  if (const auto headerProtectionKey = obj.value("HeaderProtectionKey"); !headerProtectionKey.isUndefined()) {
    config.m_headerProtectionKey = headerProtectionKey.toString();
  }
  if (const auto contentPaddingAddition = obj.value("ContentPaddingAddition"); !contentPaddingAddition.isUndefined()) {
    config.m_contentPaddingAddition = contentPaddingAddition.toString();
  }
  if (const auto rekeyAfterTime = obj.value("RekeyAfterTime"); !rekeyAfterTime.isUndefined()) {
    config.m_rekeyAfterTime = rekeyAfterTime.toString();
  }
  if (const auto rekeyTimeout = obj.value("RekeyTimeout"); !rekeyTimeout.isUndefined()) {
    config.m_rekeyTimeout = rekeyTimeout.toString();
  }
  if (const auto rejectAfterTime = obj.value("RejectAfterTime"); !rejectAfterTime.isUndefined()) {
    config.m_rejectAfterTime = rejectAfterTime.toString();
  }
  if (const auto keepaliveTimeout = obj.value("KeepaliveTimeout"); !keepaliveTimeout.isUndefined()) {
    config.m_keepaliveTimeout = keepaliveTimeout.toString();
  }
  if (const auto maxHandshakeAttempts = obj.value("MaxHandshakeAttempts"); !maxHandshakeAttempts.isUndefined()) {
    config.m_maxHandshakeAttempts = maxHandshakeAttempts.toString();
  }
  // AVPN: these values alter the AWG 3.1 wire format.  Reject malformed
  // JSON/types/values before touching the interface instead of coercing to 0.
  if (const auto randomTrailers = obj.value("RandomTrailers"); !randomTrailers.isUndefined()) {
    if (!randomTrailers.isString() ||
        !InterfaceConfig::awgBoolToUapi(randomTrailers.toString(), config.m_randomTrailers)) {
      logger.error() << "RandomTrailers is not a supported AWG boolean";
      return false;
    }
  }
  if (const auto disableCookies = obj.value("DisableCookies"); !disableCookies.isUndefined()) {
    if (!disableCookies.isString() ||
        !InterfaceConfig::awgBoolToUapi(disableCookies.toString(), config.m_disableCookies)) {
      logger.error() << "DisableCookies is not a supported AWG boolean";
      return false;
    }
  }

  return true;
}

bool Daemon::deactivate(bool emitSignals) {
  Q_ASSERT(wgutils() != nullptr);
  bool success = true;

#ifdef Q_OS_WIN
  // AVPN win-fix (BUG-12): фоновый досев исключений принадлежит уходящей сессии — снять до
  // разбора туннеля, иначе тик обратится к уже опущенному интерфейсу.
  cancelDeferredExclusions();
#endif

  // Deactivate the main interface.
  if (!m_connections.isEmpty()) {
    const ConnectionState& state = m_connections.first();
    if (!run(Down, state.m_config)) {
      return false;
    }
  }

  if (emitSignals) {
    emit disconnected();
  }

  // Cleanup DNS
  if (!dnsutils()->restoreResolvers()) {
    logger.warning() << "Failed to restore DNS resolvers.";
    success = false;
  }

#ifdef Q_OS_MACOS
  // AVPN (Tribe split-DNS): убрать наши /etc/resolver/* (по маркеру; чужие файлы не трогаем)
  SplitDnsResolverFiles::clear();
#endif

  // Cleanup peers and routing
  for (const ConnectionState& state : m_connections) {
    const InterfaceConfig& config = state.m_config;
    logger.debug() << "Deleting routes for" << config.m_hopType;
    for (const IPAddress& ip : config.m_allowedIPAddressRanges) {
      success = wgutils()->deleteRoutePrefix(ip) && success;
    }
    success = wgutils()->deletePeer(config) && success;
  }

  // Cleanup routing for excluded addresses.
  for (auto iterator = m_excludedAddrSet.constBegin();
       iterator != m_excludedAddrSet.constEnd(); ++iterator) {
    success = wgutils()->deleteExclusionRoute(iterator.key()) && success;
  }
  m_excludedAddrSet.clear();

  m_connections.clear();
  // Delete the interface
  success = wgutils()->deleteInterface() && success;
  return success;
}

QString Daemon::logs() {
  return {};
}

void Daemon::cleanLogs() { }

bool Daemon::supportServerSwitching(const InterfaceConfig& config) const {
  if (!m_connections.contains(config.m_hopType)) {
    return false;
  }
  const InterfaceConfig& current =
      m_connections.value(config.m_hopType).m_config;

  return current.m_privateKey == config.m_privateKey &&
         current.m_deviceIpv4Address == config.m_deviceIpv4Address &&
         current.m_deviceIpv6Address == config.m_deviceIpv6Address &&
         current.m_serverIpv4Gateway == config.m_serverIpv4Gateway &&
         current.m_serverIpv6Gateway == config.m_serverIpv6Gateway;
}

bool Daemon::switchServer(const InterfaceConfig& config) {
  Q_ASSERT(wgutils() != nullptr);

  logger.debug() << "Switching server for" << config.m_hopType;

  Q_ASSERT(m_connections.contains(config.m_hopType));
  const InterfaceConfig& lastConfig =
      m_connections.value(config.m_hopType).m_config;

  // Configure routing for new excluded addresses.
  // AVPN win-fix: bulk-окно (см. activate) — Windows-only оптимизация, на прочих no-op.
#ifdef Q_OS_WIN
  // AVPN win-fix (BUG-12): при смене сервера действует то же правило, что и в activate —
  // массовый список исключений не держит окно переключения, а досеивается фоном.
  const QStringList deferredExclusions = config.m_excludedAddresses;
  InterfaceConfig fastConfig = config;
  fastConfig.m_excludedAddresses.clear();
  const InterfaceConfig& peerConfig = fastConfig;
  cancelDeferredExclusions();
#else
  wgutils()->beginBulkExclusion();
  for (const QString& i : config.m_excludedAddresses) {
    addExclusionRoute(IPAddress(i));
  }
  wgutils()->endBulkExclusion();
  const InterfaceConfig& peerConfig = config;
#endif

  // Activate the new peer and its routes.
  if (!wgutils()->updatePeer(peerConfig)) {
    logger.error() << "Server switch failed to update the wireguard interface";
    return false;
  }
  for (const IPAddress& ip : config.m_allowedIPAddressRanges) {
    if (!wgutils()->updateRoutePrefix(ip)) {
      logger.error() << "Server switch failed to update the routing table";
      break;
    }
  }

  // Remove routing entries for the old peer.
  for (const QString& i : lastConfig.m_excludedAddresses) {
    delExclusionRoute(QHostAddress(i));
  }
  for (const IPAddress& ip : lastConfig.m_allowedIPAddressRanges) {
    if (!config.m_allowedIPAddressRanges.contains(ip)) {
      wgutils()->deleteRoutePrefix(ip);
    }
  }

  // Remove the old peer if it is no longer necessary.
  if (config.m_serverPublicKey != lastConfig.m_serverPublicKey) {
    if (!wgutils()->deletePeer(lastConfig)) {
      return false;
    }
  }

  m_connections[config.m_hopType] = ConnectionState(config);
#ifdef Q_OS_WIN
  // AVPN win-fix (BUG-12): новый пир на месте — досеиваем его исключения фоном.
  startDeferredExclusions(deferredExclusions, config.m_serverPublicKey);
#endif
  return true;
}

QJsonObject Daemon::getStatus() {
  Q_ASSERT(wgutils() != nullptr);
  QJsonObject json;
  logger.debug() << "Status request";

  if (!wgutils()->interfaceExists() || m_connections.isEmpty()) {
    json.insert("connected", QJsonValue(false));
    return json;
  }

  const ConnectionState& connection = m_connections.first();
  QList<WireguardUtils::PeerStatus> peers = wgutils()->getPeerStatus();
  for (const WireguardUtils::PeerStatus& status : peers) {
    if (status.m_pubkey != connection.m_config.m_serverPublicKey) {
      continue;
    }
    json.insert("connected", QJsonValue(true));
    json.insert("serverIpv4Gateway",
                QJsonValue(connection.m_config.m_serverIpv4Gateway));
    json.insert("deviceIpv4Address",
                QJsonValue(connection.m_config.m_deviceIpv4Address));
    json.insert("date", connection.m_date.toString());
    json.insert("txBytes", QJsonValue(status.m_txBytes));
    json.insert("rxBytes", QJsonValue(status.m_rxBytes));
    return json;
  }

  json.insert("connected", QJsonValue(false));
  return json;
}

void Daemon::checkHandshake() {
  Q_ASSERT(wgutils() != nullptr);

  logger.debug() << "Checking for handshake...";

  int pendingHandshakes = 0;
  QList<WireguardUtils::PeerStatus> peers = wgutils()->getPeerStatus();
  for (ConnectionState& connection : m_connections) {
    const InterfaceConfig& config = connection.m_config;
    if (connection.m_date.isValid()) {
      continue;
    }
    logger.debug() << "awaiting" << config.m_serverPublicKey;

    // Check if the handshake has completed.
    for (const WireguardUtils::PeerStatus& status : peers) {
      if (config.m_serverPublicKey != status.m_pubkey) {
        continue;
      }
      if (status.m_handshake != 0) {
        connection.m_date.setMSecsSinceEpoch(status.m_handshake);
        emit connected(status.m_pubkey);
      }
    }

    if (!connection.m_date.isValid()) {
      pendingHandshakes++;
    }
  }

  // Check again if there were connections that haven't completed a handshake.
  if (pendingHandshakes > 0) {
    m_handshakeTimer.start(HANDSHAKE_POLL_MSEC);
  }
}
