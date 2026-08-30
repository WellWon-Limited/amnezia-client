/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "wireguardutilsmacos.h"

#include <errno.h>
#include <net/route.h>

#include <QByteArray>
#include <QDir>
#include <QFile>
#include <QLocalSocket>
#include <QTimer>

#include "leakdetector.h"
#include "logger.h"

#include "killswitch.h"

constexpr const int WG_TUN_PROC_TIMEOUT = 15000; // AVPN: было 5000 — мало для первого старта amneziawg-go под демоном (создание utun + проверка подписи) → таймаут → демон убивал процесс
constexpr const char* WG_RUNTIME_DIR = "/var/run/amneziawg"; // AVPN: ДОЛЖЕН совпадать с зашитым в amneziawg-go каталогом UAPI-сокета (/var/run/amneziawg), иначе waitForTunnelName не находит <ifname>.sock → таймаут. Изоляция от upstream сохраняется: у официальной Amnezia wireguard-go = /var/run/wireguard

namespace {
Logger logger("WireguardUtilsMacos");
Logger logwireguard("WireguardGo");
};  // namespace

WireguardUtilsMacos::WireguardUtilsMacos(QObject* parent)
    : WireguardUtils(parent), m_tunnel(this) {
  MZ_COUNT_CTOR(WireguardUtilsMacos);
  logger.debug() << "WireguardUtilsMacos created.";

  connect(&m_tunnel, SIGNAL(readyReadStandardOutput()), this,
          SLOT(tunnelStdoutReady()));
  connect(&m_tunnel, SIGNAL(errorOccurred(QProcess::ProcessError)), this,
          SLOT(tunnelErrorOccurred(QProcess::ProcessError)));
}

WireguardUtilsMacos::~WireguardUtilsMacos() {
  MZ_COUNT_DTOR(WireguardUtilsMacos);
  logger.debug() << "WireguardUtilsMacos destroyed.";
}

void WireguardUtilsMacos::tunnelStdoutReady() {
  for (;;) {
    QByteArray line = m_tunnel.readLine();
    if (line.length() <= 0) {
      break;
    }
    logwireguard.debug() << QString::fromUtf8(line);
  }
}

void WireguardUtilsMacos::tunnelErrorOccurred(QProcess::ProcessError error) {
  logger.warning() << "Tunnel process encountered an error:" << error;
  emit backendFailure();
}

bool WireguardUtilsMacos::addInterface(const InterfaceConfig& config) {
  Q_UNUSED(config);
  if (m_tunnel.state() != QProcess::NotRunning) {
    logger.warning() << "Unable to start: tunnel process already running";
    return false;
  }

  // AVPN: «один VPN». До подъёма нашего туннеля гасим любой чужой VPN, держащий
  // дефолт-маршрут (Amnezia, Outline и любой full-tunnel) — иначе на macOS два
  // демон-VPN могут сосуществовать и драться за маршрут.
  displaceConflictingVpns(m_ifname);

  QDir wgRuntimeDir(WG_RUNTIME_DIR);
  if (!wgRuntimeDir.exists()) {
    wgRuntimeDir.mkpath(".");
  }

  QProcessEnvironment pe = QProcessEnvironment::systemEnvironment();
  QString wgNameFile = wgRuntimeDir.filePath(QString(WG_INTERFACE) + ".name");
  pe.insert("WG_TUN_NAME_FILE", wgNameFile);
#ifdef MZ_DEBUG
  pe.insert("LOG_LEVEL", "debug");
#endif
  m_tunnel.setProcessEnvironment(pe);

  // AVPN: вывод amneziawg-go идёт в stdout/stderr демона (→ StandardErrorPath лог).
  // Без этого pipe QProcess не вычитывается и может заполниться/подвесить процесс,
  // а ошибки wg-go были не видны. ForwardedChannels устраняет и deadlock, и слепоту.
  m_tunnel.setProcessChannelMode(QProcess::ForwardedChannels);

  QDir appPath(QCoreApplication::applicationDirPath());
  QStringList wgArgs = {"-f", "utun"};
  m_tunnel.start(appPath.filePath("amneziawg-go"), wgArgs);
  if (!m_tunnel.waitForStarted(WG_TUN_PROC_TIMEOUT)) {
    logger.error() << "Unable to start tunnel process due to timeout";
    m_tunnel.kill();
    return false;
  }

  m_ifname = waitForTunnelName(wgNameFile);
  if (m_ifname.isNull()) {
    logger.error() << "Unable to read tunnel interface name";
    m_tunnel.kill();
    return false;
  }
  logger.debug() << "Created wireguard interface" << m_ifname;

  // Start the routing table monitor.
  m_rtmonitor = new MacosRouteMonitor(m_ifname, this);

  // Send a UAPI command to configure the interface
  QString message("set=1\n");
  QByteArray privateKey = QByteArray::fromBase64(config.m_privateKey.toUtf8());
  QTextStream out(&message);
  out << "private_key=" << QString(privateKey.toHex()) << "\n";
  out << "replace_peers=true\n";

  if (!config.m_junkPacketCount.isEmpty()) {
    out << "jc=" << config.m_junkPacketCount << "\n";
  }
  if (!config.m_junkPacketMinSize.isEmpty()) {
    out << "jmin=" << config.m_junkPacketMinSize << "\n";
  }
  if (!config.m_junkPacketMaxSize.isEmpty()) {
    out << "jmax=" << config.m_junkPacketMaxSize << "\n";
  }
  if (!config.m_initPacketJunkSize.isEmpty()) {
    out << "s1=" << config.m_initPacketJunkSize << "\n";
  }
  if (!config.m_responsePacketJunkSize.isEmpty()) {
    out << "s2=" << config.m_responsePacketJunkSize << "\n";
  }
  if (!config.m_cookieReplyPacketJunkSize.isEmpty()) {
    out << "s3=" << config.m_cookieReplyPacketJunkSize << "\n";
  }
  if (!config.m_transportPacketJunkSize.isEmpty()) {
    out << "s4=" << config.m_transportPacketJunkSize << "\n";
  }
  if (!config.m_initPacketMagicHeader.isEmpty()) {
    out << "h1=" << config.m_initPacketMagicHeader << "\n";
  }
  if (!config.m_responsePacketMagicHeader.isEmpty()) {
    out << "h2=" << config.m_responsePacketMagicHeader << "\n";
  }
  if (!config.m_underloadPacketMagicHeader.isEmpty()) {
    out << "h3=" << config.m_underloadPacketMagicHeader << "\n";
  }
  if (!config.m_transportPacketMagicHeader.isEmpty()) {
    out << "h4=" << config.m_transportPacketMagicHeader << "\n";
  }

  for (const QString& key : config.m_specialJunk.keys()) {
      out << key.toLower() << "=" << config.m_specialJunk.value(key) << "\n";
  }

  if (!config.m_headerProtectionKey.isEmpty()) {
    QByteArray headerProtectionKey =
        QByteArray::fromBase64(config.m_headerProtectionKey.toUtf8());
    out << "header_protection_key=" << QString(headerProtectionKey.toHex()) << "\n";
  }
  if (!config.m_contentPaddingAddition.isEmpty()) {
    out << "content_padding_addition=" << config.m_contentPaddingAddition << "\n";
  }
  if (!config.m_rekeyAfterTime.isEmpty()) {
    out << "rekey_after_time=" << config.m_rekeyAfterTime << "\n";
  }
  if (!config.m_rekeyTimeout.isEmpty()) {
    out << "rekey_timeout=" << config.m_rekeyTimeout << "\n";
  }
  if (!config.m_rejectAfterTime.isEmpty()) {
    out << "reject_after_time=" << config.m_rejectAfterTime << "\n";
  }
  if (!config.m_keepaliveTimeout.isEmpty()) {
    out << "keepalive_timeout=" << config.m_keepaliveTimeout << "\n";
  }
  if (!config.m_maxHandshakeAttempts.isEmpty()) {
    out << "max_handshake_attempts=" << config.m_maxHandshakeAttempts << "\n";
  }
  if (!config.m_randomTrailers.isEmpty()) {
    QString normalized;
    if (!InterfaceConfig::awgBoolToUapi(config.m_randomTrailers, normalized)) {
      logger.error() << "Invalid RandomTrailers value"; // AVPN: fail closed before UAPI.
      deleteInterface();
      return false;
    }
    out << "random_trailers=" << normalized << "\n";
  }
  if (!config.m_disableCookies.isEmpty()) {
    QString normalized;
    if (!InterfaceConfig::awgBoolToUapi(config.m_disableCookies, normalized)) {
      logger.error() << "Invalid DisableCookies value"; // AVPN
      deleteInterface();
      return false;
    }
    out << "disable_cookies=" << normalized << "\n";
  }

  int err = uapiErrno(uapiCommand(message));
  // AVPN: positive capability check.  A successful set/handshake alone does
  // not prove an old binary applied the AWG 3.1 wire-format fields.
  if (err == 0 && (!config.m_randomTrailers.isEmpty() ||
                   !config.m_disableCookies.isEmpty())) {
    const QString runtime = uapiCommand(QStringLiteral("get=1"));
    auto hasUapiValue = [&runtime](const QString& key,
                                   const QString& expected) {
      return runtime.split(QLatin1Char('\n')).contains(key + QLatin1Char('=') + expected);
    };
    QString randomTrailers;
    QString disableCookies;
    const bool randomOk = config.m_randomTrailers.isEmpty() ||
        (InterfaceConfig::awgBoolToUapi(config.m_randomTrailers, randomTrailers) &&
         hasUapiValue(QStringLiteral("random_trailers"), randomTrailers));
    const bool cookiesOk = config.m_disableCookies.isEmpty() ||
        (InterfaceConfig::awgBoolToUapi(config.m_disableCookies, disableCookies) &&
         hasUapiValue(QStringLiteral("disable_cookies"), disableCookies));
    if (!randomOk || !cookiesOk) {
      logger.error() << "AWG 3.1 UAPI capability mismatch; stopping interface";
      err = EPROTONOSUPPORT;
      deleteInterface();
    } else {
      logger.debug() << "AWG 3.1 UAPI capability verified";
    }
  }
  if (err != 0) {
    logger.error() << "Interface configuration failed:" << strerror(err);
  } else {
    if (config.m_killSwitchEnabled) {
      FirewallParams params { };
      params.dnsServers.append(config.m_primaryDnsServer);
      if (!config.m_secondaryDnsServer.isEmpty()) {
          params.dnsServers.append(config.m_secondaryDnsServer);
      }

      if (config.m_allowedIPAddressRanges.contains(IPAddress("0.0.0.0/0"))) {
          params.blockAll = true;
          if (config.m_excludedAddresses.size()) {
              params.allowNets = true;
              foreach (auto net, config.m_excludedAddresses) {
                  params.allowAddrs.append(net.toUtf8());
              }
          }
      } else {
          params.blockNets = true;
          foreach (auto net, config.m_allowedIPAddressRanges) {
              params.blockAddrs.append(net.toString());
          }
      }
      if (!applyFirewallRules(params)) {
        logger.error() << "PF policy transaction failed; keeping quarantine";
        err = EIO;
        deleteInterface();
      }
    }
  }
  return (err == 0);
}

bool WireguardUtilsMacos::deleteInterface() {
  if (m_rtmonitor) {
    delete m_rtmonitor;
    m_rtmonitor = nullptr;
  }

  bool stopped = m_tunnel.state() == QProcess::NotRunning;
  if (!stopped) {
    // Attempt to terminate gracefully, then prove exact child death before PF
    // release. A timeout retains the emergency quarantine.
    m_tunnel.terminate();
    stopped = m_tunnel.waitForFinished(WG_TUN_PROC_TIMEOUT);
    if (!stopped) {
      m_tunnel.kill();
      stopped = m_tunnel.waitForFinished(WG_TUN_PROC_TIMEOUT);
    }
  }
  if (!stopped || m_tunnel.state() != QProcess::NotRunning) {
    KillSwitch::instance()->disableAllTraffic();
    return false;
  }

  // Garbage collect.
  QDir wgRuntimeDir(WG_RUNTIME_DIR);
  QFile::remove(wgRuntimeDir.filePath(QString(WG_INTERFACE) + ".name"));

  // double-check + ensure our firewall is installed and enabled
  return KillSwitch::instance()->disableKillSwitch();
}

// dummy implementations for now
bool WireguardUtilsMacos::updatePeer(const InterfaceConfig& config) {
  QByteArray publicKey =
      QByteArray::fromBase64(qPrintable(config.m_serverPublicKey));

  QByteArray pskKey = QByteArray::fromBase64(qPrintable(config.m_serverPskKey));

  logger.debug() << "Configuring peer" << config.m_serverPublicKey
                 << "via" << config.m_serverIpv4AddrIn;

  // Update/create the peer config
  QString message;
  QTextStream out(&message);
  out << "set=1\n";
  out << "public_key=" << QString(publicKey.toHex()) << "\n";
  if (!config.m_serverPskKey.isNull()) {
    out << "preshared_key=" << QString(pskKey.toHex()) << "\n";
  }
  if (!config.m_serverIpv4AddrIn.isNull()) {
    out << "endpoint=" << config.m_serverIpv4AddrIn << ":";
  } else if (!config.m_serverIpv6AddrIn.isNull()) {
    out << "endpoint=[" << config.m_serverIpv6AddrIn << "]:";
  } else {
    logger.warning() << "Failed to create peer with no endpoints";
    return false;
  }
  out << config.m_serverPort << "\n";

  out << "replace_allowed_ips=true\n";
  if (!config.m_persistentKeepalive.isEmpty()) {
    out << "persistent_keepalive_interval=" << config.m_persistentKeepalive << "\n";
  }
  for (const IPAddress& ip : config.m_allowedIPAddressRanges) {
    out << "allowed_ip=" << ip.toString() << "\n";
  }

  // Exclude the server address, except for multihop exit servers.
  if ((config.m_hopType != InterfaceConfig::MultiHopExit) &&
      (m_rtmonitor != nullptr)) {
    m_rtmonitor->addExclusionRoute(IPAddress(config.m_serverIpv4AddrIn));
    m_rtmonitor->addExclusionRoute(IPAddress(config.m_serverIpv6AddrIn));
  }

  int err = uapiErrno(uapiCommand(message));
  if (err != 0) {
    logger.error() << "Peer configuration failed:" << strerror(err);
  }
  return (err == 0);
}

bool WireguardUtilsMacos::deletePeer(const InterfaceConfig& config) {
  QByteArray publicKey =
      QByteArray::fromBase64(qPrintable(config.m_serverPublicKey));

  // Clear exclustion routes for this peer.
  if ((config.m_hopType != InterfaceConfig::MultiHopExit) &&
      (m_rtmonitor != nullptr)) {
    m_rtmonitor->deleteExclusionRoute(IPAddress(config.m_serverIpv4AddrIn));
    m_rtmonitor->deleteExclusionRoute(IPAddress(config.m_serverIpv6AddrIn));
  }

  QString message;
  QTextStream out(&message);
  out << "set=1\n";
  out << "public_key=" << QString(publicKey.toHex()) << "\n";
  out << "remove=true\n";

  int err = uapiErrno(uapiCommand(message));
  if (err != 0) {
    logger.error() << "Peer deletion failed:" << strerror(err);
  }
  return (err == 0);
}

// AVPN (BUG-4 auto-heal): пересоздать UDP-сокет живого awg-go с новым эфемерным локальным
// портом. UAPI-строка listen_port=0 → device.BindUpdate(): сокет закрывается и открывается
// заново, следующий handshake уходит с нового порта = новый 5-tuple flow (лечит сессионный
// блок ТСПУ; эквивалент режима полёта). Пиры/ключи/маршруты не трогаются.
bool WireguardUtilsMacos::rebindEndpointSocket() {
  if (m_tunnel.state() != QProcess::Running) {
    logger.warning() << "rebind: tunnel process is not running";
    return false;
  }
  QString message;
  QTextStream out(&message);
  out << "set=1\n";
  out << "listen_port=0\n";
  int err = uapiErrno(uapiCommand(message));
  if (err != 0) {
    logger.error() << "rebind: listen_port rebind failed:" << strerror(err);
  } else {
    logger.debug() << "rebind: socket rebound to a new ephemeral port";
  }
  return (err == 0);
}

QList<WireguardUtils::PeerStatus> WireguardUtilsMacos::getPeerStatus() {
  QString reply = uapiCommand("get=1");
  PeerStatus status;
  QList<PeerStatus> peerList;
  for (const QString& line : reply.split('\n')) {
    int eq = line.indexOf('=');
    if (eq <= 0) {
      continue;
    }
    QString name = line.left(eq);
    QString value = line.mid(eq + 1);

    if (name == "public_key") {
      if (!status.m_pubkey.isEmpty()) {
        peerList.append(status);
      }
      QByteArray pubkey = QByteArray::fromHex(value.toUtf8());
      status = PeerStatus(pubkey.toBase64());
    }

    if (name == "tx_bytes") {
      status.m_txBytes = value.toDouble();
    }
    if (name == "rx_bytes") {
      status.m_rxBytes = value.toDouble();
    }
    if (name == "last_handshake_time_sec") {
      status.m_handshake += value.toLongLong() * 1000;
    }
    if (name == "last_handshake_time_nsec") {
      status.m_handshake += value.toLongLong() / 1000000;
    }
  }
  if (!status.m_pubkey.isEmpty()) {
    peerList.append(status);
  }

  return peerList;
}

bool WireguardUtilsMacos::updateRoutePrefix(const IPAddress& prefix) {
  if (!m_rtmonitor) {
    return false;
  }
  if (prefix.prefixLength() > 0) {
    return m_rtmonitor->insertRoute(prefix);
  }

  // Ensure that we do not replace the default route.
  if (prefix.type() == QAbstractSocket::IPv4Protocol) {
    return m_rtmonitor->insertRoute(IPAddress("0.0.0.0/1")) &&
           m_rtmonitor->insertRoute(IPAddress("128.0.0.0/1"));
  }
  if (prefix.type() == QAbstractSocket::IPv6Protocol) {
    return m_rtmonitor->insertRoute(IPAddress("::/1")) &&
           m_rtmonitor->insertRoute(IPAddress("8000::/1"));
  }

  return false;
}

bool WireguardUtilsMacos::deleteRoutePrefix(const IPAddress& prefix) {
  if (!m_rtmonitor) {
    return false;
  }

  if (prefix.prefixLength() > 0) {
    return m_rtmonitor->deleteRoute(prefix);
  }
  // Ensure that we do not replace the default route.
  if (prefix.type() == QAbstractSocket::IPv4Protocol) {
    return m_rtmonitor->deleteRoute(IPAddress("0.0.0.0/1")) &&
           m_rtmonitor->deleteRoute(IPAddress("128.0.0.0/1"));
  } else if (prefix.type() == QAbstractSocket::IPv6Protocol) {
    return m_rtmonitor->deleteRoute(IPAddress("::/1")) &&
           m_rtmonitor->deleteRoute(IPAddress("8000::/1"));
  } else {
    return false;
  }
}

bool WireguardUtilsMacos::addExclusionRoute(const IPAddress& prefix) {
  if (!m_rtmonitor) {
    return false;
  }
  return m_rtmonitor->addExclusionRoute(prefix);
}

bool WireguardUtilsMacos::deleteExclusionRoute(const IPAddress& prefix) {
  if (!m_rtmonitor) {
    return false;
  }
  return m_rtmonitor->deleteExclusionRoute(prefix);
}

bool WireguardUtilsMacos::excludeLocalNetworks(const QList<IPAddress>& routes) {
  if (!m_rtmonitor) {
    return false;
  }

  // Explicitly discard LAN traffic that makes its way into the tunnel. This
  // doesn't really exclude the LAN traffic, we just don't take any action to
  // overrule the routes of other interfaces.
  bool result = true;
  for (const auto& prefix : routes) {
    logger.error() << "Attempting to exclude:" << prefix.toString();
    if (!m_rtmonitor->insertRoute(prefix, RTF_IFSCOPE | RTF_REJECT)) {
      result = false;
    }
  }

  // TODO: A kill switch would be nice though :)
  return result;
}

QString WireguardUtilsMacos::uapiCommand(const QString& command) {
  QLocalSocket socket;
  QTimer uapiTimeout;
  QDir wgRuntimeDir(WG_RUNTIME_DIR);
  QString wgSocketFile = wgRuntimeDir.filePath(m_ifname + ".sock");

  uapiTimeout.setSingleShot(true);
  uapiTimeout.start(WG_TUN_PROC_TIMEOUT);

  socket.connectToServer(wgSocketFile, QIODevice::ReadWrite);
  if (!socket.waitForConnected(WG_TUN_PROC_TIMEOUT)) {
    logger.error() << "QLocalSocket::waitForConnected() failed:"
                   << socket.errorString();
    return QString();
  }

  // Send the message to the UAPI socket.
  QByteArray message = command.toLocal8Bit();
  while (!message.endsWith("\n\n")) {
    message.append('\n');
  }
  socket.write(message);

  QByteArray reply;
  while (!reply.contains("\n\n")) {
    if (!uapiTimeout.isActive()) {
      logger.error() << "UAPI command timed out";
      return QString();
    }
    QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
    reply.append(socket.readAll());
  }

  return QString::fromUtf8(reply).trimmed();
}

// static
int WireguardUtilsMacos::uapiErrno(const QString& reply) {
  for (const QString& line : reply.split("\n")) {
    int eq = line.indexOf('=');
    if (eq <= 0) {
      continue;
    }
    if (line.left(eq) == "errno") {
      return line.mid(eq + 1).toInt();
    }
  }
  return EINVAL;
}

QString WireguardUtilsMacos::waitForTunnelName(const QString& filename) {
  QTimer timeout;
  timeout.setSingleShot(true);
  timeout.start(WG_TUN_PROC_TIMEOUT);

  QFile file(filename);
  while ((m_tunnel.state() == QProcess::Running) && timeout.isActive()) {
    QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
      continue;
    }
    QString ifname = QString::fromLocal8Bit(file.readLine()).trimmed();
    file.close();

    // Test-connect to the UAPI socket.
    QLocalSocket sock;
    QDir wgRuntimeDir(WG_RUNTIME_DIR);
    QString sockName = wgRuntimeDir.filePath(ifname + ".sock");
    sock.connectToServer(sockName, QIODevice::ReadWrite);
    if (sock.waitForConnected(100)) {
      return ifname;
    }
  }

  return QString();
}

// AVPN: гарантия «на macOS активен один VPN». Перед подъёмом нашего туннеля находим
// чужие utun-интерфейсы, которые держат дефолт-маршрут (0/1, 128.0/1, default или их
// IPv6-аналоги) — это конкурирующие full-tunnel VPN (Amnezia/Outline/любой). Системные
// utun (AirDrop/Handoff/Continuity) дефолт-маршрут НЕ держат, поэтому не затрагиваются.
// Гасим их интерфейс (ifconfig down) + сносим их дефолт-маршруты: чужой туннель теряет
// трафик, его собственный сетевой монитор это видит и отключается. Свой интерфейс
// (selfIfname) и физические (en*) не трогаем.
void WireguardUtilsMacos::displaceConflictingVpns(const QString& selfIfname) {
  // ТОЛЬКО IPv4-дефолт: full-tunnel VPN держит 0/1 / 128.0/1 / default через utun.
  // Системные utun (Continuity/AirDrop/iCloud Relay) держат лишь IPv6-половинки (::/1) —
  // их НЕ трогаем, иначе ломается системная сеть. Поэтому inet6 исключён намеренно.
  const QString script = QStringLiteral(
      "netstat -rnf inet 2>/dev/null | "
      "awk '($1==\"default\"||$1==\"0/1\"||$1==\"128.0/1\") "
      "&& $NF ~ /^utun[0-9]+$/ {print $NF}' | sort -u");

  QProcess finder;
  finder.start(QStringLiteral("/bin/sh"), QStringList{QStringLiteral("-c"), script});
  if (!finder.waitForFinished(3000)) {
    finder.kill();
    return;
  }
  const QStringList ifaces =
      QString::fromUtf8(finder.readAllStandardOutput()).split('\n', Qt::SkipEmptyParts);

  for (QString ifn : ifaces) {
    ifn = ifn.trimmed();
    if (ifn.isEmpty() || !ifn.startsWith(QStringLiteral("utun"))) continue;
    if (!selfIfname.isEmpty() && ifn == selfIfname) continue;  // не трогаем свой

    logger.warning() << "Displacing conflicting VPN on interface" << ifn;
    // Снести дефолт-маршруты, идущие через чужой интерфейс.
    for (const QString& r : {QStringLiteral("default"), QStringLiteral("0.0.0.0/1"),
                             QStringLiteral("128.0.0.0/1")}) {
      QProcess del;
      del.start(QStringLiteral("/sbin/route"),
                QStringList{QStringLiteral("-q"), QStringLiteral("-n"),
                            QStringLiteral("delete"), QStringLiteral("-ifscope"), ifn, r});
      del.waitForFinished(2000);
    }
    // Погасить чужой интерфейс — туннель остаётся без устройства, чужой VPN отключается.
    QProcess down;
    down.start(QStringLiteral("/sbin/ifconfig"), QStringList{ifn, QStringLiteral("down")});
    down.waitForFinished(2000);
  }
}

bool WireguardUtilsMacos::applyFirewallRules(FirewallParams& params)
{
  // double-check + ensure our firewall is installed and enabled. This is necessary as
  // other software may disable pfctl before re-enabling with their own rules (e.g other VPNs)
  if (!MacOSFirewall::isInstalled()) MacOSFirewall::install();

  bool ok = MacOSFirewall::setAnchorEnabled(
      QStringLiteral("999.quarantine"), true);
  ok = MacOSFirewall::ensureRootAnchorPriority() && ok;
  ok = MacOSFirewall::flushAllStates() && ok;
  ok = MacOSFirewall::isInstalled() && ok;
  ok = MacOSFirewall::isQuarantineEnabled() && ok;
  if (!ok) return false;

  ok = MacOSFirewall::setAnchorEnabled(
      QStringLiteral("000.allowLoopback"), true) && ok;
  ok = MacOSFirewall::setAnchorEnabled(
      QStringLiteral("100.blockAll"), params.blockAll) && ok;
  ok = MacOSFirewall::setAnchorEnabled(
      QStringLiteral("110.allowNets"), params.allowNets) && ok;
  ok = MacOSFirewall::setAnchorTable(
      QStringLiteral("110.allowNets"), params.allowNets,
      QStringLiteral("allownets"), params.allowAddrs) && ok;

  ok = MacOSFirewall::setAnchorEnabled(
      QStringLiteral("120.blockNets"), params.blockNets) && ok;
  ok = MacOSFirewall::setAnchorTable(
      QStringLiteral("120.blockNets"), params.blockNets,
      QStringLiteral("blocknets"), params.blockAddrs) && ok;

  ok = MacOSFirewall::setAnchorEnabled(
      QStringLiteral("200.allowVPN"), true) && ok;
  ok = MacOSFirewall::setAnchorEnabled(
      QStringLiteral("250.blockIPv6"), true) && ok;
  ok = MacOSFirewall::setAnchorEnabled(
      QStringLiteral("290.allowDHCP"), true) && ok;
  ok = MacOSFirewall::setAnchorEnabled(
      QStringLiteral("300.allowLAN"), true) && ok;
  ok = MacOSFirewall::setAnchorEnabled(
      QStringLiteral("310.blockDNS"), true) && ok;
  ok = MacOSFirewall::setAnchorTable(
      QStringLiteral("310.blockDNS"), true,
      QStringLiteral("dnsaddr"), params.dnsServers) && ok;
  if (!ok) return false;
  return MacOSFirewall::setAnchorEnabled(
      QStringLiteral("999.quarantine"), false)
      && !MacOSFirewall::isAnchorEnabled(QStringLiteral("999.quarantine"));
}
