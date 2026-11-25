#include "killswitch.h"


#include <QApplication>
#include <QDateTime>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QTimer>
#include <QRegularExpression>
#include <algorithm>

#include "../client/core/utils/protocolEnum.h"
#include "../client/core/protocols/protocolUtils.h"
#include "../client/core/utils/constants/configKeys.h"
#include "../client/core/utils/constants/protocolConstants.h"
#include "qjsonarray.h"
#include "version.h"

static bool isValidIpOrCidr(const QString &value) {
    static const QRegularExpression re(
        QStringLiteral(R"(^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$)"));
    if (!re.match(value).hasMatch()) return false;
    const QStringList ipParts = value.split(QLatin1Char('/'))[0].split(QLatin1Char('.'));
    for (const QString &part : ipParts) {
        bool ok;
        int octet = part.toInt(&ok);
        if (!ok || octet < 0 || octet > 255) return false;
    }
    if (value.contains(QLatin1Char('/'))) {
        bool ok;
        int prefix = value.split(QLatin1Char('/'))[1].toInt(&ok);
        if (!ok || prefix < 0 || prefix > 32) return false;
    }
    return true;
}

#ifdef Q_OS_WIN
    #include "../client/platforms/windows/daemon/windowsfirewall.h"
    #include "../client/platforms/windows/daemon/windowsdaemon.h"
#endif

#ifdef Q_OS_LINUX
    #include "../client/platforms/linux/daemon/linuxfirewall.h"
#endif

#ifdef Q_OS_MACOS
    #include "../client/platforms/macos/daemon/macosfirewall.h"
#endif

KillSwitch* s_instance = nullptr;

// AVPN (round mac-D3/D4): the lease's clocks. The running lease is measured on the monotonic clock - a wall clock that
// steps back (no app renewing) must not keep a block beyond its ttl, one that steps forward must not end a lease the app
// renews (review of 99635acf2, finding 1). The wall clock only carries the deadline across a service restart.
static qint64 systemWallMs() { return QDateTime::currentMSecsSinceEpoch(); }
static qint64 systemMonoMs()
{
    static QElapsedTimer t = []() { QElapsedTimer e; e.start(); return e; }();
    return t.elapsed() + 1; // never 0: 0 means "no lease"
}
static qint64 (*s_wallMs)() = &systemWallMs;
static qint64 (*s_monoMs)() = &systemMonoMs;
void KillSwitch::setClocksForTest(qint64 (*wallMs)(), qint64 (*monoMs)())
{
    s_wallMs = wallMs ? wallMs : &systemWallMs;
    s_monoMs = monoMs ? monoMs : &systemMonoMs;
}
static const QString kHoldUntilKey = QStringLiteral("Conf/killSwitchHoldUntilMs");
static const QString kHoldAddrsKey = QStringLiteral("Conf/killSwitchHoldAddrs");

KillSwitch* KillSwitch::instance()
{
    if (s_instance == nullptr) {
        s_instance = new KillSwitch(qApp);
    }
    return s_instance;
}

bool KillSwitch::init()
{
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
    m_appSettigns = QSharedPointer<SecureQSettings>(new SecureQSettings(ORGANIZATION_NAME, APPLICATION_NAME, nullptr));
#endif

    if (isStrictKillSwitchEnabled()) {
        return disableAllTraffic();
    }

#ifdef Q_OS_MACOS
    // AVPN (round mac-D3): a service that starts inside the app's lease on the intent (the previous process died with
    // the VPN wanted on - mid-switch or mid-session) keeps the block that process left until the app's next session
    // opens or the lease ends; the dead session's passes go, the API edges stay. Never beyond kHoldMaxMs.
    {
        // The one place the wall clock is judged: the deadline a previous process persisted, at most kHoldMaxMs away.
        const qint64 until = m_appSettigns->value(kHoldUntilKey, 0).toLongLong();
        const qint64 now = s_wallMs();
        if (until > now && until - now <= kHoldMaxMs && MacOSFirewall::isInstalled()) {
            m_holdUntilWallMs = until;
            m_holdDeadlineMs = s_monoMs() + (until - now);
            m_holdAddrs = m_appSettigns->value(kHoldAddrsKey).toStringList();
            m_sessionAllowAddrs.clear();
            keepBlockForNextSession();
            armHoldTimer();
            qInfo().noquote() << "[killswitch] kill switch hold: the service starts inside the intent - the block stays for"
                              << (until - now) << "ms or until the next session";
            return true;
        }
        m_appSettigns->remove(kHoldUntilKey);
        m_appSettigns->remove(kHoldAddrsKey);
    }
#endif

    // AVPN: self-heal на старте демона. Если прошлый инстанс упал с загруженным
    // firewall-анкором ("tribe") / висящим pf.token — здесь он снимается (на macOS
    // disableKillSwitch() → MacOSFirewall::uninstall(): флаш анкора + снос токена +
    // восстановление /etc/pf.conf). Гарантия: сеть не может остаться запертой после
    // краша демона. killswitch по умолчанию OFF, так что обычный путь — именно сюда.
    return disableKillSwitch();
}

bool KillSwitch::refresh(bool enabled)
{
#ifdef Q_OS_WIN
    QSettings RegHLM("HKEY_LOCAL_MACHINE\\Software\\" + QString(ORGANIZATION_NAME)
                             + "\\" + QString(APPLICATION_NAME), QSettings::NativeFormat);
    RegHLM.setValue("strictKillSwitchEnabled", enabled);
#endif

#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
    m_appSettigns->setValue("Conf/strictKillSwitchEnabled", enabled);
#endif

#ifdef Q_OS_MACOS
    // AVPN (round mac-D3): the client sends refresh(false) for the kill switch turned off too - nothing is held then.
    if (!enabled && m_holdDeadlineMs > 0) {
        m_holdDeadlineMs = 0;
        m_holdUntilWallMs = 0;
        m_holdAddrs.clear();
        persistHold();
    }
#endif
    if (isStrictKillSwitchEnabled()) {
        return disableAllTraffic();
    }  else {
        return disableKillSwitch();
    }

}

bool KillSwitch::isStrictKillSwitchEnabled()
{
#ifdef Q_OS_WIN
    QSettings RegHLM("HKEY_LOCAL_MACHINE\\Software\\" + QString(ORGANIZATION_NAME)
                             + "\\" + QString(APPLICATION_NAME), QSettings::NativeFormat);
    return RegHLM.value("strictKillSwitchEnabled", false).toBool();
#endif
    return m_appSettigns->value("Conf/strictKillSwitchEnabled", false).toBool();
}

bool KillSwitch::disableKillSwitch() {
#ifdef Q_OS_LINUX
    if (isStrictKillSwitchEnabled()) {
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("000.allowLoopback"), true);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("100.blockAll"), true);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv4, QStringLiteral("110.allowNets"), false);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv4, QStringLiteral("120.blockNets"), false);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("130.allowMarkedXray"), false);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv4, QStringLiteral("200.allowVPN"), false);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv6, QStringLiteral("250.blockIPv6"), true);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("290.allowDHCP"), false);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("300.allowLAN"), false);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv4, QStringLiteral("310.blockDNS"), false);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv4, QStringLiteral("320.allowDNS"), false);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("400.allowPIA"), false);
    } else {
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("000.allowLoopback"), true);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("100.blockAll"), false);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv4, QStringLiteral("110.allowNets"), false);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv4, QStringLiteral("120.blockNets"), false);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("130.allowMarkedXray"), false);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv4, QStringLiteral("200.allowVPN"), false);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv6, QStringLiteral("250.blockIPv6"), false);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("290.allowDHCP"), true);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("300.allowLAN"), true);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv4, QStringLiteral("310.blockDNS"), false);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv4, QStringLiteral("320.allowDNS"), true);
        LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("400.allowPIA"), false);
        LinuxFirewall::uninstall();
    }
#endif

#ifdef Q_OS_MACOS
    // AVPN (pf state ownership, macospfanchors.h): a stop ends the kill-switch session and leaves no session
    // pf state. Strict: the block stays and every anchor of the session is flushed; otherwise every tribe/*
    // anchor is flushed. The session's tun goes with it (killswitch.h).
    // Round mac-D3: under the app's lease on the intent (setHold) a stop ends the session, not the block - the next
    // session replaces the session anchors under it; the lease's release or end lifts it.
    const bool hadBlock = m_sessionOpen || m_blockHeld;
    m_sessionOpen = false;
    m_createdTun.clear();
    if (hadBlock && holdActive() && !isStrictKillSwitchEnabled()) {
        keepBlockForNextSession();
        m_allowedRanges.clear();
        return true;
    }
    m_blockHeld = false;
    if (isStrictKillSwitchEnabled()) {
        MacOSFirewall::applyStrictBlock();
    } else {
        MacOSFirewall::uninstall();
    }
#endif

#ifdef Q_OS_WIN
    if (isStrictKillSwitchEnabled()) {
        return disableAllTraffic();
    }
    return WindowsFirewall::create(this)->allowAllTraffic();
#endif

    m_allowedRanges.clear();
    return true;
}

bool KillSwitch::disableAllTraffic() {
#ifdef Q_OS_WIN
    WindowsFirewall::create(this)->enableInterface(-1);
#endif
#ifdef Q_OS_LINUX
    if (!LinuxFirewall::isInstalled()) {
        LinuxFirewall::install();
    }
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("100.blockAll"), true);
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("130.allowMarkedXray"), false);
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("000.allowLoopback"), true);
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv6, QStringLiteral("250.blockIPv6"), true);
#endif
#ifdef Q_OS_MACOS
    // AVPN (pf state ownership): callers - KillSwitch::init (the service start with strict on: never a
    // session), refresh(true) (strict turned on), the IPC slot. A tunnel session up: its own anchors stay and
    // the block is added; it outlives the session (its stop applies the strict block). No session: the block
    // alone, which also flushes what a previous session or service process left.
    if (m_sessionOpen)
        MacOSFirewall::addBlockToSession();
    else
        MacOSFirewall::applyStrictBlock();
#endif
    m_allowedRanges.clear();
    return true;
}

bool KillSwitch::resetAllowedRange(const QStringList &ranges) {

    if (!std::all_of(ranges.cbegin(), ranges.cend(), isValidIpOrCidr)) {
        qCritical() << "IPC: invalid IP/CIDR in ranges, rejecting resetAllowedRange";
        return false;
    }
    m_allowedRanges = ranges;

#ifdef Q_OS_LINUX
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv4, QStringLiteral("110.allowNets"), true);
    LinuxFirewall::updateAllowNets(m_allowedRanges);
#endif

#ifdef Q_OS_MACOS
    MacOSFirewall::setAnchorEnabled(QStringLiteral("110.allowNets"), true);
    MacOSFirewall::setAnchorTable(QStringLiteral("110.allowNets"), true, QStringLiteral("allownets"), m_allowedRanges);
#endif

#ifdef Q_OS_WIN
    if (isStrictKillSwitchEnabled()) {
        WindowsFirewall::create(this)->enableInterface(-1);
    }
    WindowsFirewall::create(this)->allowTrafficRange(m_allowedRanges);
#endif

    return true;
}

bool KillSwitch::addAllowedRange(const QStringList &ranges) {
    if (!std::all_of(ranges.cbegin(), ranges.cend(), isValidIpOrCidr)) {
        qCritical() << "IPC: invalid IP/CIDR in ranges, rejecting addAllowedRange";
        return false;
    }
    for (const QString &range : ranges) {
        if (!range.isEmpty() && !m_allowedRanges.contains(range)) {
            m_allowedRanges.append(range);
        }
    }

    return resetAllowedRange(m_allowedRanges);
}

bool KillSwitch::enablePeerTraffic(const QJsonObject &configStr) {
#ifdef Q_OS_WIN
    InterfaceConfig config;

    config.m_primaryDnsServer = configStr.value(amnezia::configKey::dns1).toString();

    // We don't use secondary DNS if primary DNS is AmneziaDNS
    if (!config.m_primaryDnsServer.contains(amnezia::protocols::dns::amneziaDnsIp)) {
        config.m_secondaryDnsServer = configStr.value(amnezia::configKey::dns2).toString();
    }

    config.m_serverPublicKey = "openvpn";
    config.m_serverIpv4Gateway = configStr.value("vpnGateway").toString();
    config.m_serverIpv4AddrIn = configStr.value("vpnServer").toString();
    int vpnAdapterIndex = configStr.value("vpnAdapterIndex").toInt();
    int inetAdapterIndex = configStr.value("inetAdapterIndex").toInt();

    int splitTunnelType = configStr.value("splitTunnelType").toInt();
    QJsonArray splitTunnelSites = configStr.value("splitTunnelSites").toArray();

    // Use APP split tunnel
    if (splitTunnelType == 0 || splitTunnelType == 2) {
        config.m_allowedIPAddressRanges.append(IPAddress(QHostAddress("0.0.0.0"), 0));
        config.m_allowedIPAddressRanges.append(IPAddress(QHostAddress("::"), 0));
    }

    if (splitTunnelType == 1) {
        for (auto v : splitTunnelSites) {
            QString ipRange = v.toString();
            if (ipRange.split('/').size() > 1) {
                config.m_allowedIPAddressRanges.append(
                        IPAddress(QHostAddress(ipRange.split('/')[0]), atoi(ipRange.split('/')[1].toLocal8Bit())));
            } else {
                config.m_allowedIPAddressRanges.append(IPAddress(QHostAddress(ipRange), 32));
            }
        }
    }

    config.m_excludedAddresses.append(configStr.value("vpnServer").toString());
    if (splitTunnelType == 2) {
        for (auto v : splitTunnelSites) {
            QString ipRange = v.toString();
            config.m_excludedAddresses.append(ipRange);
        }
    }

    for (const QJsonValue &i : configStr.value(amnezia::configKey::splitTunnelApps).toArray()) {
        if (!i.isString()) {
            break;
        }
        config.m_vpnDisabledApps.append(i.toString());
    }

    for (auto dns : configStr.value(amnezia::configKey::allowedDnsServers).toArray()) {
        if (!dns.isString()) {
            break;
        }
        config.m_allowedDnsServers.append(dns.toString());
    }

    // killSwitch toggle
    if (QVariant(configStr.value(amnezia::configKey::killSwitchOption).toString()).toBool()) {
        WindowsFirewall::create(this)->enablePeerTraffic(config);
    }

    WindowsDaemon::instance()->prepareActivation(config, inetAdapterIndex);
    WindowsDaemon::instance()->activateSplitTunnel(config, vpnAdapterIndex);
#endif
    return true;
}

bool KillSwitch::enableKillSwitch(const QJsonObject &configStr, int vpnAdapterIndex) {
#ifdef Q_OS_WIN
    if (configStr.value("splitTunnelType").toInt() != 0) {
        WindowsFirewall::create(this)->allowAllTraffic();
    }
    return WindowsFirewall::create(this)->enableInterface(vpnAdapterIndex);
#endif

#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
    int splitTunnelType = configStr.value("splitTunnelType").toInt();
    QJsonArray splitTunnelSites = configStr.value("splitTunnelSites").toArray();
    bool blockAll = 0;
    bool allowNets = 0;
    bool blockNets = 0;
    bool allowMarkedXray = 0;
    QStringList allownets;
    QStringList blocknets;
    QStringList allowedDnsServers;

    const QString dns1 = configStr.value(amnezia::configKey::dns1).toString();
    // We don't use secondary DNS if primary DNS is AmneziaDNS
    const QString dns2 = dns1.contains(amnezia::protocols::dns::amneziaDnsIp)
            ? QString()
            : configStr.value(amnezia::configKey::dns2).toString();

    if ((!dns1.isEmpty() && !isValidIpOrCidr(dns1)) || (!dns2.isEmpty() && !isValidIpOrCidr(dns2))) {
        qCritical() << "IPC: invalid dns1/dns2, rejecting enableKillSwitch";
        return false;
    }

    for (const QJsonValue &dns : configStr.value(amnezia::configKey::allowedDnsServers).toArray()) {
        if (!dns.isString()) break;
        const QString dnsStr = dns.toString();
        if (isValidIpOrCidr(dnsStr))
            allowedDnsServers.append(dnsStr);
        else if (!dnsStr.isEmpty())
            qWarning() << "IPC: rejected invalid allowedDnsServer:" << dnsStr;
    }

    if (splitTunnelType == 0) {
        blockAll = true;
        allowNets = true;
        allowMarkedXray = true;
        allownets.append(configStr.value("vpnServer").toString());
    } else if (splitTunnelType == 1) {
        blockNets = true;
        allowMarkedXray = true;
        for (auto v : splitTunnelSites) {
            blocknets.append(v.toString());
        }
    } else if (splitTunnelType == 2) {
        blockAll = true;
        allowNets = true;
        allownets.append(configStr.value("vpnServer").toString());
        for (auto v : splitTunnelSites) {
            allownets.append(v.toString());
        }
    }

    if (!std::all_of(allownets.cbegin(), allownets.cend(), isValidIpOrCidr) ||
        !std::all_of(blocknets.cbegin(), blocknets.cend(), isValidIpOrCidr)) {
        qCritical() << "IPC: invalid IP/CIDR in allownets/blocknets, rejecting enableKillSwitch";
        return false;
    }
#endif

#ifdef Q_OS_LINUX
    if (!LinuxFirewall::isInstalled()) {
        LinuxFirewall::install();
    }

    // double-check + ensure our firewall is installed and enabled
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("000.allowLoopback"), true);
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("100.blockAll"), blockAll);
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv4, QStringLiteral("110.allowNets"), allowNets);
    LinuxFirewall::updateAllowNets(allownets);
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv4, QStringLiteral("120.blockNets"), blockNets);
    LinuxFirewall::updateBlockNets(blocknets);
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("130.allowMarkedXray"), true);
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv4, QStringLiteral("200.allowVPN"), true);
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv6, QStringLiteral("250.blockIPv6"), true);
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("290.allowDHCP"), true);
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("300.allowLAN"), true);
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv4, QStringLiteral("310.blockDNS"), true);
    QStringList dnsServers;

    if (!dns1.isEmpty())
        dnsServers.append(dns1);
    if (!dns2.isEmpty())
        dnsServers.append(dns2);

    dnsServers.append("127.0.0.1");
    dnsServers.append("127.0.0.53");
    dnsServers.append(allowedDnsServers);

    LinuxFirewall::updateDNSServers(dnsServers);
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::IPv4, QStringLiteral("320.allowDNS"), true);
    LinuxFirewall::setAnchorEnabled(LinuxFirewall::Both, QStringLiteral("400.allowPIA"), true);
#endif

#ifdef Q_OS_MACOS
    QStringList dnsServers;
    if (!dns1.isEmpty())
        dnsServers.append(dns1);
    if (!dns2.isEmpty())
        dnsServers.append(dns2);

    dnsServers.append(allowedDnsServers);

    // AVPN (pf state ownership, macospfanchors.h): every tribe/* anchor of this session is written by one
    // call; 200.allowVPN passes only the tun this session brought up (IpcServer::createTun), never the
    // rule an earlier (AmneziaWG) session left in the kernel. The service's own sockets pass by 400.allowPIA.
    FirewallParams params {};
    params.blockAll = blockAll;
    params.allowNets = allowNets;
    params.allowAddrs = allownets;
    params.blockNets = blockNets;
    params.blockAddrs = blocknets;
    params.dnsServers = dnsServers;
    params.allowPIA = true;
    // The tun brought up for this session (IpcServer::createTun) is taken: it is this session's from here on.
    const QString tunnel = m_createdTun;
    m_createdTun.clear();
    MacOSFirewall::applySessionRules(params, tunnel);
    m_sessionOpen = true;
    m_blockHeld = false; // round mac-D3: a held block is this session's from here on
    m_sessionAllowAddrs = params.allowAddrs;
    // AVPN (diag): what the kill switch lets out - the server and the resolvers of this session.
    qDebug().noquote() << "[killswitch] split" << splitTunnelType << "allownets:" << allownets.join(QStringLiteral(", "))
                       << "| dnsaddr:" << dnsServers.join(QStringLiteral(", "));
#endif
    return true;
}

#ifdef Q_OS_MACOS
// AVPN (pf state ownership): the AmneziaWG kill switch of its own utun opens the session
// (WireguardUtilsMacos::applyFirewallRules); a tun created for another session being built is not this one's.
void KillSwitch::openTunnelSession(const FirewallParams &params, const QString &tunnelIfname)
{
    m_createdTun.clear();
    MacOSFirewall::applySessionRules(params, tunnelIfname);
    m_sessionOpen = true;
    m_blockHeld = false; // round mac-D3: a held block is this session's from here on
    m_sessionAllowAddrs = params.allowAddrs;
}
#endif

bool KillSwitch::setHold(int ttlMs, const QStringList &controlPlaneAddrs)
{
#ifdef Q_OS_MACOS
    QStringList addrs;
    for (const QString &a : controlPlaneAddrs) {
        if (isValidIpOrCidr(a) && !addrs.contains(a))
            addrs << a;
        else if (!a.isEmpty())
            qWarning() << "IPC: rejected an invalid control-plane address of the kill switch hold";
    }
    if (ttlMs > 0) {
        const bool fresh = m_holdDeadlineMs == 0;
        m_holdDeadlineMs = s_monoMs() + qMin(ttlMs, kHoldMaxMs);
        m_holdUntilWallMs = s_wallMs() + qMin(ttlMs, kHoldMaxMs);
        const bool addrsChanged = addrs != m_holdAddrs;
        m_holdAddrs = addrs;
        persistHold();
        armHoldTimer();
        if (fresh)
            qInfo().noquote() << "[killswitch] kill switch hold: armed, ttl" << ttlMs << "ms, control plane passes:" << addrs.size();
        if (addrsChanged && m_blockHeld && !m_sessionOpen)
            keepBlockForNextSession(); // the seat request of the next leg goes to the current edges
        return true;
    }
    const bool had = m_holdDeadlineMs > 0;
    m_holdDeadlineMs = 0;
    m_holdUntilWallMs = 0;
    m_holdAddrs.clear();
    persistHold();
    if (m_holdTimer)
        m_holdTimer->stop();
    if (had)
        qInfo() << "[killswitch] kill switch hold: released";
    if (m_blockHeld && !m_sessionOpen)
        liftHeldBlock("released");
    return true;
#else
    (void)ttlMs;
    (void)controlPlaneAddrs;
    return true;
#endif
}

bool KillSwitch::holdTimerActive() const
{
#ifdef Q_OS_MACOS
    return m_holdTimer && m_holdTimer->isActive();
#else
    return false;
#endif
}

void KillSwitch::holdTick()
{
#ifdef Q_OS_MACOS
    if (m_holdDeadlineMs == 0)
        return;
    if (s_monoMs() < m_holdDeadlineMs) {
        armHoldTimer();
        return;
    }
    m_holdDeadlineMs = 0;
    m_holdUntilWallMs = 0;
    m_holdAddrs.clear();
    persistHold();
    qInfo() << "[killswitch] kill switch hold: expired (no renewal from the app)";
    if (m_blockHeld && !m_sessionOpen)
        liftHeldBlock("expired");
#endif
}

#ifdef Q_OS_MACOS
bool KillSwitch::holdActive() const
{
    return m_holdDeadlineMs > 0 && s_monoMs() < m_holdDeadlineMs;
}

// The block stays: pf and every anchor of the ended session; its pass table also lets the API edges through (the next
// provider leg's seat request; the person's traffic has no tunnel to pass and stays blocked).
void KillSwitch::keepBlockForNextSession()
{
    m_blockHeld = true;
    QStringList pass = m_sessionAllowAddrs;
    for (const QString &a : m_holdAddrs)
        if (!pass.contains(a))
            pass << a;
    MacOSFirewall::setAnchorEnabled(QStringLiteral("110.allowNets"), true);
    MacOSFirewall::setAnchorTable(QStringLiteral("110.allowNets"), true, QStringLiteral("allownets"), pass);
    qInfo().noquote() << "[killswitch] kill switch hold: the session ended, its block stays until the next session;"
                      << "control plane passes:" << m_holdAddrs.size();
}

void KillSwitch::liftHeldBlock(const char *why)
{
    m_blockHeld = false;
    qInfo().noquote() << "[killswitch] kill switch hold: the block is lifted -" << why;
    if (isStrictKillSwitchEnabled())
        MacOSFirewall::applyStrictBlock();
    else
        MacOSFirewall::uninstall();
}

void KillSwitch::persistHold()
{
    if (!m_appSettigns)
        return;
    if (m_holdDeadlineMs > 0) {
        m_appSettigns->setValue(kHoldUntilKey, m_holdUntilWallMs);
        m_appSettigns->setValue(kHoldAddrsKey, m_holdAddrs);
    } else {
        m_appSettigns->remove(kHoldUntilKey);
        m_appSettigns->remove(kHoldAddrsKey);
    }
}

void KillSwitch::armHoldTimer()
{
    if (!m_holdTimer) {
        m_holdTimer = new QTimer(this);
        m_holdTimer->setSingleShot(true);
        connect(m_holdTimer, &QTimer::timeout, this, &KillSwitch::holdTick);
    }
    const qint64 left = m_holdDeadlineMs - s_monoMs();
    m_holdTimer->start(int(qBound(qint64(0), left + 10, qint64(kHoldMaxMs) + 10)));
}
#endif
