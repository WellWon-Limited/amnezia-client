#include "killswitch.h"


#include <QApplication>
#include <QHostAddress>
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
    bool operationOk = true;
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
    if (m_nativeSessionGuardOwned) {
        // Inner AWG/OpenVPN-era cleanup must not release the durable catalog-v2
        // outer owner. The guard state machine is the sole release authority.
        return MacOSFirewall::isInstalled();
    }
    if (isStrictKillSwitchEnabled()) {
        if (!MacOSFirewall::isInstalled()) MacOSFirewall::install();
        // Quarantine first; normal anchor transitions happen behind the final
        // quick block and therefore cannot create a transient WAN opening.
        operationOk = MacOSFirewall::setAnchorEnabled(
                QStringLiteral("999.quarantine"), true);
        operationOk = MacOSFirewall::ensureRootAnchorPriority() && operationOk;
        operationOk = MacOSFirewall::flushAllStates() && operationOk;
        operationOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("000.allowLoopback"), true) && operationOk;
        operationOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("100.blockAll"), true) && operationOk;
        operationOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("110.allowNets"), false) && operationOk;
        operationOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("120.blockNets"), false) && operationOk;
        operationOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("200.allowVPN"), false) && operationOk;
        operationOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("250.blockIPv6"), true) && operationOk;
        operationOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("290.allowDHCP"), false) && operationOk;
        operationOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("300.allowLAN"), false) && operationOk;
        operationOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("310.blockDNS"), false) && operationOk;
        operationOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("400.allowPIA"), false) && operationOk;
        operationOk = MacOSFirewall::isInstalled()
                && MacOSFirewall::isQuarantineEnabled()
                && operationOk;
    } else {
        MacOSFirewall::uninstall();
        operationOk = !MacOSFirewall::isInstalled();
    }
#endif

#ifdef Q_OS_WIN
    if (isStrictKillSwitchEnabled()) {
        return disableAllTraffic();
    }
    return WindowsFirewall::create(this)->allowAllTraffic();
#endif

    m_allowedRanges.clear();
    return operationOk;
}

bool KillSwitch::disableAllTraffic() {
    bool operationOk = true;
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
    // double-check + ensure our firewall is installed and enabled. This is necessary as
    // other software may disable pfctl before re-enabling with their own rules (e.g other VPNs)
    if (!MacOSFirewall::isInstalled())
        MacOSFirewall::install();
    // Load the terminal quick quarantine before touching any normal anchor.
    // A later normal pass cannot override it, and every command is proven by
    // explicit PF readback before this method reports success.
    operationOk = MacOSFirewall::setAnchorEnabled(
            QStringLiteral("999.quarantine"), true);
    operationOk = MacOSFirewall::ensureRootAnchorPriority() && operationOk;
    operationOk = MacOSFirewall::flushAllStates() && operationOk;
    operationOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("100.blockAll"), true) && operationOk;
    operationOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("000.allowLoopback"), true) && operationOk;
    operationOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("250.blockIPv6"), true) && operationOk;
    operationOk = MacOSFirewall::isInstalled()
            && MacOSFirewall::isQuarantineEnabled()
            && operationOk;
#endif
    m_allowedRanges.clear();
    return operationOk;
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
    if (!MacOSFirewall::setAnchorEnabled(QStringLiteral("110.allowNets"), true)
            || !MacOSFirewall::setAnchorTable(
                    QStringLiteral("110.allowNets"), true,
                    QStringLiteral("allownets"), m_allowedRanges)) {
        return false;
    }
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
    // double-check + ensure our firewall is installed and enabled. This is necessary as
    // other software may disable pfctl before re-enabling with their own rules (e.g other VPNs)
    if (!MacOSFirewall::isInstalled())
        MacOSFirewall::install();

    // Every multi-anchor update is transactional behind the terminal quick
    // block, including the legacy OpenVPN path that does not use the catalog
    // native-session guard.
    bool firewallOk = MacOSFirewall::setAnchorEnabled(
            QStringLiteral("999.quarantine"), true);
    firewallOk = MacOSFirewall::ensureRootAnchorPriority() && firewallOk;
    firewallOk = MacOSFirewall::flushAllStates() && firewallOk;
    firewallOk = MacOSFirewall::isQuarantineEnabled() && firewallOk;
    firewallOk = MacOSFirewall::isInstalled() && firewallOk;
    if (!firewallOk) {
        return false;
    }
    firewallOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("000.allowLoopback"), true) && firewallOk;
    firewallOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("100.blockAll"), blockAll) && firewallOk;
    firewallOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("110.allowNets"), allowNets) && firewallOk;
    firewallOk = MacOSFirewall::setAnchorTable(
            QStringLiteral("110.allowNets"), allowNets,
            QStringLiteral("allownets"), allownets) && firewallOk;

    firewallOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("120.blockNets"), blockNets) && firewallOk;
    firewallOk = MacOSFirewall::setAnchorTable(
            QStringLiteral("120.blockNets"), blockNets,
            QStringLiteral("blocknets"), blocknets) && firewallOk;
    firewallOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("200.allowVPN"), true) && firewallOk;
    firewallOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("250.blockIPv6"), true) && firewallOk;
    firewallOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("290.allowDHCP"), true) && firewallOk;
    firewallOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("300.allowLAN"), true) && firewallOk;

    QStringList dnsServers;
    if (!dns1.isEmpty())
        dnsServers.append(dns1);
    if (!dns2.isEmpty())
        dnsServers.append(dns2);

    dnsServers.append(allowedDnsServers);

    firewallOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("310.blockDNS"), true) && firewallOk;
    firewallOk = MacOSFirewall::setAnchorTable(
            QStringLiteral("310.blockDNS"), true,
            QStringLiteral("dnsaddr"), dnsServers) && firewallOk;
    firewallOk = MacOSFirewall::setAnchorEnabled(QStringLiteral("400.allowPIA"), true) && firewallOk;
    if (!firewallOk) {
        return false; // The pre-existing quarantine intentionally remains armed.
    }
    // Commit the prepared policy by removing the terminal quarantine last.
    if (!MacOSFirewall::setAnchorEnabled(QStringLiteral("999.quarantine"), false)
            || MacOSFirewall::isAnchorEnabled(QStringLiteral("999.quarantine"))) {
        return false;
    }
#endif
    return true;
}

bool KillSwitch::armNativeSessionGuard(const QJsonObject &configStr)
{
#ifdef Q_OS_MACOS
    const int splitMode = configStr.value(QStringLiteral("splitTunnelType")).toInt(-1);
    if (splitMode < 0 || splitMode > 2) {
        return false;
    }
    // PREPARE may replace a stopped inner while the same outer PF owner remains armed. Enter a
    // proven all-traffic blackhole before touching any allow/block table so a multi-anchor PF
    // update can never transiently open WAN. A failed replacement deliberately remains blocked.
    const bool blackholed = disableAllTraffic()
        && MacOSFirewall::isInstalled()
        && MacOSFirewall::isQuarantineEnabled();
    if (!blackholed || !enableKillSwitch(configStr, 0)) {
        disableAllTraffic();
        return false;
    }
    const bool blockAll = splitMode == 0 || splitMode == 2;
    const bool allowNets = blockAll;
    const bool blockNets = splitMode == 1;
    // Read back every anchor whose state defines the outer policy.  A pfctl command returning
    // success without actually loading the expected anchor is not an Armed receipt.
    const bool armed = MacOSFirewall::isInstalled()
        && MacOSFirewall::isAnchorEnabled(QStringLiteral("000.allowLoopback"))
        && MacOSFirewall::isAnchorEnabled(QStringLiteral("100.blockAll")) == blockAll
        && MacOSFirewall::isAnchorEnabled(QStringLiteral("110.allowNets")) == allowNets
        && MacOSFirewall::isAnchorEnabled(QStringLiteral("120.blockNets")) == blockNets
        && MacOSFirewall::isAnchorEnabled(QStringLiteral("200.allowVPN"))
        && MacOSFirewall::isAnchorEnabled(QStringLiteral("250.blockIPv6"))
        && MacOSFirewall::isAnchorEnabled(QStringLiteral("310.blockDNS"))
        && !MacOSFirewall::isAnchorEnabled(QStringLiteral("999.quarantine"));
    if (!armed) disableAllTraffic();
    if (armed) m_nativeSessionGuardOwned = true;
    return armed;
#else
    Q_UNUSED(configStr)
    return false;
#endif
}

bool KillSwitch::quarantineNativeSessionGuard()
{
#ifdef Q_OS_MACOS
    // Set ownership before the PF command so even a partial/error result cannot
    // later be opened by a legacy inner cleanup path.
    m_nativeSessionGuardOwned = true;
    return disableAllTraffic();
#else
    return false;
#endif
}

bool KillSwitch::releaseNativeSessionGuard()
{
#ifdef Q_OS_MACOS
    m_nativeSessionGuardOwned = false;
    if (!disableKillSwitch()) {
        m_nativeSessionGuardOwned = true;
        return false;
    }
    if (isStrictKillSwitchEnabled()) {
        return MacOSFirewall::isInstalled()
            && MacOSFirewall::isAnchorEnabled(QStringLiteral("100.blockAll"))
            && MacOSFirewall::isAnchorEnabled(QStringLiteral("250.blockIPv6"))
            && MacOSFirewall::isQuarantineEnabled()
            && !MacOSFirewall::isAnchorEnabled(QStringLiteral("200.allowVPN"));
    }
    return !MacOSFirewall::isInstalled();
#else
    return false;
#endif
}
