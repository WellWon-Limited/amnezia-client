// Copyright (c) 2023 Private Internet Access, Inc.
//
// This file is part of the Private Internet Access Desktop Client.
//
// The Private Internet Access Desktop Client is free software: you can
// redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// The Private Internet Access Desktop Client is distributed in the hope that
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the Private Internet Access Desktop Client.  If not, see
// <https://www.gnu.org/licenses/>.

// Copyright (c) 2024 AmneziaVPN
// This file has been modified for AmneziaVPN
//
// This file is based on the work of the Private Internet Access Desktop Client.
// The original code of the Private Internet Access Desktop Client is copyrighted (c) 2023 Private Internet Access, Inc. and licensed under GPL3.
//
// The modified version of this file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this file. If not, see <https://www.gnu.org/licenses/>.

#ifndef MACOSFIREWALL_H
#define MACOSFIREWALL_H

#include <QString>
#include <QStringList>

// Descriptor for a set of firewall rules to be appled.
//
struct FirewallParams
{
    QStringList dnsServers;
    QVector<QString> excludeApps; // Apps to exclude if VPN exemptions are enabled

    QStringList allowAddrs;
    QStringList blockAddrs;

    // The follow flags indicate which general rulesets are needed. Note that
    // this is after some sanity filtering, i.e. an allow rule may be listed
    // as not needed if there were no block rules preceding it. The rulesets
    // should be thought of as in last-match order.

    bool blockAll;      // Block all traffic by default
    bool blockNets;
    bool allowNets;
    bool allowVPN;      // Exempt traffic through VPN tunnel
    bool allowDHCP;     // Exempt DHCP traffic
    bool blockIPv6;     // Block all IPv6 traffic
    bool allowLAN;      // Exempt LAN traffic, including IPv6 LAN traffic
    bool blockDNS;      // Block all DNS traffic except specified DNS servers
    bool allowPIA;      // Exempt PIA executables
    bool allowLoopback; // Exempt loopback traffic
    bool allowHnsd;     // Exempt Handshake DNS traffic
    bool allowVpnExemptions; // Exempt specified traffic from the tunnel (route it over the physical uplink instead)
};

class MacOSFirewall
{

private:
    static int execute(const QString &command, bool ignoreErrors = false);
    static bool isPFEnabled();
    static bool isRootAnchorLoaded();

public:
    static void install();
    static void uninstall();
    static bool isInstalled();
    static void enableAnchor(const QString &anchor);
    static void disableAnchor(const QString &anchor);
    static bool isAnchorEnabled(const QString &anchor);
    static void setAnchorEnabled(const QString &anchor, bool enable);
    static void setAnchorTable(const QString &anchor, bool enabled, const QString &table, const QStringList &items);
    static void setAnchorWithRules(const QString &anchor, bool enabled, const QStringList &rules);
    static void ensureRootAnchorPriority();
    static void installRootAnchors();

    // AVPN (Scanner, plan scanner-client-plan.md R6): while a scan runs, the root service's own probe
    // sockets must pass the kill switch. The AmneziaWG kill switch (WireguardUtilsMacos::
    // applyFirewallRules) blocks all outbound traffic except its excluded addresses (the peer), the tunnel's
    // own utun, LAN, DHCP and its DNS, and never enables 400.allowPIA - so probes bound to the uplink would be dropped. The Xray kill
    // switch (KillSwitch::enableKillSwitch) enables 400.allowPIA, which already passes them.
    // The exemption is ONE quick pass in the sub-anchor 160.allowScan (declared in tribe.conf), scoped to
    // the service's pf identity (the launchd GroupName of Tribe-service, as in tribe.400.allowPIA.conf)
    // and to the uplink the probes are bound to. No address-only rule: a user application never runs with
    // the service's group, so it never matches. Not a table of probe endpoints either: probes resolve
    // provider hostnames and the probe host themselves (CDN answers vary), and a dropped direct access
    // attempt would be read as "the access network cannot reach the probe host" (the exclusion proof).
    static QString scanExemptionIdentity()
    {
#ifdef MZ_DEBUG
        return QStringLiteral("user { root }"); // = AMN_PF_RULE_IDENTITY of a Debug build (CMakeLists.txt)
#else
        return QStringLiteral("group { tribevpn }");
#endif
    }
    static QStringList scanExemptionRules(const QString &uplinkIfname)
    {
        if (uplinkIfname.isEmpty() || uplinkIfname.size() > 15)
            return {};
        for (const QChar c : uplinkIfname) {
            if (!((c >= QLatin1Char('a') && c <= QLatin1Char('z')) || (c >= QLatin1Char('A') && c <= QLatin1Char('Z'))
                  || (c >= QLatin1Char('0') && c <= QLatin1Char('9'))))
                return {}; // the name goes into a shell command line: plain BSD names only
        }
        return {QStringLiteral("pass out quick on %1 proto { tcp, udp } %2 flags any no state")
                    .arg(uplinkIfname, scanExemptionIdentity())};
    }
    // Loads the rules when our root anchor is installed (the kill switch owns pf now). Always flushes the
    // sub-anchor first. 1 = armed, 0 = not needed (pf is not ours: nothing of ours blocks the probes),
    // -1 = needed but not loaded (an unsafe name, a pfctl failure): the caller must not probe then.
    static int setScanExemption(const QString &uplinkIfname);
    // Flushes the sub-anchor; safe in every pf state (also when pf is not ours or off).
    static void clearScanExemption();
};

#endif // MACOSFIREWALL_H
