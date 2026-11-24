// AVPN (pf state ownership, 2026-11-24): who owns each sub-anchor of the service's pf root anchor "tribe"
// (deploy/data/macos/pf/tribe.conf) and what a session may take over from the kernel.
//
// Why: pf keeps a sub-anchor's rules and tables in the kernel until they are flushed or the Mac reboots -
// flushing the root anchor or reloading /etc/pf.conf does not touch them. Before this rule a stop flushed
// only the root anchor, and an enable loaded a sub-anchor's file only when the kernel copy was empty. So
// after an AmneziaWG session (200.allowVPN = "pass out on <its utun>") the next own or provider Xray
// session kept that rule: 100.blockAll dropped everything leaving the Xray tun except DNS (owner's Mac,
// 24.11.2026: 16 of 16 Xray sessions after an AWG session got no data, 5 of 5 without one worked).
//
// The rule (MacOSFirewall, macosfirewall.cpp):
//  - Static: the bundled file is the whole content and it is the same for every session. Loading it only
//    when the kernel copy is empty (MacOSFirewall::enableAnchor) is exact, because nothing else writes it
//    and every stop flushes it (an older build's copy cannot survive into a session of this one).
//  - StaticRuleSessionTable: the rule is static (as above); its table is the session's and every session
//    writes it explicitly (MacOSFirewall::setAnchorTable: -T replace, or -T kill when unused).
//  - SessionRule: the rule depends on the session (200.allowVPN: the session's own tun only, wave 3). It
//    is written explicitly by the session that owns it and never taken over from the kernel.
//  - ScanRule: 160.allowScan, armed by the probe host for one scan and flushed when the scan ends
//    (service/server/tribe_scan.cpp); a tunnel session neither writes nor flushes it.
//  - Unused: declared in tribe.conf, never enabled (upstream PIA leftovers); flushed on every stop.
//  - Retired: no longer in tribe.conf; still flushed on every stop, because the main ruleset evaluates
//    every child of "tribe" ("anchor tribe/*") and an older build's copy would stay in force. Never
//    remove a name from this table: retire it.
//  A stop (MacOSFirewall::uninstall) flushes the rules and tables of every anchor here. With the strict
//  kill switch the stop keeps the block instead (MacOSFirewall::applyStrictBlock): the strictBlock anchors
//  are reloaded from their files and every other anchor except the scan's is flushed.
#ifndef MACOSPFANCHORS_H
#define MACOSPFANCHORS_H

#include <QString>
#include <QStringList>

namespace avpn {
namespace pf {

enum class AnchorKind { Static, StaticRuleSessionTable, SessionRule, ScanRule, Unused, Retired };

struct AnchorSpec {
    const char *name;
    AnchorKind kind;
    bool strictBlock; // stays loaded after a stop with the strict kill switch
};

// Every sub-anchor the service ever loaded under "tribe", in tribe.conf order, retired names last.
inline const QList<AnchorSpec> &anchors()
{
    static const QList<AnchorSpec> list = {
        { "000.allowLoopback", AnchorKind::Static, true },
        { "100.blockAll", AnchorKind::Static, true },
        { "110.allowNets", AnchorKind::StaticRuleSessionTable, false },   // table <allownets>
        { "120.blockNets", AnchorKind::StaticRuleSessionTable, false },   // table <blocknets>
        { "150.allowExcludedApps", AnchorKind::Unused, false },
        { "160.allowScan", AnchorKind::ScanRule, false },
        { "200.allowVPN", AnchorKind::SessionRule, false },
        { "250.blockIPv6", AnchorKind::Static, true },
        { "290.allowDHCP", AnchorKind::Static, false },
        { "300.allowLAN", AnchorKind::Static, false },                    // static table <lanips>
        { "310.blockDNS", AnchorKind::StaticRuleSessionTable, false },    // table <dnsaddr>
        { "350.allowHnsd", AnchorKind::Unused, false },
        { "400.allowPIA", AnchorKind::Static, false },
        { "999.quarantine", AnchorKind::Retired, false },                 // 7d36adc96 .. a69449817 (Aug-Sep 2026)
    };
    return list;
}

inline const AnchorSpec *findAnchor(const QString &name)
{
    for (const AnchorSpec &a : anchors()) {
        if (name == QLatin1String(a.name))
            return &a;
    }
    return nullptr;
}

// True when the kernel copy of the anchor's rules may be kept as it is (MacOSFirewall::enableAnchor):
// only for rules that are the same for every session. Unknown names are never taken over.
inline bool kernelCopyIsCurrent(const QString &name)
{
    const AnchorSpec *a = findAnchor(name);
    return a && (a->kind == AnchorKind::Static || a->kind == AnchorKind::StaticRuleSessionTable);
}

// Names flushed by a stop: all of them.
inline QStringList stopFlushList()
{
    QStringList out;
    for (const AnchorSpec &a : anchors())
        out << QString::fromLatin1(a.name);
    return out;
}

// The block that stays after a stop with the strict kill switch.
inline QStringList strictBlockList()
{
    QStringList out;
    for (const AnchorSpec &a : anchors()) {
        if (a.strictBlock)
            out << QString::fromLatin1(a.name);
    }
    return out;
}

// Flushed by a stop with the strict kill switch: everything but the block and the scan's anchor (the probe
// host flushes that one itself when its scan ends; the service ends every scan before a tunnel change).
inline QStringList strictFlushList()
{
    QStringList out;
    for (const AnchorSpec &a : anchors()) {
        if (!a.strictBlock && a.kind != AnchorKind::ScanRule)
            out << QString::fromLatin1(a.name);
    }
    return out;
}

// A macOS tunnel interface name: "utun" + 1-3 digits. The name goes into a shell command line.
inline bool isTunnelIfname(const QString &ifname)
{
    if (ifname.size() < 5 || ifname.size() > 7 || !ifname.startsWith(QLatin1String("utun")))
        return false;
    for (int i = 4; i < ifname.size(); ++i) {
        if (ifname.at(i) < QLatin1Char('0') || ifname.at(i) > QLatin1Char('9'))
            return false;
    }
    return true;
}

// 200.allowVPN of a session: pass out only on the session's own tun (wave 3, 6f0bdf723: the static file
// passes utun0-utun30, i.e. also a foreign VPN's tun). Empty = the tun is unknown or not a tun name; the
// caller then writes the static file explicitly.
inline QStringList tunnelPassRules(const QString &ifname)
{
    if (!isTunnelIfname(ifname))
        return {};
    return { QStringLiteral("pass out on %1 flags any no state").arg(ifname) };
}

} // namespace pf
} // namespace avpn

#endif // MACOSPFANCHORS_H
