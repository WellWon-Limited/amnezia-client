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

#include "macosfirewall.h"
#include "macospfanchors.h" // AVPN (pf state ownership)
#include "logger.h"
#include <QProcess>
#include <QCoreApplication>

// AVPN: свой PF-анкор — официальная Amnezia использует "amn", общий анкор означает,
// что два демона перетирают правила фаервола друг друга (имена pf-файлов в deploy/
// data/macos/pf/ обязаны начинаться с этого же префикса: enableAnchor() ищет
// "<brand>.<anchor>.conf")
#define BRAND_IDENTIFIER "tribe"

namespace {
    Logger logger("MacOSFirewall");
}  // namespace

#include "macosfirewall.h"

#include <QDir>
#include <QStandardPaths>

// Read-only rules bundled with the application.
#define ResourceDir (qApp->applicationDirPath() + "/pf")

// Writable location that does NOT live inside the signed bundle.  Using a
// constant path under /Library/Application Support keeps the signature intact
// and is accessible to the root helper.
#define DaemonDataDir QStringLiteral("/Library/Application Support/TribeVPN/pf") // AVPN: не делить каталог с офиц. Amnezia

#include <QProcess>

static QString kRootAnchor = QStringLiteral(BRAND_IDENTIFIER);
static QByteArray kPfWarning = "pfctl: Use of -f option, could result in flushing of rules\npresent in the main ruleset added by the system at startup.\nSee /etc/pf.conf for further details.\n";

int waitForExitCode(QProcess& process)
{
    if (!process.waitForFinished() || process.error() == QProcess::FailedToStart)
        return -2;
    else if (process.exitStatus() != QProcess::NormalExit)
        return -1;
    else
        return process.exitCode();
}

// AVPN (pf state ownership): the host check's command seam (macosfirewall.h).
static MacOSFirewall::CommandRunner s_commandRunner = nullptr;

void MacOSFirewall::setCommandRunner(CommandRunner runner)
{
    s_commandRunner = runner;
}

int MacOSFirewall::execute(const QString& command, bool ignoreErrors)
{
    if (s_commandRunner) // AVPN: host check only
        return s_commandRunner(command);

    QProcess p;

    p.start(QStringLiteral("/bin/bash"), { QStringLiteral("-c"), command }, QProcess::ReadOnly);
    p.closeWriteChannel();
    int exitCode = waitForExitCode(p);
    auto out = p.readAllStandardOutput().trimmed();

    auto err = p.readAllStandardError().replace(kPfWarning, "").trimmed();
    if ((exitCode != 0 || !err.isEmpty()) && !ignoreErrors)
        logger.info() << "(" << exitCode << ") $ " << command;
    else if (false)
        logger.info() << "(" << exitCode << ") $ " << command;
    if (!out.isEmpty()) logger.info() << out;
    if (!err.isEmpty()) logger.info() << err;
    return exitCode;
}

void MacOSFirewall::installRootAnchors()
{
    logger.info() << "Installing PF root anchors";

    // Append our NAT anchors by reading back and re-applying NAT rules only
    auto insertNatAnchors = QStringLiteral(
        "( "
        R"(pfctl -sn | grep -v '%1/*'; )"   // Translation rules (includes both nat and rdr, despite the modifier being 'nat')
        R"(echo 'nat-anchor "%2/*"'; )"     // PIA's translation anchors
        R"(echo 'rdr-anchor "%3/*"'; )"
        R"(echo 'load anchor "%4" from "%5/%6.conf"'; )" // Load the PIA anchors from file
        ") | pfctl -N -f -").arg(kRootAnchor, kRootAnchor, kRootAnchor, kRootAnchor, ResourceDir, kRootAnchor);

    execute(insertNatAnchors);

    // Append our filter anchor by reading back and re-applying filter rules
    // only.  pfctl -sr also includes scrub rules, but these will be ignored
    // due to -R.
    auto insertFilterAnchor = QStringLiteral(
        "( "
        R"(pfctl -sr | grep -v '%1/*'; )"   // Filter rules (everything from pfctl -sr except 'scrub')
        R"(echo 'anchor "%2/*"'; )"         // PIA's filter anchors
        R"(echo 'load anchor "%3" from "%4/%5.conf"'; )" // Load the PIA anchors from file
        " ) | pfctl -R -f -").arg(kRootAnchor, kRootAnchor, kRootAnchor, ResourceDir, kRootAnchor);
    execute(insertFilterAnchor);
}

void MacOSFirewall::install()
{
    // remove hard-coded (legacy) pia anchor from /etc/pf.conf if it exists
    execute(QStringLiteral("if grep -Fq '%1' /etc/pf.conf ; then echo \"`cat /etc/pf.conf | grep -vF '%1'`\" > /etc/pf.conf ; fi").arg(kRootAnchor));

    // Clean up any existing rules if they exist.
    uninstall();

    timespec waitTime{0, 10'000'000};
    ::nanosleep(&waitTime, nullptr);

    logger.info() << "Installing PF root anchor";

    installRootAnchors();
    // Ensure writable directory exists, then store the token there.
    // AVPN (pf state ownership): mkdir in the same command, so the host check's seam sees every effect.
    execute(QStringLiteral("mkdir -p '%1' ; pfctl -E 2>&1 | grep -F 'Token : ' | cut -c9- > '%1/pf.token'").arg(DaemonDataDir));
}


void MacOSFirewall::uninstall()
{
    logger.info() << "Uninstalling PF root anchor";

    execute(QStringLiteral("pfctl -q -a '%1' -F all").arg(kRootAnchor));
    execute(QStringLiteral("test -f '%1/pf.token' && pfctl -X `cat '%1/pf.token'` && rm '%1/pf.token'").arg(DaemonDataDir));
    execute(QStringLiteral("test -f /etc/pf.conf && pfctl -F all -f /etc/pf.conf"));
    // AVPN (pf state ownership, macospfanchors.h): the commands above leave every sub-anchor's rules and
    // tables in the kernel until a reboot, and the next session took them for its own (an AWG session's
    // 200.allowVPN broke the next Xray session). A stop leaves nothing: flush them all, after the main
    // ruleset no longer references them (no packet sees a half-flushed set). install() runs this first too,
    // so a fresh install never starts from a previous process's or an older build's anchors.
    flushAnchors(avpn::pf::stopFlushList());
}

void MacOSFirewall::flushAnchors(const QStringList& anchors)
{
    QStringList commands;
    for (const QString& anchor : anchors)
        commands << QStringLiteral("pfctl -q -a '%1/%2' -F all 2> /dev/null").arg(kRootAnchor, anchor);
    if (!commands.isEmpty())
        execute(commands.join(QStringLiteral(" ; ")), true);
}

void MacOSFirewall::reloadAnchor(const QString& anchor)
{
    execute(QStringLiteral("pfctl -q -a '%1/%2' -f '%3/%1.%2.conf'").arg(kRootAnchor, anchor, ResourceDir));
}

bool MacOSFirewall::isInstalled()
{
    return isPFEnabled() && isRootAnchorLoaded();
}

bool MacOSFirewall::isPFEnabled()
{
    return 0 == execute(QStringLiteral("test -s '%1/pf.token' && pfctl -s References | grep -qFf '%1/pf.token'").arg(DaemonDataDir), true);
}

void MacOSFirewall::ensureRootAnchorPriority()
{
    // We check whether our anchor appears last in the ruleset. If it does not, then remove it and re-add it last (this happens atomically).
    // Appearing last ensures priority.
    execute(QStringLiteral("if ! pfctl -sr | tail -1 | grep -qF '%1'; then echo -e \"$(pfctl -sr | grep -vF '%1')\\n\"'anchor \"%1\"' | pfctl -f - ; fi").arg(kRootAnchor));
}

bool MacOSFirewall::isRootAnchorLoaded()
{
    // Our Root anchor is loaded if:
    // 1. It is is included among the top-level anchors
    // 2. It is not empty (i.e it contains sub-anchors)
    return 0 == execute(QStringLiteral("pfctl -sr | grep -q '%1' && pfctl -q -a '%1' -s rules 2> /dev/null | grep -q .").arg(kRootAnchor), true);
}

void MacOSFirewall::enableAnchor(const QString& anchor)
{
    // AVPN (pf state ownership, macospfanchors.h): "load only when empty" is exact for static rules only.
    // Any other anchor's kernel copy belongs to whoever wrote it last: write it from the file instead.
    if (!avpn::pf::kernelCopyIsCurrent(anchor)) {
        logger.info() << anchor << ": written from its file (not taken over from the kernel)";
        reloadAnchor(anchor);
        return;
    }
    execute(QStringLiteral("if pfctl -q -a '%1/%2' -s rules 2> /dev/null | grep -q . ; then echo '%2: ON' ; else echo '%2: OFF -> ON' ; pfctl -q -a '%1/%2' -F all -f '%3/%1.%2.conf' ; fi").arg(kRootAnchor, anchor, ResourceDir));
}

void MacOSFirewall::disableAnchor(const QString& anchor)
{
    execute(QStringLiteral("if ! pfctl -q -a '%1/%2' -s rules 2> /dev/null | grep -q . ; then echo '%2: OFF' ; else echo '%2: ON -> OFF' ; pfctl -q -a '%1/%2' -F all ; fi").arg(kRootAnchor, anchor));
}

bool MacOSFirewall::isAnchorEnabled(const QString& anchor)
{
    return 0 == execute(QStringLiteral("pfctl -q -a '%1/%2' -s rules 2> /dev/null | grep -q .").arg(kRootAnchor, anchor), true);
}

void MacOSFirewall::setAnchorEnabled(const QString& anchor, bool enabled)
{
    if (enabled)
        enableAnchor(anchor);
    else
        disableAnchor(anchor);
}

void MacOSFirewall::setAnchorTable(const QString& anchor, bool enabled, const QString& table, const QStringList& items)
{
    if (enabled)
        execute(QStringLiteral("pfctl -q -a '%1/%2' -t '%3' -T replace %4").arg(kRootAnchor, anchor, table, items.join(' ')));
    else
        execute(QStringLiteral("pfctl -q -a '%1/%2' -t '%3' -T kill").arg(kRootAnchor, anchor, table), true);
}

void MacOSFirewall::setAnchorWithRules(const QString& anchor, bool enabled, const QStringList &ruleList)
{
    if (!enabled)
        return (void)execute(QStringLiteral("pfctl -q -a '%1/%2' -F rules").arg(kRootAnchor, anchor), true);
    else
        return (void)execute(QStringLiteral("echo -e \"%1\" | pfctl -q -a '%2/%3' -f -").arg(ruleList.join('\n'), kRootAnchor, anchor), true);
}

// AVPN (Scanner, plan R6): the scan-lifetime exemption of the service's probe sockets (macosfirewall.h).
static const QString kScanAnchor = QStringLiteral("160.allowScan");

int MacOSFirewall::setScanExemption(const QString& uplinkIfname)
{
    clearScanExemption();
    if (!isInstalled())
        return 0;
    const QStringList rules = scanExemptionRules(uplinkIfname);
    if (rules.isEmpty())
        return -1;
    setAnchorWithRules(kScanAnchor, true, rules);
    return isAnchorEnabled(kScanAnchor) ? 1 : -1;
}

void MacOSFirewall::clearScanExemption()
{
    setAnchorWithRules(kScanAnchor, false, {});
}

// AVPN (pf state ownership, 2026-11-24, macospfanchors.h): the kill switch of one tunnel session.
static const QString kTunnelAnchor = QStringLiteral("200.allowVPN");

void MacOSFirewall::setTunnelPass(const QString& tunnelIfname)
{
    const QStringList rules = avpn::pf::tunnelPassRules(tunnelIfname);
    if (!rules.isEmpty()) {
        logger.info() << kTunnelAnchor << ": pass out on" << tunnelIfname << "only";
        setAnchorWithRules(kTunnelAnchor, true, rules);
        return;
    }
    logger.warning() << kTunnelAnchor << ": the session's tunnel interface is unknown - every utun passes (static file)";
    reloadAnchor(kTunnelAnchor);
}

void MacOSFirewall::applySessionRules(const FirewallParams& params, const QString& tunnelIfname)
{
    // double-check + ensure our firewall is installed and enabled. This is necessary as
    // other software may disable pfctl before re-enabling with their own rules (e.g other VPNs)
    if (!isInstalled())
        install();

    ensureRootAnchorPriority();
    setAnchorEnabled(QStringLiteral("000.allowLoopback"), true);
    setAnchorEnabled(QStringLiteral("100.blockAll"), params.blockAll);
    setAnchorEnabled(QStringLiteral("110.allowNets"), params.allowNets);
    setAnchorTable(QStringLiteral("110.allowNets"), params.allowNets, QStringLiteral("allownets"), params.allowAddrs);
    setAnchorEnabled(QStringLiteral("120.blockNets"), params.blockNets);
    setAnchorTable(QStringLiteral("120.blockNets"), params.blockNets, QStringLiteral("blocknets"), params.blockAddrs);
    setTunnelPass(tunnelIfname);
    setAnchorEnabled(QStringLiteral("250.blockIPv6"), true);
    setAnchorEnabled(QStringLiteral("290.allowDHCP"), true);
    setAnchorEnabled(QStringLiteral("300.allowLAN"), true);
    setAnchorEnabled(QStringLiteral("310.blockDNS"), true);
    setAnchorTable(QStringLiteral("310.blockDNS"), true, QStringLiteral("dnsaddr"), params.dnsServers);
    // Set either way: the AmneziaWG kill switch never passes the service's group, and an Xray session's
    // pass must not outlive it.
    setAnchorEnabled(QStringLiteral("400.allowPIA"), params.allowPIA);
}

void MacOSFirewall::applyStrictBlock()
{
    // double-check + ensure our firewall is installed and enabled (as applySessionRules)
    if (!isInstalled())
        install();

    ensureRootAnchorPriority();
    logger.info() << "Strict kill switch: the block is reloaded, every session anchor is flushed";
    // The block first, then the exemptions go: no moment without both.
    for (const QString& anchor : avpn::pf::strictBlockList())
        reloadAnchor(anchor);
    flushAnchors(avpn::pf::strictFlushList());
}

void MacOSFirewall::addBlockToSession()
{
    if (!isInstalled()) {
        logger.warning() << "Strict kill switch over a live session: our pf is not in force - the block comes at the session's stop";
        return;
    }
    ensureRootAnchorPriority();
    logger.info() << "Strict kill switch over a live session: its anchors stay, the block is added";
    for (const QString& anchor : avpn::pf::strictBlockList())
        enableAnchor(anchor);
}
