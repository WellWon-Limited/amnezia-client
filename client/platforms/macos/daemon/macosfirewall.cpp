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
#include <QHostAddress>
#include <QRegularExpression>
#include <QSet>
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

int MacOSFirewall::execute(const QString& command, bool ignoreErrors)
{
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
    QDir().mkpath(DaemonDataDir);
    execute(QStringLiteral("pfctl -E 2>&1 | grep -F 'Token : ' | cut -c9- > '%1/pf.token'").arg(DaemonDataDir));
}


void MacOSFirewall::uninstall()
{
    logger.info() << "Uninstalling PF root anchor";

    execute(QStringLiteral("pfctl -q -a '%1' -F all").arg(kRootAnchor));
    execute(QStringLiteral("test -f '%1/pf.token' && pfctl -X `cat '%1/pf.token'` && rm '%1/pf.token'").arg(DaemonDataDir));
    execute(QStringLiteral("test -f /etc/pf.conf && pfctl -F all -f /etc/pf.conf"));
}

bool MacOSFirewall::isInstalled()
{
    return isPFEnabled() && isRootAnchorLoaded();
}

bool MacOSFirewall::isPFEnabled()
{
    return 0 == execute(QStringLiteral("test -s '%1/pf.token' && pfctl -s References | grep -qFf '%1/pf.token'").arg(DaemonDataDir), true);
}

bool MacOSFirewall::ensureRootAnchorPriority()
{
    // We check whether our anchor appears last in the ruleset. If it does not, then remove it and re-add it last (this happens atomically).
    // Appearing last ensures priority.  The second command is an explicit
    // readback; callers must not treat a best-effort pfctl invocation as a
    // fail-closed policy receipt.
    const int update = execute(QStringLiteral(
        "if ! pfctl -sr | tail -1 | grep -qF '%1'; then "
        "echo -e \"$(pfctl -sr | grep -vF '%1')\\n\"'anchor \"%1\"' | pfctl -f -; fi")
        .arg(kRootAnchor));
    const int readback = execute(QStringLiteral(
        "pfctl -sr | tail -1 | grep -qF '%1'").arg(kRootAnchor), true);
    return update == 0 && readback == 0;
}

bool MacOSFirewall::isRootAnchorLoaded()
{
    // Our Root anchor is loaded if:
    // 1. It is is included among the top-level anchors
    // 2. It is not empty (i.e it contains sub-anchors)
    return 0 == execute(QStringLiteral("pfctl -sr | grep -q '%1' && pfctl -q -a '%1' -s rules 2> /dev/null | grep -q .").arg(kRootAnchor), true);
}

bool MacOSFirewall::enableAnchor(const QString& anchor)
{
    // Always reload the sealed resource. A non-empty anchor is not evidence
    // that it contains the intended policy (it may be stale or partial).
    const int result = execute(QStringLiteral(
        "pfctl -q -a '%1/%2' -F all -f '%3/%1.%2.conf'")
        .arg(kRootAnchor, anchor, ResourceDir));
    return result == 0 && isAnchorEnabled(anchor);
}

bool MacOSFirewall::disableAnchor(const QString& anchor)
{
    const int result = execute(QStringLiteral("if ! pfctl -q -a '%1/%2' -s rules 2> /dev/null | grep -q . ; then echo '%2: OFF' ; else echo '%2: ON -> OFF' ; pfctl -q -a '%1/%2' -F all ; fi").arg(kRootAnchor, anchor));
    return result == 0 && !isAnchorEnabled(anchor);
}

bool MacOSFirewall::isAnchorEnabled(const QString& anchor)
{
    return 0 == execute(QStringLiteral("pfctl -q -a '%1/%2' -s rules 2> /dev/null | grep -q .").arg(kRootAnchor, anchor), true);
}

bool MacOSFirewall::isQuarantineEnabled()
{
    // PF canonicalizes `flags any no state` away on current macOS releases,
    // while older releases may retain either suffix.  Require exactly one
    // semantically identical terminal quick block and reject a merely
    // non-empty/stale anchor.  Keep this accepted set in sync with the
    // dry-run contract in metadata/tests/test_macos_pf_contract.py.
    return 0 == execute(QStringLiteral(
        "rules=\"$(pfctl -q -a '%1/999.quarantine' -s rules 2>/dev/null)\"; "
        "test \"$(printf '%%s\\n' \"$rules\" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')\" = 1 "
        "&& printf '%%s\\n' \"$rules\" | grep -Eq "
        "'^block drop quick all( flags any( no state)?)?$'")
        .arg(kRootAnchor), true);
}

bool MacOSFirewall::flushAllStates()
{
    // Existing PF states bypass filter evaluation. Emergency quarantine is
    // not proven until every pre-quarantine state has been invalidated.
    return execute(QStringLiteral("pfctl -q -F states")) == 0;
}

bool MacOSFirewall::setAnchorEnabled(const QString& anchor, bool enabled)
{
    return enabled ? enableAnchor(anchor) : disableAnchor(anchor);
}

bool MacOSFirewall::setAnchorTable(const QString& anchor, bool enabled,
                                  const QString& table,
                                  const QStringList& items)
{
    static const QRegularExpression anchorPattern(
            QStringLiteral(R"(^[0-9]{3}\.[A-Za-z0-9]+$)"));
    static const QRegularExpression tablePattern(
            QStringLiteral(R"(^[a-z][a-z0-9]{0,31}$)"));
    if (!anchorPattern.match(anchor).hasMatch()
            || !tablePattern.match(table).hasMatch()
            || items.size() > 4096) {
        return false;
    }
    if (!enabled) {
        execute(QStringLiteral("pfctl -q -a '%1/%2' -t '%3' -T kill")
                        .arg(kRootAnchor, anchor, table), true);
        return execute(QStringLiteral(
                    "! pfctl -q -a '%1/%2' -t '%3' -T show >/dev/null 2>&1")
                    .arg(kRootAnchor, anchor, table), true) == 0;
    }

    QStringList uniqueItems;
    QSet<QString> seen;
    for (const QString &item : items) {
        const QHostAddress direct(item);
        const auto subnet = QHostAddress::parseSubnet(item);
        const bool valid = !direct.isNull()
                || (!subnet.first.isNull() && subnet.second >= 0
                    && subnet.second <= (subnet.first.protocol()
                            == QAbstractSocket::IPv4Protocol ? 32 : 128));
        if (!valid) return false;
        if (!seen.contains(item)) {
            seen.insert(item);
            uniqueItems.append(item);
        }
    }
    const int replaced = execute(QStringLiteral(
            "pfctl -q -a '%1/%2' -t '%3' -T replace %4")
            .arg(kRootAnchor, anchor, table, uniqueItems.join(' ')));
    if (replaced != 0) return false;
    for (const QString &item : uniqueItems) {
        if (execute(QStringLiteral(
                    "pfctl -q -a '%1/%2' -t '%3' -T test '%4' >/dev/null")
                    .arg(kRootAnchor, anchor, table, item), true) != 0) {
            return false;
        }
    }
    return execute(QStringLiteral(
            "test \"$(pfctl -q -a '%1/%2' -t '%3' -T show 2>/dev/null "
            "| sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')\" -eq %4")
            .arg(kRootAnchor, anchor, table)
            .arg(uniqueItems.size()), true) == 0;
}

void MacOSFirewall::setAnchorWithRules(const QString& anchor, bool enabled, const QStringList &ruleList)
{
    if (!enabled)
        return (void)execute(QStringLiteral("pfctl -q -a '%1/%2' -F rules").arg(kRootAnchor, anchor), true);
    else
        return (void)execute(QStringLiteral("echo -e \"%1\" | pfctl -q -a '%2/%3' -f -").arg(ruleList.join('\n'), kRootAnchor, anchor), true);
}
