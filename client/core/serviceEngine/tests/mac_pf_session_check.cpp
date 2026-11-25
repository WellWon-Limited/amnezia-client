// AVPN (macOS pf state ownership, 2026-11-24): the real KillSwitch (service/server/killswitch.cpp) and the real
// MacOSFirewall (client/platforms/macos/daemon/macosfirewall.cpp) run against a model of the pf kernel state
// instead of /bin/bash: the firewall's command seam (MacOSFirewall::setCommandRunner) hands every command to the
// model, which keeps the rules and tables of the root anchor "tribe" and of each sub-anchor, the main ruleset's
// reference and our pf token, and reads the real anchor files (deploy/data/macos/pf). Nothing is executed: an
// unmodelled command fails the check. pfctl is never run. Tables follow pf.conf(5), TABLES (macOS 27):
//   "persist  The persist flag forces the kernel to keep the table even when no rules refer to it.  If the
//    flag is not set, the kernel will automatically remove the table when the last rule referring to it is
//    flushed."
//   "manually  Persistent tables can be manually created with the add or replace option of pfctl(8)"
//   "The contents of a pre-existing table defined without a list of addresses to initialize it is not altered
//    when pf.conf is loaded.  A table initialized with the empty list, { }, will be cleared on load."
// and pfctl(8): "-T kill  Kill a table.", "-T replace  Replace the addresses of the table.  Automatically create
// a nonexisting table.", "-F Tables  Flush the tables." (-F all = all of the -F modifiers). Not in the man
// pages, modelled conservatively: -T replace keeps the flags of an existing table; a file's definition sets
// the flags of the table it defines.
//
// Every session is driven through the service's own entry points, in the order its callers use them:
//   AmneziaWG start = KillSwitch::openTunnelSession(params, utun) (WireguardUtilsMacos::applyFirewallRules,
//                     params as WireguardUtilsMacos::addInterface builds them), stop = disableKillSwitch
//                     (WireguardUtilsMacos::deleteInterface);
//   Xray start      = KillSwitch::tunnelCreated(tun) (IpcServer::createTun after Router::createTun) then
//                     enableKillSwitch(config) (XrayProtocol::setupRouting), stop = disableKillSwitch then
//                     IpcServer::deleteTun (XrayProtocol::stop; the lost-client teardown of fix/mac-xray-quit
//                     uses the same order); OpenVPN = enableKillSwitch with no createTun;
//   service start   = a new KillSwitch + init() (LocalServer); strict on/off = refresh(bool) (refreshKillSwitch).
// The call sites themselves are checked by check_mac_pf_session_wiring.sh.
//   P1  reboot -> AWG(utunA): installed, 200.allowVPN passes utunA only, 400.allowPIA empty
//   P2  AWG -> stop: every tribe/* anchor (rules and tables), the root anchor and the token are gone
//   P3  AWG(utunA) -> stop -> Xray(utun22): 200.allowVPN passes exactly utun22 (the field defect, 24.11)
//   P4  Xray -> stop -> AWG(utunB): 200.allowVPN = utunB, 400.allowPIA empty
//   P5  AWG(utunA) -> AWG(utunB), with and without a stop: 200.allowVPN = utunB only
//   P6  client lost (no stop, no deleteTun): the next session's 200/400 are its own
//   P7  a session with no tun of its own (OpenVPN) gets the static file - also after a lost Xray client
//   P8  strict kill switch with no session: the block stays, every session anchor is flushed
//   P9  strict keeps the scan's own 160.allowScan; a full stop flushes it
//   P10 service start after a process died with pf installed (AWG session, scan, retired anchor)
//   P11 a session after an older build stopped with the root-only flush (pf not ours, anchors left)
//   P12 service start with strict on and stale anchors: only the block, from the current files
//   P13 enableAnchor never keeps the kernel copy of a session anchor; keeps a static one
//   P14 tunnel interface names
//   P15 the ownership table matches tribe.conf and the files
//   P16 a late deleteTun of an older session does not change the newer session's tun
//   P17 a createTun no session takes is dropped by the next session opened or by a stop
//   P18 strict turned on over a live session keeps its rules; the block outlives it; strict off = no pf
//   P19 the table model itself (the man page lines above)
//   P20 DNS passes to the session's resolvers only through its own tun (static file: tunnels only) - review N1
// Build and run: tests/build_mac_pf_session.sh. PF_CHECK_API_57F10A133 builds the same sequences against the
// entry points of commit 57f10a133 (setTunnelInterface / clearTunnelInterface, AWG through applySessionRules).
#include "platforms/macos/daemon/macosfirewall.h"
#include "platforms/macos/daemon/macospfanchors.h"
#include "killswitch.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonObject>
#include <QMap>
#include <QRegularExpression>
#include <QStringList>

#include <cstdio>

extern KillSwitch *s_instance; // killswitch.cpp: the singleton; a new one = a new service process

static int g_checks = 0;
static int g_failed = 0;
static const char *g_case = "";
#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        ++g_checks;                                                                                                    \
        if (!(cond)) {                                                                                                 \
            ++g_failed;                                                                                                \
            std::printf("FAIL [%s] %s:%d: %s\n", g_case, __FILE__, __LINE__, #cond);                                  \
        }                                                                                                              \
    } while (0)
#define CHECK_EQ(actual, expected)                                                                                     \
    do {                                                                                                               \
        ++g_checks;                                                                                                    \
        const QStringList a_ = (actual);                                                                               \
        const QStringList e_ = (expected);                                                                             \
        if (a_ != e_) {                                                                                                \
            ++g_failed;                                                                                                \
            std::printf("FAIL [%s] %s:%d: %s\n    got:      [%s]\n    expected: [%s]\n", g_case, __FILE__, __LINE__,    \
                        #actual, qPrintable(a_.join(QStringLiteral(" | "))), qPrintable(e_.join(QStringLiteral(" | ")))); \
        }                                                                                                              \
    } while (0)

// ---- the anchor files ---------------------------------------------------------------------------------------------

struct PfTableDef {
    QStringList addrs;
    bool hasList = false; // "{ ... }" given (an empty list clears the table on load)
    bool persist = false;
};

struct PfFile {
    QStringList rules;
    QMap<QString, PfTableDef> tables;
    bool exists = false;
};

static QString g_pfDir;

static QStringList splitItems(const QString &list)
{
    QStringList out;
    for (QString item : list.split(QRegularExpression(QStringLiteral("[,\\s]+")), Qt::SkipEmptyParts))
        out << item;
    return out;
}

// The subset of pf.conf the bundled files use: comments, backslash continuations, macros, tables (persist,
// const, an address list), "set" options (not rules), everything else a rule with $macros expanded.
static PfFile parsePf(const QString &text)
{
    PfFile f;
    f.exists = true;
    QStringList logical;
    QString cur;
    for (QString line : text.split(QLatin1Char('\n'))) {
        const int hash = line.indexOf(QLatin1Char('#'));
        if (hash >= 0)
            line = line.left(hash);
        line = line.trimmed();
        if (line.endsWith(QLatin1Char('\\'))) {
            cur += line.left(line.size() - 1) + QLatin1Char(' ');
            continue;
        }
        cur += line;
        if (!cur.trimmed().isEmpty())
            logical << cur.simplified();
        cur.clear();
    }
    QMap<QString, QString> macros;
    static const QRegularExpression macroRe(QStringLiteral("^([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(?:\"(.*)\"|(\\S+))$"));
    static const QRegularExpression tableRe(
        QStringLiteral("^table <([^>]+)>((?:\\s+(?:persist|const))*)\\s*(?:\\{(.*)\\})?$"));
    for (QString line : logical) {
        const auto m = macroRe.match(line);
        if (m.hasMatch()) {
            macros.insert(m.captured(1), (m.captured(2).isEmpty() ? m.captured(3) : m.captured(2)).simplified());
            continue;
        }
        const auto t = tableRe.match(line);
        if (t.hasMatch()) {
            PfTableDef d;
            d.persist = t.captured(2).contains(QLatin1String("persist"));
            d.hasList = t.capturedStart(3) >= 0;
            d.addrs = splitItems(t.captured(3));
            f.tables.insert(t.captured(1), d);
            continue;
        }
        if (line.startsWith(QLatin1String("set ")))
            continue;
        for (auto it = macros.cbegin(); it != macros.cend(); ++it)
            line.replace(QLatin1Char('$') + it.key(), it.value());
        f.rules << line.simplified();
    }
    return f;
}

static PfFile readPfFile(const QString &basename)
{
    QFile file(QDir(g_pfDir).filePath(basename));
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return {};
    return parsePf(QString::fromUtf8(file.readAll()));
}

static QStringList fileRules(const QString &anchor)
{
    return readPfFile(QStringLiteral("tribe.%1.conf").arg(anchor)).rules;
}

// ---- the kernel model ---------------------------------------------------------------------------------------------

static QStringList g_unmodelled; // over every case: a command the model does not know fails the check
static int g_commands = 0;
static bool g_installedOnce = false;

struct Table {
    QStringList addrs;
    bool persist = false;
};

struct Anchor {
    QStringList rules;
    QMap<QString, Table> tables;
    bool empty() const { return rules.isEmpty() && tables.isEmpty(); }
    bool referenced(const QString &table) const
    {
        for (const QString &r : rules) {
            if (r.contains(QLatin1Char('<') + table + QLatin1Char('>')))
                return true;
        }
        return false;
    }
    // pf.conf(5): a table without persist goes when the last rule referring to it is flushed.
    void collect()
    {
        for (auto it = tables.begin(); it != tables.end();) {
            if (!it.value().persist && !referenced(it.key()))
                it = tables.erase(it);
            else
                ++it;
        }
    }
};

struct Kernel {
    bool mainRefsTribe = false; // the main ruleset evaluates "tribe" (anchor "tribe/*" / anchor "tribe")
    bool tokenHeld = false;     // our pf enable reference (pf.token)
    QMap<QString, Anchor> anchors; // "tribe" and "tribe/<sub>"

    void clear(const QString &path) { anchors.remove(path); }
    void settle(const QString &path)
    {
        if (!anchors.contains(path))
            return;
        anchors[path].collect();
        if (anchors[path].empty())
            anchors.remove(path);
    }
    void setRules(const QString &path, const QStringList &rules)
    {
        anchors[path].rules = rules;
        settle(path);
    }
    // pfctl -a <path> -f <file>: the file's rules replace the anchor's; its tables are defined as written.
    void loadFile(const QString &path, const QString &file)
    {
        const PfFile f = readPfFile(QFileInfo(file).fileName());
        if (!f.exists) {
            g_unmodelled << QStringLiteral("missing file %1").arg(QFileInfo(file).fileName());
            return;
        }
        Anchor &a = anchors[path];
        a.rules = f.rules;
        for (auto it = f.tables.cbegin(); it != f.tables.cend(); ++it) {
            Table &t = a.tables[it.key()];
            t.persist = it.value().persist;
            if (it.value().hasList)
                t.addrs = it.value().addrs;
        }
        settle(path);
    }
};

static Kernel g_k;

// Round mac-D3: while a transition runs under the app's lease on the intent, every single pf command must leave the
// block in force (our pf enabled, the main ruleset evaluating "tribe", 100.blockAll loaded); a command after which it
// is not is a moment the Mac could send the person's traffic outside any tunnel.
static bool g_watchBlock = false;
static QStringList g_blockGaps;
static bool blockInForce()
{
    return g_k.tokenHeld && g_k.mainRefsTribe && !g_k.anchors.value(QStringLiteral("tribe/100.blockAll")).rules.isEmpty();
}
static int modelImpl(const QString &command);
static int model(const QString &command)
{
    const int rc = modelImpl(command);
    if (g_watchBlock && !blockInForce())
        g_blockGaps << command.left(90);
    return rc;
}
static int modelImpl(const QString &command)
{
    ++g_commands;
    static const QString A = QStringLiteral("'tribe/([^']+)'");
    static const QRegularExpression enableRe(QStringLiteral(
        "^if pfctl -q -a %1 -s rules 2> /dev/null \\| grep -q \\. ; then echo '[^']*' ; else echo '[^']*' ; "
        "pfctl -q -a 'tribe/\\1' -F all -f '([^']+)' ; fi$").arg(A));
    static const QRegularExpression disableRe(QStringLiteral(
        "^if ! pfctl -q -a %1 -s rules 2> /dev/null \\| grep -q \\. ; then echo '[^']*' ; else echo '[^']*' ; "
        "pfctl -q -a 'tribe/\\1' -F all ; fi$").arg(A));
    static const QRegularExpression hasRulesRe(QStringLiteral("^pfctl -q -a %1 -s rules 2> /dev/null \\| grep -q \\.$").arg(A));
    static const QRegularExpression replaceRe(QStringLiteral("^pfctl -q -a %1 -t '([^']+)' -T replace ?(.*)$").arg(A));
    static const QRegularExpression killRe(QStringLiteral("^pfctl -q -a %1 -t '([^']+)' -T kill$").arg(A));
    static const QRegularExpression flushRulesRe(QStringLiteral("^pfctl -q -a %1 -F rules$").arg(A));
    static const QRegularExpression loadStdinRe(QStringLiteral("^echo -e \"(.*)\" \\| pfctl -q -a %1 -f -$").arg(A),
                                                QRegularExpression::DotMatchesEverythingOption);
    static const QRegularExpression reloadRe(QStringLiteral("^pfctl -q -a %1 -f '([^']+)'$").arg(A));
    static const QRegularExpression flushAllRe(QStringLiteral("^pfctl -q -a %1 -F all 2> /dev/null$").arg(A));
    static const QRegularExpression rootLoadRe(QStringLiteral(
        "^\\( pfctl -sr \\| grep -v 'tribe/\\*'; echo 'anchor \"tribe/\\*\"'; echo 'load anchor \"tribe\" from \"([^\"]+)\"';  \\) \\| pfctl -R -f -$"));

    QRegularExpressionMatch m;
    auto sub = [](const QRegularExpressionMatch &mm) { return QStringLiteral("tribe/") + mm.captured(1); };

    if ((m = enableRe.match(command)).hasMatch()) {
        if (!g_k.anchors.value(sub(m)).rules.isEmpty())
            return 0;
        g_k.clear(sub(m)); // -F all
        g_k.loadFile(sub(m), m.captured(2));
        return 0;
    }
    if ((m = disableRe.match(command)).hasMatch()) {
        if (!g_k.anchors.value(sub(m)).rules.isEmpty())
            g_k.clear(sub(m));
        return 0;
    }
    if ((m = hasRulesRe.match(command)).hasMatch())
        return g_k.anchors.value(sub(m)).rules.isEmpty() ? 1 : 0;
    if ((m = replaceRe.match(command)).hasMatch()) {
        Anchor &a = g_k.anchors[sub(m)];
        if (!a.tables.contains(m.captured(2)))
            a.tables[m.captured(2)].persist = true; // "Automatically create a nonexisting table" - persistent
        a.tables[m.captured(2)].addrs = splitItems(m.captured(3));
        return 0;
    }
    if ((m = killRe.match(command)).hasMatch()) {
        if (g_k.anchors.contains(sub(m))) {
            g_k.anchors[sub(m)].tables.remove(m.captured(2));
            g_k.settle(sub(m));
        }
        return 0;
    }
    if ((m = flushRulesRe.match(command)).hasMatch()) {
        if (g_k.anchors.contains(sub(m)))
            g_k.setRules(sub(m), {});
        return 0;
    }
    if ((m = loadStdinRe.match(command)).hasMatch()) {
        // pfctl -a <path> -f -: like a file - the rules replace the anchor's, a table is defined as written
        const PfFile f = parsePf(m.captured(1));
        const QString path = QStringLiteral("tribe/") + m.captured(2);
        Anchor &a = g_k.anchors[path];
        a.rules = f.rules;
        for (auto it = f.tables.cbegin(); it != f.tables.cend(); ++it) {
            Table &t = a.tables[it.key()];
            t.persist = it.value().persist;
            if (it.value().hasList)
                t.addrs = it.value().addrs;
        }
        g_k.settle(path);
        return 0;
    }
    if ((m = reloadRe.match(command)).hasMatch()) {
        g_k.loadFile(sub(m), m.captured(2));
        return 0;
    }
    if (command.contains(QLatin1String(" -F all 2> /dev/null"))) {
        for (const QString &part : command.split(QStringLiteral(" ; "))) {
            if ((m = flushAllRe.match(part)).hasMatch())
                g_k.clear(sub(m));
            else
                g_unmodelled << part;
        }
        return 0;
    }
    if ((m = rootLoadRe.match(command)).hasMatch()) {
        g_k.mainRefsTribe = true;
        g_k.setRules(QStringLiteral("tribe"), readPfFile(QFileInfo(m.captured(1)).fileName()).rules);
        g_installedOnce = true;
        return 0;
    }
    if (command.endsWith(QLatin1String(") | pfctl -N -f -")) && command.startsWith(QLatin1String("( pfctl -sn | grep -v 'tribe/*';")))
        return 0; // our nat anchors: nothing of ours lives there
    if (command.startsWith(QLatin1String("if grep -Fq 'tribe' /etc/pf.conf ; then ")))
        return 0; // the legacy hard-coded anchor in /etc/pf.conf: none in the model
    if (command == QLatin1String("pfctl -q -a 'tribe' -F all")) {
        g_k.clear(QStringLiteral("tribe"));
        return 0;
    }
    if (command.startsWith(QLatin1String("test -f '")) && command.contains(QLatin1String("/pf.token' && pfctl -X `cat '"))) {
        const bool held = g_k.tokenHeld;
        g_k.tokenHeld = false;
        return held ? 0 : 1;
    }
    if (command == QLatin1String("test -f /etc/pf.conf && pfctl -F all -f /etc/pf.conf")) {
        g_k.mainRefsTribe = false; // the system ruleset has no tribe reference
        return 0;
    }
    if (command.startsWith(QLatin1String("mkdir -p '")) && command.contains(QLatin1String(" ; pfctl -E 2>&1 | grep -F 'Token : ' | cut -c9- > '"))) {
        g_k.tokenHeld = true;
        return 0;
    }
    if (command.startsWith(QLatin1String("test -s '")) && command.contains(QLatin1String("/pf.token' && pfctl -s References | grep -qFf '")))
        return g_k.tokenHeld ? 0 : 1;
    if (command == QLatin1String("pfctl -sr | grep -q 'tribe' && pfctl -q -a 'tribe' -s rules 2> /dev/null | grep -q ."))
        return (g_k.mainRefsTribe && !g_k.anchors.value(QStringLiteral("tribe")).rules.isEmpty()) ? 0 : 1;
    if (command.startsWith(QLatin1String("if ! pfctl -sr | tail -1 | grep -qF 'tribe'; then "))) {
        g_k.mainRefsTribe = true; // re-adds anchor "tribe" last
        return 0;
    }
    g_unmodelled << command;
    return 127;
}

// ---- helpers ------------------------------------------------------------------------------------------------------

static QStringList rulesOf(const QString &anchor) { return g_k.anchors.value(QStringLiteral("tribe/") + anchor).rules; }
static QStringList tableOf(const QString &anchor, const QString &table)
{
    return g_k.anchors.value(QStringLiteral("tribe/") + anchor).tables.value(table).addrs;
}
static bool hasTable(const QString &anchor, const QString &table)
{
    return g_k.anchors.value(QStringLiteral("tribe/") + anchor).tables.contains(table);
}
static QStringList nonEmptyAnchors()
{
    QStringList out;
    for (auto it = g_k.anchors.cbegin(); it != g_k.anchors.cend(); ++it) {
        if (!it.value().empty())
            out << it.key();
    }
    return out;
}
static QStringList pass(const QString &ifname) { return { QStringLiteral("pass out on %1 flags any no state").arg(ifname) }; }
// 310.blockDNS of a session with its own tun (round mac-C, review N1): DNS to its resolvers only through that tun.
static QStringList dnsRules(const QString &ifname)
{
    return { QStringLiteral("block return out proto { tcp, udp } to port 53 flags any no state"),
             QStringLiteral("pass out on %1 proto { tcp, udp } to <dnsaddr> port 53 flags any no state").arg(ifname) };
}

// Documentation addresses only (RFC 5737).
static const QString kAwgPeer = QStringLiteral("192.0.2.10");
static const QString kAwgDns = QStringLiteral("198.51.100.53");
static const QString kXrayServer = QStringLiteral("203.0.113.20");
static const QString kXrayDns1 = QStringLiteral("198.51.100.1");
static const QString kXrayDns2 = QStringLiteral("198.51.100.2");

// ---- the service's entry points -----------------------------------------------------------------------------------

static KillSwitch *ks() { return KillSwitch::instance(); }

// A new service process: LocalServer creates the kill switch and runs init().
static void serviceStart()
{
    delete s_instance;
    s_instance = nullptr;
    ks()->init();
}
static void reboot()
{
    g_k = Kernel();
    serviceStart();
}
static void setStrict(bool on) { ks()->refresh(on); } // IpcServer::refreshKillSwitch

// IpcServer::createTun after a successful Router::createTun / IpcServer::deleteTun, as each commit wires them.
static void ipcCreateTun(const QString &dev)
{
#ifdef PF_CHECK_API_57F10A133
    ks()->setTunnelInterface(dev);
#else
    ks()->tunnelCreated(dev);
#endif
}
static void ipcDeleteTun(const QString &dev)
{
#ifdef PF_CHECK_API_57F10A133
    ks()->clearTunnelInterface(dev);
#else
    (void)dev; // IpcServer::deleteTun does not touch the kill switch (checked by the wiring check)
#endif
}

// WireguardUtilsMacos::addInterface (full tunnel, the peer excluded) -> applyFirewallRules.
static void awgStart(const QString &utun)
{
    FirewallParams p {};
    p.dnsServers = { kAwgDns };
    p.blockAll = true;
    p.allowNets = true;
    p.allowAddrs = { kAwgPeer };
    p.allowPIA = false;
#ifdef PF_CHECK_API_57F10A133
    MacOSFirewall::applySessionRules(p, utun);
#else
    ks()->openTunnelSession(p, utun);
#endif
}
static void awgStop() { ks()->disableKillSwitch(); } // WireguardUtilsMacos::deleteInterface

// XrayProtocol::setupRouting (splitTunnelType 0: blockAll + the server; dns1, dns2); createTun first.
static QJsonObject xrayConfig()
{
    QJsonObject c;
    c.insert(QStringLiteral("splitTunnelType"), 0);
    c.insert(QStringLiteral("vpnServer"), kXrayServer);
    c.insert(QStringLiteral("dns1"), kXrayDns1);
    c.insert(QStringLiteral("dns2"), kXrayDns2);
    return c;
}
static void xrayStart(const QString &tun)
{
    ipcCreateTun(tun);
    CHECK(ks()->enableKillSwitch(xrayConfig(), 0));
}
static void xrayStop(const QString &tun) // XrayProtocol::stop: disableKillSwitch ... deleteTun
{
    ks()->disableKillSwitch();
    ipcDeleteTun(tun);
}
static void openVpnStart() { CHECK(ks()->enableKillSwitch(xrayConfig(), 0)); } // no createTun: tun unknown

static void checkAllGone()
{
    CHECK_EQ(nonEmptyAnchors(), QStringList());
    CHECK(!g_k.tokenHeld);
    CHECK(!g_k.mainRefsTribe);
}

static void checkXray(const QString &tun)
{
    CHECK_EQ(rulesOf(QStringLiteral("200.allowVPN")), pass(tun));
    CHECK_EQ(rulesOf(QStringLiteral("100.blockAll")), fileRules(QStringLiteral("100.blockAll")));
    CHECK_EQ(rulesOf(QStringLiteral("400.allowPIA")), fileRules(QStringLiteral("400.allowPIA")));
    CHECK_EQ(tableOf(QStringLiteral("110.allowNets"), QStringLiteral("allownets")), QStringList { kXrayServer });
    CHECK_EQ(tableOf(QStringLiteral("310.blockDNS"), QStringLiteral("dnsaddr")), (QStringList { kXrayDns1, kXrayDns2 }));
    CHECK_EQ(rulesOf(QStringLiteral("310.blockDNS")), dnsRules(tun)); // N1: never a pass on the physical interface
    CHECK(g_k.tokenHeld && g_k.mainRefsTribe);
}

static void checkAwg(const QString &utun)
{
    CHECK_EQ(rulesOf(QStringLiteral("200.allowVPN")), pass(utun));
    CHECK_EQ(rulesOf(QStringLiteral("100.blockAll")), fileRules(QStringLiteral("100.blockAll")));
    CHECK_EQ(rulesOf(QStringLiteral("400.allowPIA")), QStringList());
    CHECK_EQ(tableOf(QStringLiteral("110.allowNets"), QStringLiteral("allownets")), QStringList { kAwgPeer });
    CHECK_EQ(tableOf(QStringLiteral("310.blockDNS"), QStringLiteral("dnsaddr")), QStringList { kAwgDns });
    CHECK_EQ(rulesOf(QStringLiteral("310.blockDNS")), dnsRules(utun)); // N1: never a pass on the physical interface
    CHECK(!hasTable(QStringLiteral("120.blockNets"), QStringLiteral("blocknets")));
    CHECK(g_k.tokenHeld && g_k.mainRefsTribe);
}

// Only the strict block, from the current files (and the scan's anchor when a scan armed it).
static void checkStrictBlockOnly(bool scanArmed)
{
    QStringList expected;
    for (const QString &a : avpn::pf::strictBlockList()) {
        expected << QStringLiteral("tribe/") + a;
        CHECK_EQ(rulesOf(a), fileRules(a));
    }
    if (scanArmed)
        expected << QStringLiteral("tribe/160.allowScan");
    expected << QStringLiteral("tribe");
    expected.sort();
    CHECK_EQ(nonEmptyAnchors(), expected);
    CHECK(g_k.tokenHeld && g_k.mainRefsTribe);
}

// A previous process / an older build: pf state with session content everywhere.
static void plantStale(bool pfOurs)
{
    g_k = Kernel();
    g_k.mainRefsTribe = pfOurs;
    g_k.tokenHeld = pfOurs;
    if (pfOurs)
        g_k.anchors[QStringLiteral("tribe")].rules = readPfFile(QStringLiteral("tribe.conf")).rules;
    auto put = [](const QString &a, const QStringList &rules) { g_k.anchors[QStringLiteral("tribe/") + a].rules = rules; };
    put(QStringLiteral("000.allowLoopback"), fileRules(QStringLiteral("000.allowLoopback")));
    put(QStringLiteral("100.blockAll"), { QStringLiteral("block out all flags any no state # older build") });
    put(QStringLiteral("110.allowNets"), fileRules(QStringLiteral("110.allowNets")));
    g_k.anchors[QStringLiteral("tribe/110.allowNets")].tables[QStringLiteral("allownets")].addrs = { kAwgPeer };
    put(QStringLiteral("160.allowScan"), { QStringLiteral("pass out quick on en0 proto { tcp, udp } group { tribevpn } flags any no state") });
    put(QStringLiteral("200.allowVPN"), pass(QStringLiteral("utun4")));
    put(QStringLiteral("310.blockDNS"), fileRules(QStringLiteral("310.blockDNS")));
    g_k.anchors[QStringLiteral("tribe/310.blockDNS")].tables[QStringLiteral("dnsaddr")].addrs = { kAwgDns };
    // a Debug build's identity (CMakeLists.txt AMN_PF_RULE_IDENTITY)
    put(QStringLiteral("400.allowPIA"), { QStringLiteral("pass out proto { tcp, udp } user { root } flags any no state") });
    put(QStringLiteral("999.quarantine"), { QStringLiteral("block drop quick all flags any no state") });
}

// The kill switch's qDebug diagnostics: only with PF_CHECK_VERBOSE=1.
static void quietMessages(QtMsgType type, const QMessageLogContext &, const QString &msg)
{
    if (type != QtDebugMsg || qEnvironmentVariableIsSet("PF_CHECK_VERBOSE"))
        std::fprintf(stderr, "  [qt] %s\n", qPrintable(msg));
}

int main(int argc, char **argv)
{
    // The seam first: no MacOSFirewall call may reach /bin/bash.
    MacOSFirewall::setCommandRunner(&model);
    qInstallMessageHandler(&quietMessages);
    QCoreApplication app(argc, argv); // ResourceDir = applicationDirPath() + "/pf": the model reads the real files
    if (argc < 2) {
        std::printf("usage: mac_pf_session_check <deploy/data/macos/pf>\n");
        return 2;
    }
    g_pfDir = QString::fromLocal8Bit(argv[1]);
    if (!QFileInfo(QDir(g_pfDir).filePath(QStringLiteral("tribe.conf"))).isFile()) {
        std::printf("no tribe.conf in %s\n", argv[1]);
        return 2;
    }
    const QString tA = QStringLiteral("utun4"), tB = QStringLiteral("utun5"), xray = QStringLiteral("utun22");
    reboot();
    setStrict(false);

    g_case = "P1 reboot -> AWG";
    reboot();
    awgStart(tA);
    checkAwg(tA);

    g_case = "P2 AWG -> stop";
    awgStop();
    checkAllGone();

    g_case = "P3 AWG -> stop -> Xray";
    reboot();
    awgStart(tA);
    awgStop();
    xrayStart(xray);
    checkXray(xray);
    g_case = "P3 ... -> Xray stop";
    xrayStop(xray);
    checkAllGone();

    g_case = "P4 Xray -> stop -> AWG";
    reboot();
    xrayStart(xray);
    xrayStop(xray);
    awgStart(tB);
    checkAwg(tB);

    g_case = "P5 AWG(utunA) -> stop -> AWG(utunB)";
    reboot();
    awgStart(tA);
    awgStop();
    awgStart(tB);
    checkAwg(tB);
    g_case = "P5 AWG(utunA) -> AWG(utunB) over a live pf";
    reboot();
    awgStart(tA);
    awgStart(tB);
    checkAwg(tB);

    g_case = "P6 Xray -> client lost (no stop, no deleteTun) -> AWG";
    reboot();
    xrayStart(xray);
    awgStart(tB);
    checkAwg(tB);
    g_case = "P6 AWG -> client lost -> Xray";
    reboot();
    awgStart(tA);
    xrayStart(xray);
    checkXray(xray);

    g_case = "P7 OpenVPN (no createTun) after AWG";
    reboot();
    awgStart(tA);
    awgStop();
    openVpnStart();
    CHECK_EQ(rulesOf(QStringLiteral("200.allowVPN")), fileRules(QStringLiteral("200.allowVPN")));
    CHECK(fileRules(QStringLiteral("200.allowVPN")).size() == 1
          && fileRules(QStringLiteral("200.allowVPN")).first().startsWith(QLatin1String("pass out on { utun0, utun1,")));
    g_case = "P7 Xray -> client lost (no stop, no deleteTun) -> OpenVPN";
    reboot();
    xrayStart(xray);
    openVpnStart(); // the lost session's tun is not this session's
    CHECK_EQ(rulesOf(QStringLiteral("200.allowVPN")), fileRules(QStringLiteral("200.allowVPN")));
    g_case = "P7 a createTun of a non-tun name";
    reboot();
    xrayStart(QStringLiteral("en0")); // never a pass on the uplink
    CHECK_EQ(rulesOf(QStringLiteral("200.allowVPN")), fileRules(QStringLiteral("200.allowVPN")));
    CHECK_EQ(rulesOf(QStringLiteral("310.blockDNS")), fileRules(QStringLiteral("310.blockDNS")));

    g_case = "P20 DNS passes only through a tunnel (round mac-C, review N1)";
    {
        const QStringList file = fileRules(QStringLiteral("310.blockDNS"));
        bool passOnTunsOnly = false;
        for (const QString &r : file) {
            if (!r.startsWith(QLatin1String("pass")))
                continue;
            passOnTunsOnly = r.startsWith(QLatin1String("pass out on { utun0, utun1,")) && !r.contains(QLatin1String("en0"));
            CHECK(passOnTunsOnly); // the static file: every pass names the tunnels, never "any interface"
        }
        CHECK(passOnTunsOnly);
        CHECK(avpn::pf::dnsSessionRules(QStringLiteral("utun4")).size() == 3);
        for (const char *bad : { "", "en0", "utun", "bridge0", "utun4; pfctl -d" })
            CHECK(avpn::pf::dnsSessionRules(QString::fromLatin1(bad)).isEmpty());
        reboot();
        awgStart(tA);
        awgStop();
        xrayStart(xray); // the next session's DNS pass is its own tun, not the earlier one's
        CHECK_EQ(rulesOf(QStringLiteral("310.blockDNS")), dnsRules(xray));
        openVpnStart(); // a later session without a tun of its own: the static file again
        CHECK_EQ(rulesOf(QStringLiteral("310.blockDNS")), file);
        CHECK_EQ(tableOf(QStringLiteral("310.blockDNS"), QStringLiteral("dnsaddr")), (QStringList { kXrayDns1, kXrayDns2 }));
    }

    g_case = "P8 strict, no session: AWG -> strict stop";
    reboot();
    setStrict(true);
    checkStrictBlockOnly(false);
    awgStart(tA);
    checkAwg(tA);
    awgStop();
    checkStrictBlockOnly(false);
    g_case = "P8 strict: Xray -> strict stop -> AWG -> strict stop -> Xray";
    xrayStart(xray);
    checkXray(xray);
    xrayStop(xray);
    checkStrictBlockOnly(false);
    awgStart(tA);
    awgStop();
    xrayStart(xray);
    checkXray(xray);
    xrayStop(xray);
    g_case = "P8 strict: the service start with pf not installed installs the block";
    reboot();
    checkStrictBlockOnly(false);
    setStrict(false);
    checkAllGone();

    g_case = "P9 strict keeps the scan's anchor";
    reboot();
    setStrict(true);
    xrayStart(xray);
    CHECK(MacOSFirewall::setScanExemption(QStringLiteral("en0")) == 1);
    xrayStop(xray);
    checkStrictBlockOnly(true);
    CHECK_EQ(rulesOf(QStringLiteral("160.allowScan")), MacOSFirewall::scanExemptionRules(QStringLiteral("en0")));
    MacOSFirewall::clearScanExemption(); // the probe host, at the end of its scan
    checkStrictBlockOnly(false);
    setStrict(false);
    g_case = "P9 a full stop flushes the scan's anchor";
    reboot();
    awgStart(tA);
    CHECK(MacOSFirewall::setScanExemption(QStringLiteral("en0")) == 1);
    awgStop();
    checkAllGone();

    g_case = "P10 service start: previous process died with pf installed";
    plantStale(true);
    CHECK(MacOSFirewall::isInstalled());
    serviceStart();
    checkAllGone();
    xrayStart(xray);
    checkXray(xray);
    CHECK_EQ(rulesOf(QStringLiteral("999.quarantine")), QStringList());

    g_case = "P11 a session after an older build's root-only stop";
    reboot();
    plantStale(false);
    CHECK(!MacOSFirewall::isInstalled());
    xrayStart(xray); // install() starts from a clean state
    checkXray(xray);
    CHECK_EQ(rulesOf(QStringLiteral("999.quarantine")), QStringList());
    CHECK_EQ(rulesOf(QStringLiteral("160.allowScan")), QStringList());
    g_case = "P11 ... and the same for AWG";
    xrayStop(xray);
    plantStale(false);
    awgStart(tB);
    checkAwg(tB);

    g_case = "P12 service start with strict on, stale anchors";
    setStrict(true);
    plantStale(true);
    serviceStart(); // KillSwitch::init -> disableAllTraffic, no session in a new process
    // The kill switch never writes the scan's anchor (it is the probe host's, which clears a dead process's
    // copy itself - not covered here); everything else is only the block, from the current files.
    checkStrictBlockOnly(true);
    setStrict(false);

    g_case = "P13 enableAnchor and the kernel copy";
    reboot();
    awgStart(tA);
    MacOSFirewall::enableAnchor(QStringLiteral("200.allowVPN"));
    CHECK_EQ(rulesOf(QStringLiteral("200.allowVPN")), fileRules(QStringLiteral("200.allowVPN")));
    g_k.anchors[QStringLiteral("tribe/100.blockAll")].rules = { QStringLiteral("block out all flags any no state # kernel copy") };
    MacOSFirewall::enableAnchor(QStringLiteral("100.blockAll")); // static: load-if-empty keeps it (stops flush it)
    CHECK_EQ(rulesOf(QStringLiteral("100.blockAll")), QStringList { QStringLiteral("block out all flags any no state # kernel copy") });
    MacOSFirewall::enableAnchor(QStringLiteral("160.allowScan"));
    CHECK_EQ(rulesOf(QStringLiteral("160.allowScan")), QStringList());
    MacOSFirewall::enableAnchor(QStringLiteral("unknown.anchor")); // unknown: never kept, its file is missing
    CHECK(g_unmodelled.contains(QStringLiteral("missing file tribe.unknown.anchor.conf")));
    g_unmodelled.removeAll(QStringLiteral("missing file tribe.unknown.anchor.conf"));

    g_case = "P14 tunnel interface names";
    for (const char *ok : { "utun0", "utun4", "utun22", "utun999" })
        CHECK(avpn::pf::tunnelPassRules(QString::fromLatin1(ok)) == pass(QString::fromLatin1(ok)));
    for (const char *bad : { "", "utun", "en0", "utun1234", "utun2 ", " utun2", "utun2;x", "UTUN2", "utun-1", "utun2'", "bridge0" })
        CHECK(avpn::pf::tunnelPassRules(QString::fromLatin1(bad)).isEmpty());

    g_case = "P15 the ownership table";
    {
        QStringList declared;
        for (const QString &rule : readPfFile(QStringLiteral("tribe.conf")).rules) {
            static const QRegularExpression anchorRe(QStringLiteral("^anchor \"([^\"]+)\"$"));
            const auto mm = anchorRe.match(rule);
            CHECK(mm.hasMatch());
            declared << mm.captured(1);
        }
        QStringList live, retired;
        for (const auto &a : avpn::pf::anchors())
            (a.kind == avpn::pf::AnchorKind::Retired ? retired : live) << QString::fromLatin1(a.name);
        CHECK_EQ(live, declared); // same names, same order
        CHECK(!retired.isEmpty());
        for (const QString &r : retired)
            CHECK(!QFileInfo(QDir(g_pfDir).filePath(QStringLiteral("tribe.%1.conf").arg(r))).exists());
        for (const auto &a : avpn::pf::anchors()) {
            if (a.kind == avpn::pf::AnchorKind::Retired)
                continue;
            const PfFile f = readPfFile(QStringLiteral("tribe.%1.conf").arg(QString::fromLatin1(a.name)));
            CHECK(f.exists);
            // A table the file declares with an empty list is filled at run time: the session's table.
            bool emptyTable = false;
            for (const PfTableDef &d : f.tables)
                emptyTable = emptyTable || (d.hasList && d.addrs.isEmpty());
            CHECK(emptyTable == (a.kind == avpn::pf::AnchorKind::StaticRuleSessionTable
                                 || a.kind == avpn::pf::AnchorKind::SessionRuleSessionTable));
            for (const PfTableDef &d : f.tables)
                CHECK(!d.persist); // every bundled table lives only while its rule does (P19)
            if (f.rules.isEmpty())
                CHECK(a.kind == avpn::pf::AnchorKind::ScanRule || a.kind == avpn::pf::AnchorKind::Unused);
        }
        CHECK(avpn::pf::stopFlushList().size() == avpn::pf::anchors().size());
        CHECK(!avpn::pf::strictFlushList().contains(QStringLiteral("160.allowScan")));
        CHECK(avpn::pf::strictFlushList().contains(QStringLiteral("200.allowVPN")));
        CHECK_EQ(avpn::pf::strictBlockList(), (QStringList { QStringLiteral("000.allowLoopback"), QStringLiteral("100.blockAll"),
                                                              QStringLiteral("250.blockIPv6") }));
    }

    g_case = "P16 late deleteTun of an older session";
    reboot();
    xrayStart(xray);
    ks()->disableKillSwitch(); // session 1 stops; its deleteTun comes late
    ipcCreateTun(xray);        // session 2 brings up the same device
    ipcDeleteTun(xray);        // session 1's late deleteTun
    CHECK(ks()->enableKillSwitch(xrayConfig(), 0));
    checkXray(xray);

    g_case = "P17 a createTun no session takes: dropped by the next session opened";
    reboot();
    ipcCreateTun(QStringLiteral("utun9"));
    awgStart(tA); // AmneziaWG opens with its own utun: the created one is not its
    checkAwg(tA);
    openVpnStart(); // its client lost (no stop): the next session never gets the dropped tun
    CHECK_EQ(rulesOf(QStringLiteral("200.allowVPN")), fileRules(QStringLiteral("200.allowVPN")));
    g_case = "P17 ... dropped by a stop";
    reboot();
    ipcCreateTun(QStringLiteral("utun9"));
    ks()->disableKillSwitch();
    openVpnStart();
    CHECK_EQ(rulesOf(QStringLiteral("200.allowVPN")), fileRules(QStringLiteral("200.allowVPN")));
    g_case = "P17 ... a createTun inside an open session changes neither it nor the next one";
    reboot();
    xrayStart(xray);
    ipcCreateTun(QStringLiteral("utun9"));
    checkXray(xray);
    xrayStop(xray);
    openVpnStart();
    CHECK_EQ(rulesOf(QStringLiteral("200.allowVPN")), fileRules(QStringLiteral("200.allowVPN")));

    g_case = "P18 strict on over a live Xray session";
    reboot();
    xrayStart(xray);
    setStrict(true);
    checkXray(xray); // its pass, its tables, its 400 stay
    CHECK_EQ(rulesOf(QStringLiteral("000.allowLoopback")), fileRules(QStringLiteral("000.allowLoopback")));
    CHECK_EQ(rulesOf(QStringLiteral("250.blockIPv6")), fileRules(QStringLiteral("250.blockIPv6")));
    xrayStop(xray);
    checkStrictBlockOnly(false); // the block outlives the session
    setStrict(false);
    checkAllGone();
    g_case = "P18 strict on over a live AWG session";
    reboot();
    awgStart(tA);
    setStrict(true);
    checkAwg(tA);
    awgStop();
    checkStrictBlockOnly(false);
    g_case = "P18 strict off over a live session: no pf of ours (the client sends it for kill switch off too)";
    awgStart(tA);
    setStrict(false);
    checkAllGone();
    setStrict(true); // no session any more: the block alone
    checkStrictBlockOnly(false);
    setStrict(false);
    g_case = "P18 strict on over a live session whose pf another program flushed";
    reboot();
    xrayStart(xray);
    g_k.mainRefsTribe = false; // e.g. another VPN reloaded /etc/pf.conf
    const QMap<QString, Anchor> before = g_k.anchors;
    setStrict(true);
    CHECK(g_k.anchors.keys() == before.keys());
    CHECK_EQ(rulesOf(QStringLiteral("200.allowVPN")), pass(xray)); // not flushed by an install
    xrayStop(xray);
    checkStrictBlockOnly(false);
    setStrict(false);

    g_case = "P19 the table model (pf.conf(5) TABLES, pfctl(8) -T)";
    {
        reboot();
        const QString dir = QCoreApplication::applicationDirPath() + QStringLiteral("/pf");
        model(QStringLiteral("pfctl -q -a 'tribe/110.allowNets' -f '%1/tribe.110.allowNets.conf'").arg(dir));
        CHECK(hasTable(QStringLiteral("110.allowNets"), QStringLiteral("allownets")));
        CHECK(!g_k.anchors.value(QStringLiteral("tribe/110.allowNets")).tables.value(QStringLiteral("allownets")).persist);
        model(QStringLiteral("pfctl -q -a 'tribe/110.allowNets' -t 'allownets' -T replace %1").arg(kAwgPeer));
        CHECK_EQ(tableOf(QStringLiteral("110.allowNets"), QStringLiteral("allownets")), QStringList { kAwgPeer });
        model(QStringLiteral("pfctl -q -a 'tribe/110.allowNets' -F rules")); // the last rule referring to it
        CHECK(!hasTable(QStringLiteral("110.allowNets"), QStringLiteral("allownets")));
        model(QStringLiteral("pfctl -q -a 'tribe/110.allowNets' -t 'allownets' -T replace %1").arg(kAwgPeer));
        CHECK(g_k.anchors.value(QStringLiteral("tribe/110.allowNets")).tables.value(QStringLiteral("allownets")).persist);
        model(QStringLiteral("pfctl -q -a 'tribe/110.allowNets' -F rules")); // persistent: stays
        CHECK_EQ(tableOf(QStringLiteral("110.allowNets"), QStringLiteral("allownets")), QStringList { kAwgPeer });
        model(QStringLiteral("pfctl -q -a 'tribe/110.allowNets' -f '%1/tribe.110.allowNets.conf'").arg(dir));
        CHECK_EQ(tableOf(QStringLiteral("110.allowNets"), QStringLiteral("allownets")), QStringList()); // "{ }" clears
        CHECK(hasTable(QStringLiteral("110.allowNets"), QStringLiteral("allownets")));
        model(QStringLiteral("pfctl -q -a 'tribe/110.allowNets' -F all 2> /dev/null"));
        CHECK(!hasTable(QStringLiteral("110.allowNets"), QStringLiteral("allownets")));
        model(QStringLiteral("pfctl -q -a 'tribe/300.allowLAN' -f '%1/tribe.300.allowLAN.conf'").arg(dir));
        CHECK(tableOf(QStringLiteral("300.allowLAN"), QStringLiteral("lanips")).contains(QStringLiteral("192.168.0.0/16")));
        model(QStringLiteral("pfctl -q -a 'tribe/300.allowLAN' -t 'lanips' -T kill"));
        CHECK(!hasTable(QStringLiteral("300.allowLAN"), QStringLiteral("lanips")));
        // A session's tables after a session with the kill switch off for blockNets: never left behind.
        reboot();
        awgStart(tA);
        CHECK(!hasTable(QStringLiteral("120.blockNets"), QStringLiteral("blocknets")));
        awgStop();
    }

    // ---- round mac-D3: the block across the app's own transitions (KillSwitch::setHold) -------------------------
    {
        // Round mac-D4: the wall clock (persisted deadline) and the monotonic one (the running lease) move apart only
        // in H18/H19; every other step moves both.
        static qint64 wallMs = 1'700'000'000'000LL;
        static qint64 monoMs = 1'000'000;
        KillSwitch::setClocksForTest([]() { return wallMs; }, []() { return monoMs; });
        const QStringList api = { QStringLiteral("192.0.2.80"), QStringLiteral("198.51.100.80") }; // the API edges
        auto held = [&](const char *name) {
            g_case = name;
            g_blockGaps.clear();
            g_watchBlock = true;
        };
        auto endHeld = [&]() {
            g_watchBlock = false;
            CHECK_EQ(g_blockGaps, QStringList());
        };
        auto heldPass = [&](const QStringList &session) {
            QStringList p = session;
            p << api;
            CHECK_EQ(tableOf(QStringLiteral("110.allowNets"), QStringLiteral("allownets")), p);
            CHECK(blockInForce());
        };
        const QString tC = QStringLiteral("utun6"), xray2 = QStringLiteral("utun23");

        reboot();
        awgStart(tA);
        CHECK(ks()->setHold(8000, api));
        held("H1 AWG -> AWG (server switch: deactivate, activate)");
        awgStop();
        heldPass({ kAwgPeer });
        awgStart(tC);
        checkAwg(tC);
        endHeld();

        held("H2 AWG -> Xray (mode switch)");
        awgStop();
        xrayStart(xray);
        checkXray(xray);
        CHECK_EQ(rulesOf(QStringLiteral("200.allowVPN")), pass(xray)); // the AWG utun's pass is replaced, not kept
        endHeld();

        held("H3 Xray -> Xray (server switch)");
        xrayStop(xray);
        heldPass({ kXrayServer });
        xrayStart(xray2);
        checkXray(xray2);
        endHeld();

        held("H4 Xray -> AWG (mode switch)");
        xrayStop(xray2);
        awgStart(tA);
        checkAwg(tA);
        CHECK_EQ(rulesOf(QStringLiteral("400.allowPIA")), QStringList()); // the Xray session's service pass goes
        endHeld();

        held("H5 failover: AWG leg -> dead AWG leg -> Xray leg -> AWG");
        awgStop();
        awgStart(tB);
        awgStop();
        xrayStart(xray);
        xrayStop(xray);
        awgStart(tA);
        checkAwg(tA);
        endHeld();

        held("H6 a lost client mid-session (IpcServer::onProcessControllerLost) -> the app's next session");
        awgStop();
        xrayStart(xray);
        ks()->disableKillSwitch(); // the lost client's teardown
        heldPass({ kXrayServer });
        xrayStart(xray2);
        checkXray(xray2);
        endHeld();

        g_case = "H7 renewals keep it; the person's Stop (release) lifts it at once";
        wallMs += 5000; monoMs += 5000;
        CHECK(ks()->setHold(8000, api));
        wallMs += 5000; monoMs += 5000;
        ks()->holdTick();
        xrayStop(xray2);
        CHECK(blockInForce()); // 10 s after arming, renewed at 5 s: still held
        CHECK(ks()->setHold(0, {}));
        checkAllGone();

        g_case = "H8 release first, then the stop (the AWG stop travels on another channel)";
        reboot();
        CHECK(ks()->setHold(8000, api));
        awgStart(tA);
        CHECK(ks()->setHold(0, {}));
        checkAwg(tA); // a release never touches an open session
        awgStop();
        checkAllGone();

        g_case = "H9 the app dies mid-switch: no renewal -> the block ends with the lease";
        reboot();
        CHECK(ks()->setHold(8000, api));
        awgStart(tA);
        awgStop();
        CHECK(blockInForce());
        wallMs += 7000; monoMs += 7000;
        ks()->holdTick();
        CHECK(blockInForce());
        wallMs += 1001; monoMs += 1001;
        ks()->holdTick();
        checkAllGone();

        reboot();
        CHECK(ks()->setHold(8000, api));
        xrayStart(xray);
        held("H10 the service restarts mid-session inside the lease -> the block stays -> the next session");
        serviceStart(); // kill -9 + launchd: a new process, the kernel keeps the dead process's pf
        CHECK_EQ(tableOf(QStringLiteral("110.allowNets"), QStringLiteral("allownets")), api); // the dead session's pass goes
        CHECK(ks()->setHold(8000, api)); // the app's next renewal reaches the new process
        awgStart(tB);
        checkAwg(tB);
        endHeld();

        g_case = "H11 the service restarts inside the lease and no app comes back -> lifted at the lease's end";
        awgStop();
        serviceStart();
        CHECK(blockInForce());
        CHECK(ks()->holdTimerActive()); // round mac-D4: init() schedules the end itself (the tick below only stands in for it)
        wallMs += 8001; monoMs += 8001;
        ks()->holdTick();
        checkAllGone();

        g_case = "H18 the wall clock steps back 1 h after the last renewal (no app): the block still ends within the bound";
        reboot();
        CHECK(ks()->setHold(8000, api));
        awgStart(tA);
        awgStop();
        CHECK(blockInForce());
        wallMs -= 3600LL * 1000;
        monoMs += 8001;
        ks()->holdTick();
        checkAllGone();

        g_case = "H19 the wall clock steps forward 1 h: a lease the app renews keeps the block";
        reboot();
        CHECK(ks()->setHold(8000, api));
        awgStart(tA);
        awgStop();
        wallMs += 3600LL * 1000;
        monoMs += 2000;
        ks()->holdTick();
        CHECK(blockInForce());
        CHECK(ks()->setHold(8000, api)); // the app's next renewal
        monoMs += 2000;
        ks()->holdTick();
        CHECK(blockInForce());
        CHECK(ks()->setHold(0, {}));
        checkAllGone();

        g_case = "H12 a service start after the lease ended: the self-heal as before";
        reboot();
        CHECK(ks()->setHold(8000, api));
        awgStart(tA);
        wallMs += 9000; monoMs += 9000;
        serviceStart();
        checkAllGone();

        g_case = "H13 kill switch turned off (refresh(false)) clears the lease: the stop lifts the block";
        reboot();
        CHECK(ks()->setHold(8000, api));
        awgStart(tA);
        setStrict(false);
        checkAllGone(); // refresh(false) = disableKillSwitch, as before
        awgStart(tA);
        awgStop();
        checkAllGone();

        g_case = "H14 no lease (intent off / kill switch setting off): every stop lifts the block, as before";
        reboot();
        awgStart(tA);
        awgStop();
        checkAllGone();
        xrayStart(xray);
        xrayStop(xray);
        checkAllGone();

        g_case = "H15 a lease with no session ever opened arms nothing; its release changes nothing";
        reboot();
        CHECK(ks()->setHold(8000, api));
        checkAllGone();
        CHECK(ks()->setHold(0, {}));
        checkAllGone();

        g_case = "H16 strict on under a held block: the strict block; the release keeps the strict block";
        reboot();
        CHECK(ks()->setHold(8000, api));
        awgStart(tA);
        awgStop();
        setStrict(true);
        checkStrictBlockOnly(false);
        CHECK(ks()->setHold(0, {}));
        checkStrictBlockOnly(false);
        setStrict(false);
        checkAllGone();

        g_case = "H17 invalid control-plane addresses are refused";
        reboot();
        CHECK(ks()->setHold(8000, { QStringLiteral("1.2.3.4; pfctl -d"), QStringLiteral("example.com"), api.first() }));
        awgStart(tA);
        awgStop();
        CHECK_EQ(tableOf(QStringLiteral("110.allowNets"), QStringLiteral("allownets")), (QStringList { kAwgPeer, api.first() }));
        CHECK(ks()->setHold(0, {}));
        checkAllGone();
        KillSwitch::setClocksForTest(nullptr, nullptr);
    }

    g_case = "every command modelled";
    CHECK_EQ(g_unmodelled, QStringList());
    CHECK(g_installedOnce);

    if (g_failed) {
        std::printf("mac_pf_session_check: %d of %d checks FAILED\n", g_failed, g_checks);
        return 1;
    }
    std::printf("mac_pf_session_check: OK (%d checks, %d pf commands modelled)\n", g_checks, g_commands);
    return 0;
}
