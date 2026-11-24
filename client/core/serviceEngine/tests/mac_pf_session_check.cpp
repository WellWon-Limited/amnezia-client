// AVPN (macOS pf state ownership, 2026-11-24): the real MacOSFirewall (client/platforms/macos/daemon/
// macosfirewall.cpp) runs against a model of the pf kernel state instead of /bin/bash: its command seam
// (MacOSFirewall::setCommandRunner) hands every command to the model, which keeps the rules and tables of
// the root anchor "tribe" and of each sub-anchor, the main ruleset's reference and our pf token, and
// reads the real anchor files (deploy/data/macos/pf). Nothing is executed: an unmodelled command fails
// the check. pfctl is never run.
//
// Sequences (the kill switch of each session = MacOSFirewall::applySessionRules with the params its
// caller builds: WireguardUtilsMacos::applyFirewallRules for AmneziaWG, KillSwitch::enableKillSwitch for
// Xray; a stop = MacOSFirewall::uninstall, or applyStrictBlock with the strict kill switch; the call
// sites are checked by check_mac_pf_session_wiring.sh):
//   P1  reboot -> AWG(utunA): installed, 200.allowVPN passes utunA only, 400.allowPIA empty
//   P2  AWG -> stop: every tribe/* anchor (rules and tables), the root anchor and the token are gone
//   P3  AWG(utunA) -> stop -> Xray(utun22): 200.allowVPN passes exactly utun22 (the field defect, 24.11)
//   P4  Xray -> stop -> AWG(utunB): 200.allowVPN = utunB, 400.allowPIA empty
//   P5  AWG(utunA) -> AWG(utunB), with and without a stop: 200.allowVPN = utunB only
//   P6  Xray -> (client lost, no stop) -> AWG: 400.allowPIA of the Xray session is not inherited
//   P7  a session whose tun the service does not know (OpenVPN) gets the static file, not the old rule
//   P8  strict kill switch: the block stays, every session anchor is flushed; the next Xray is right
//   P9  strict keeps the scan's own 160.allowScan; a full stop flushes it
//   P10 first start, previous process died with pf installed (AWG session, scan, retired anchor)
//   P11 first start after an older build stopped with the root-only flush (pf not ours, anchors left)
//   P12 first start with strict on and stale anchors: only the block, from the current files
//   P13 enableAnchor never keeps the kernel copy of a session anchor; keeps a static one
//   P14 tunnel interface names
//   P15 the ownership table matches tribe.conf and the files
// Build and run: tests/build_mac_pf_session.sh <deploy/data/macos/pf>.
#include "platforms/macos/daemon/macosfirewall.h"
#include "platforms/macos/daemon/macospfanchors.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QMap>
#include <QRegularExpression>
#include <QStringList>

#include <cstdio>

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

struct PfFile {
    QStringList rules;
    QMap<QString, QStringList> tables;
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

// The subset of pf.conf the bundled files use: comments, backslash continuations, string macros, tables,
// "set" options (not rules), everything else a rule with $macros expanded and whitespace collapsed.
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
    static const QRegularExpression tableRe(QStringLiteral("^table <([^>]+)>\\s*\\{(.*)\\}$"));
    for (QString line : logical) {
        const auto m = macroRe.match(line);
        if (m.hasMatch()) {
            macros.insert(m.captured(1), (m.captured(2).isEmpty() ? m.captured(3) : m.captured(2)).simplified());
            continue;
        }
        const auto t = tableRe.match(line);
        if (t.hasMatch()) {
            f.tables.insert(t.captured(1), splitItems(t.captured(2)));
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

struct Anchor {
    QStringList rules;
    QMap<QString, QStringList> tables;
    bool empty() const { return rules.isEmpty() && tables.isEmpty(); }
};

struct Kernel {
    bool mainRefsTribe = false; // the main ruleset evaluates "tribe" (anchor "tribe/*" / anchor "tribe")
    bool tokenHeld = false;     // our pf enable reference (pf.token)
    QMap<QString, Anchor> anchors; // "tribe" and "tribe/<sub>"

    void clear(const QString &path) { anchors.remove(path); }
    void loadFile(const QString &path, const QString &file, bool replaceAll)
    {
        const PfFile f = readPfFile(QFileInfo(file).fileName());
        if (!f.exists) {
            g_unmodelled << QStringLiteral("missing file %1").arg(QFileInfo(file).fileName());
            return;
        }
        Anchor &a = anchors[path];
        if (replaceAll)
            a = Anchor();
        a.rules = f.rules;
        for (auto it = f.tables.cbegin(); it != f.tables.cend(); ++it)
            a.tables.insert(it.key(), it.value());
        if (a.empty())
            anchors.remove(path);
    }
};

static Kernel g_k;

static int model(const QString &command)
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
        g_k.loadFile(sub(m), m.captured(2), true);
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
        g_k.anchors[sub(m)].tables.insert(m.captured(2), splitItems(m.captured(3)));
        return 0;
    }
    if ((m = killRe.match(command)).hasMatch()) {
        if (g_k.anchors.contains(sub(m))) {
            g_k.anchors[sub(m)].tables.remove(m.captured(2));
            if (g_k.anchors[sub(m)].empty())
                g_k.clear(sub(m));
        }
        return 0;
    }
    if ((m = flushRulesRe.match(command)).hasMatch()) {
        if (g_k.anchors.contains(sub(m))) {
            g_k.anchors[sub(m)].rules.clear();
            if (g_k.anchors[sub(m)].empty())
                g_k.clear(sub(m));
        }
        return 0;
    }
    if ((m = loadStdinRe.match(command)).hasMatch()) {
        Anchor &a = g_k.anchors[QStringLiteral("tribe/") + m.captured(2)];
        a.rules.clear();
        for (const QString &line : m.captured(1).split(QLatin1Char('\n'), Qt::SkipEmptyParts))
            a.rules << line.simplified();
        if (a.empty())
            g_k.clear(QStringLiteral("tribe/") + m.captured(2));
        return 0;
    }
    if ((m = reloadRe.match(command)).hasMatch()) {
        g_k.loadFile(sub(m), m.captured(2), false);
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
        Anchor root;
        for (const QString &rule : readPfFile(QFileInfo(m.captured(1)).fileName()).rules)
            root.rules << rule;
        g_k.anchors.insert(QStringLiteral("tribe"), root);
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
    return g_k.anchors.value(QStringLiteral("tribe/") + anchor).tables.value(table);
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

// Documentation addresses only (RFC 5737).
static const QString kAwgPeer = QStringLiteral("192.0.2.10");
static const QString kAwgDns = QStringLiteral("198.51.100.53");
static const QString kXrayServer = QStringLiteral("203.0.113.20");
static const QString kXrayDns1 = QStringLiteral("198.51.100.1");
static const QString kXrayDns2 = QStringLiteral("198.51.100.2");

// As WireguardUtilsMacos::addInterface + applyFirewallRules build them (full tunnel, the peer excluded).
static void awgSession(const QString &utun)
{
    FirewallParams p {};
    p.dnsServers = { kAwgDns };
    p.blockAll = true;
    p.allowNets = true;
    p.allowAddrs = { kAwgPeer };
    p.allowPIA = false;
    MacOSFirewall::applySessionRules(p, utun);
}

// As KillSwitch::enableKillSwitch builds them (splitTunnelType 0: blockAll + the server; dns1, dns2).
static void xraySession(const QString &tun)
{
    FirewallParams p {};
    p.blockAll = true;
    p.allowNets = true;
    p.allowAddrs = { kXrayServer };
    p.dnsServers = { kXrayDns1, kXrayDns2 };
    p.allowPIA = true;
    MacOSFirewall::applySessionRules(p, tun);
}

static void stop() { MacOSFirewall::uninstall(); }
static void reboot() { g_k = Kernel(); }

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
    CHECK(g_k.tokenHeld && g_k.mainRefsTribe);
}

static void checkAwg(const QString &utun)
{
    CHECK_EQ(rulesOf(QStringLiteral("200.allowVPN")), pass(utun));
    CHECK_EQ(rulesOf(QStringLiteral("100.blockAll")), fileRules(QStringLiteral("100.blockAll")));
    CHECK_EQ(rulesOf(QStringLiteral("400.allowPIA")), QStringList());
    CHECK_EQ(tableOf(QStringLiteral("110.allowNets"), QStringLiteral("allownets")), QStringList { kAwgPeer });
    CHECK_EQ(tableOf(QStringLiteral("310.blockDNS"), QStringLiteral("dnsaddr")), QStringList { kAwgDns });
    CHECK(!hasTable(QStringLiteral("120.blockNets"), QStringLiteral("blocknets")));
    CHECK(g_k.tokenHeld && g_k.mainRefsTribe);
}

// Only the strict block, from the current files.
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
    g_k.anchors[QStringLiteral("tribe/000.allowLoopback")].rules = fileRules(QStringLiteral("000.allowLoopback"));
    g_k.anchors[QStringLiteral("tribe/100.blockAll")].rules = { QStringLiteral("block out all flags any no state # older build") };
    g_k.anchors[QStringLiteral("tribe/110.allowNets")].rules = fileRules(QStringLiteral("110.allowNets"));
    g_k.anchors[QStringLiteral("tribe/110.allowNets")].tables[QStringLiteral("allownets")] = { kAwgPeer };
    g_k.anchors[QStringLiteral("tribe/160.allowScan")].rules = { QStringLiteral("pass out quick on en0 proto { tcp, udp } group { tribevpn } flags any no state") };
    g_k.anchors[QStringLiteral("tribe/200.allowVPN")].rules = pass(QStringLiteral("utun4"));
    g_k.anchors[QStringLiteral("tribe/310.blockDNS")].rules = fileRules(QStringLiteral("310.blockDNS"));
    g_k.anchors[QStringLiteral("tribe/310.blockDNS")].tables[QStringLiteral("dnsaddr")] = { kAwgDns };
    g_k.anchors[QStringLiteral("tribe/400.allowPIA")].rules = { QStringLiteral("pass out proto { tcp, udp } user { root } flags any no state") };
    g_k.anchors[QStringLiteral("tribe/999.quarantine")].rules = { QStringLiteral("block drop quick all flags any no state") };
}

int main(int argc, char **argv)
{
    // The seam first: no MacOSFirewall call may reach /bin/bash.
    MacOSFirewall::setCommandRunner(&model);
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

    g_case = "P1 reboot -> AWG";
    reboot();
    awgSession(tA);
    checkAwg(tA);

    g_case = "P2 AWG -> stop";
    stop();
    checkAllGone();

    g_case = "P3 AWG -> stop -> Xray";
    reboot();
    awgSession(tA);
    stop();
    xraySession(xray);
    checkXray(xray);

    g_case = "P4 Xray -> stop -> AWG";
    reboot();
    xraySession(xray);
    stop();
    awgSession(tB);
    checkAwg(tB);

    g_case = "P5 AWG(utunA) -> stop -> AWG(utunB)";
    reboot();
    awgSession(tA);
    stop();
    awgSession(tB);
    checkAwg(tB);
    g_case = "P5 AWG(utunA) -> AWG(utunB) over a live pf";
    reboot();
    awgSession(tA);
    awgSession(tB);
    checkAwg(tB);

    g_case = "P6 Xray -> client lost (no stop) -> AWG";
    reboot();
    xraySession(xray);
    awgSession(tB);
    checkAwg(tB);
    g_case = "P6 AWG -> client lost (no stop) -> Xray";
    reboot();
    awgSession(tA);
    xraySession(xray);
    checkXray(xray);

    g_case = "P7 unknown tun after AWG";
    reboot();
    awgSession(tA);
    xraySession(QString());
    CHECK_EQ(rulesOf(QStringLiteral("200.allowVPN")), fileRules(QStringLiteral("200.allowVPN")));
    CHECK(fileRules(QStringLiteral("200.allowVPN")).size() == 1
          && fileRules(QStringLiteral("200.allowVPN")).first().startsWith(QLatin1String("pass out on { utun0, utun1,")));
    xraySession(QStringLiteral("en0")); // not a tun name: never a pass on the uplink
    CHECK_EQ(rulesOf(QStringLiteral("200.allowVPN")), fileRules(QStringLiteral("200.allowVPN")));

    g_case = "P8 strict: AWG -> strict stop";
    reboot();
    awgSession(tA);
    MacOSFirewall::applyStrictBlock();
    checkStrictBlockOnly(false);
    g_case = "P8 strict: Xray -> strict stop -> Xray";
    reboot();
    xraySession(xray);
    MacOSFirewall::applyStrictBlock();
    checkStrictBlockOnly(false);
    awgSession(tA);
    MacOSFirewall::applyStrictBlock();
    xraySession(xray);
    checkXray(xray);
    g_case = "P8 strict: block without pf installed installs it";
    reboot();
    MacOSFirewall::applyStrictBlock();
    checkStrictBlockOnly(false);

    g_case = "P9 strict keeps the scan's anchor";
    reboot();
    xraySession(xray);
    CHECK(MacOSFirewall::setScanExemption(QStringLiteral("en0")) == 1);
    MacOSFirewall::applyStrictBlock();
    checkStrictBlockOnly(true);
    CHECK_EQ(rulesOf(QStringLiteral("160.allowScan")), MacOSFirewall::scanExemptionRules(QStringLiteral("en0")));
    MacOSFirewall::clearScanExemption();
    checkStrictBlockOnly(false);
    g_case = "P9 a full stop flushes the scan's anchor";
    reboot();
    awgSession(tA);
    CHECK(MacOSFirewall::setScanExemption(QStringLiteral("en0")) == 1);
    stop();
    checkAllGone();

    g_case = "P10 first start: previous process died with pf installed";
    plantStale(true);
    CHECK(MacOSFirewall::isInstalled());
    stop(); // KillSwitch::init -> disableKillSwitch -> uninstall
    checkAllGone();
    xraySession(xray);
    checkXray(xray);
    CHECK_EQ(rulesOf(QStringLiteral("999.quarantine")), QStringList());

    g_case = "P11 first session after an older build's root-only stop";
    plantStale(false);
    CHECK(!MacOSFirewall::isInstalled());
    xraySession(xray); // install() starts from a clean state
    checkXray(xray);
    CHECK_EQ(rulesOf(QStringLiteral("999.quarantine")), QStringList());
    CHECK_EQ(rulesOf(QStringLiteral("160.allowScan")), QStringList());
    g_case = "P11 ... and the same for AWG";
    plantStale(false);
    awgSession(tB);
    checkAwg(tB);

    g_case = "P12 first start with strict on, stale anchors";
    plantStale(true);
    MacOSFirewall::applyStrictBlock(); // KillSwitch::init -> disableAllTraffic
    // The scan's anchor is the probe host's: it flushes a dead process's copy at its own start (tribe_scan.cpp).
    CHECK(rulesOf(QStringLiteral("160.allowScan")).size() == 1);
    MacOSFirewall::clearScanExemption();
    checkStrictBlockOnly(false);

    g_case = "P13 enableAnchor and the kernel copy";
    reboot();
    awgSession(tA);
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
            // A table the file declares empty is filled at run time: the session's table (written explicitly).
            bool emptyTable = false;
            for (const QStringList &items : f.tables)
                emptyTable = emptyTable || items.isEmpty();
            CHECK(emptyTable == (a.kind == avpn::pf::AnchorKind::StaticRuleSessionTable));
            // A file without rules is set at run time (or never): not a static anchor.
            if (f.rules.isEmpty())
                CHECK(a.kind == avpn::pf::AnchorKind::ScanRule || a.kind == avpn::pf::AnchorKind::Unused);
        }
        CHECK(avpn::pf::stopFlushList().size() == avpn::pf::anchors().size());
        CHECK(!avpn::pf::strictFlushList().contains(QStringLiteral("160.allowScan")));
        CHECK(avpn::pf::strictFlushList().contains(QStringLiteral("200.allowVPN")));
        CHECK_EQ(avpn::pf::strictBlockList(), (QStringList { QStringLiteral("000.allowLoopback"), QStringLiteral("100.blockAll"),
                                                              QStringLiteral("250.blockIPv6") }));
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
