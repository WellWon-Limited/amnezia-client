// service/server/tests/pf_scan_exemption_check.cpp
// AVPN (Scanner, plan R6): a reading of the real pf anchors (deploy/data/macos/pf/*.conf, order from
// tribe.conf) by a small evaluator of the subset of pf.conf they use (last match wins, `quick` ends the
// evaluation, `set skip` ignored for non-loopback packets), with the runtime rules the service loads:
//  - the AmneziaWG kill switch (WireguardUtilsMacos::applyFirewallRules, blockAll): the service's probe
//    sockets on the uplink are DROPPED without the scan exemption and PASS with it; a user application's
//    identical packets are dropped in both cases; the exemption does not open another interface;
//  - the Xray kill switch (KillSwitch::enableKillSwitch, splitTunnelType 0): 400.allowPIA already passes
//    the service's sockets (no exemption needed), a user application's are dropped.
// Packets are modelled, nothing is sent and pfctl is never run. Run by build_tribe_scan.sh (macOS).
#include "platforms/macos/daemon/macosfirewall.h"

#include <QDir>
#include <QFile>
#include <QHash>
#include <QHostAddress>
#include <QMap>
#include <QRegularExpression>
#include <QSet>
#include <QStringList>

#include <cstdio>

static int g_checks = 0;
static int g_failed = 0;
static int g_skipped = 0; // a rule line the model could not read: the reading would be incomplete
#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        ++g_checks;                                                                                                    \
        if (!(cond)) {                                                                                                 \
            ++g_failed;                                                                                                \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                                       \
        }                                                                                                              \
    } while (0)

struct Packet {
    QString ifname;
    int af = 4;
    QString proto = QStringLiteral("tcp");
    QString dst;
    int dstPort = 443;
    int srcPort = 51515;
    QString group;
    QString user = QStringLiteral("root");
};

struct Rule {
    bool pass = false;
    bool quick = false;
    QString dir; // "" = both
    QSet<QString> on;
    int af = 0;
    QSet<QString> protos;
    int fromPort = -1;
    QString toTable;
    QStringList toAddrs; // CIDRs; empty + no table = any
    QSet<int> toPorts;
    QSet<QString> groups;
    QSet<QString> users;
    QString text;
};

struct Anchor {
    QList<Rule> rules;
    QHash<QString, QStringList> tables;
};

static QStringList tokens(QString line, const QHash<QString, QString> &macros)
{
    for (auto it = macros.cbegin(); it != macros.cend(); ++it)
        line.replace(QLatin1Char('$') + it.key(), it.value());
    line.replace(QLatin1Char('{'), QStringLiteral(" { ")).replace(QLatin1Char('}'), QStringLiteral(" } ")).replace(QLatin1Char(','), QLatin1Char(' '));
    return line.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
}

// One value or a { list } starting at t[i]; i moves past it.
static QStringList listAt(const QStringList &t, int &i)
{
    QStringList out;
    if (i >= t.size())
        return out;
    if (t[i] == QLatin1String("{")) {
        ++i;
        while (i < t.size() && t[i] != QLatin1String("}"))
            out << t[i++];
        ++i;
        return out;
    }
    out << t[i++];
    return out;
}

static bool parseRule(const QStringList &t, Rule &r)
{
    if (t.isEmpty() || (t[0] != QLatin1String("pass") && t[0] != QLatin1String("block")))
        return false;
    r.pass = t[0] == QLatin1String("pass");
    int i = 1;
    while (i < t.size()) {
        const QString w = t[i];
        if (w == QLatin1String("return") || w == QLatin1String("all")) {
            ++i;
        } else if (w == QLatin1String("in") || w == QLatin1String("out")) {
            r.dir = w;
            ++i;
        } else if (w == QLatin1String("quick")) {
            r.quick = true;
            ++i;
        } else if (w == QLatin1String("on")) {
            ++i;
            for (const QString &s : listAt(t, i))
                r.on << s;
        } else if (w == QLatin1String("inet")) {
            r.af = 4;
            ++i;
        } else if (w == QLatin1String("inet6")) {
            r.af = 6;
            ++i;
        } else if (w == QLatin1String("proto")) {
            ++i;
            for (const QString &s : listAt(t, i))
                r.protos << s;
        } else if (w == QLatin1String("from")) {
            ++i;
            if (i < t.size() && t[i] == QLatin1String("port")) {
                ++i;
                r.fromPort = t.value(i++).toInt();
            } else {
                listAt(t, i); // a source address: none of ours is constrained by one
            }
        } else if (w == QLatin1String("to")) {
            ++i;
            if (i < t.size() && t[i] == QLatin1String("port")) {
                // "to port N": any address
            } else if (i < t.size() && t[i].startsWith(QLatin1Char('<'))) {
                r.toTable = t[i].mid(1, t[i].size() - 2);
                ++i;
            } else {
                for (const QString &s : listAt(t, i))
                    if (s != QLatin1String("any"))
                        r.toAddrs << s;
            }
        } else if (w == QLatin1String("port")) {
            ++i;
            for (const QString &s : listAt(t, i))
                r.toPorts << s.toInt();
        } else if (w == QLatin1String("group")) {
            ++i;
            for (const QString &s : listAt(t, i))
                r.groups << s;
        } else if (w == QLatin1String("user")) {
            ++i;
            for (const QString &s : listAt(t, i))
                r.users << s;
        } else if (w == QLatin1String("flags")) {
            i += 2;
        } else if (w == QLatin1String("no")) {
            i += 2; // no state
        } else {
            std::fprintf(stderr, "pf model: unknown word '%s' in: %s\n", qPrintable(w), qPrintable(t.join(QLatin1Char(' '))));
            return false;
        }
    }
    r.text = t.join(QLatin1Char(' '));
    return true;
}

static bool inAny(const QString &ip, const QStringList &cidrs)
{
    const QHostAddress a(ip);
    for (const QString &c : cidrs) {
        const QPair<QHostAddress, int> net = QHostAddress::parseSubnet(c.contains(QLatin1Char('/')) ? c : c + (c.contains(QLatin1Char(':')) ? QStringLiteral("/128") : QStringLiteral("/32")));
        if (net.first.protocol() == a.protocol() && a.isInSubnet(net))
            return true;
    }
    return false;
}

static bool matches(const Rule &r, const Anchor &an, const Packet &p)
{
    if (!r.dir.isEmpty() && r.dir != QLatin1String("out"))
        return false;
    if (!r.on.isEmpty() && !r.on.contains(p.ifname))
        return false;
    if (r.af && r.af != p.af)
        return false;
    if (!r.protos.isEmpty() && !r.protos.contains(p.proto))
        return false;
    if (r.fromPort >= 0 && r.fromPort != p.srcPort)
        return false;
    if (!r.toTable.isEmpty() && !inAny(p.dst, an.tables.value(r.toTable)))
        return false;
    if (!r.toAddrs.isEmpty() && !inAny(p.dst, r.toAddrs))
        return false;
    if (!r.toPorts.isEmpty() && !r.toPorts.contains(p.dstPort))
        return false;
    if (!r.groups.isEmpty() && !r.groups.contains(p.group))
        return false;
    if (!r.users.isEmpty() && !r.users.contains(p.user))
        return false;
    return true;
}

static Anchor parseAnchor(const QString &text)
{
    Anchor an;
    QHash<QString, QString> macros;
    QString joined = text;
    joined.replace(QStringLiteral("\\\n"), QStringLiteral(" "));
    for (QString line : joined.split(QLatin1Char('\n'))) {
        const int hash = line.indexOf(QLatin1Char('#'));
        if (hash >= 0)
            line = line.left(hash);
        line = line.trimmed();
        if (line.isEmpty() || line.startsWith(QLatin1String("set ")))
            continue;
        const QRegularExpressionMatch m = QRegularExpression(QStringLiteral("^(\\w+)\\s*=\\s*\"(.*)\"$")).match(line);
        if (m.hasMatch()) {
            macros.insert(m.captured(1), m.captured(2));
            continue;
        }
        const QStringList t = tokens(line, macros);
        if (t.value(0) == QLatin1String("table")) {
            const QString name = t.value(1).mid(1, t.value(1).size() - 2);
            int i = 2;
            an.tables.insert(name, listAt(t, i));
            continue;
        }
        Rule r;
        if (parseRule(t, r))
            an.rules << r;
        else {
            std::fprintf(stderr, "pf model: skipped line: %s\n", qPrintable(line));
            ++g_skipped;
        }
    }
    return an;
}

struct Ruleset {
    QStringList order;            // anchor names from tribe.conf
    QMap<QString, Anchor> enabled; // enabled anchors with their rules
};

// true = passes
static bool evaluate(const Ruleset &rs, const Packet &p, QString *why = nullptr)
{
    bool pass = true; // pf default: pass
    QString last = QStringLiteral("(default pass)");
    for (const QString &name : rs.order) {
        if (!rs.enabled.contains(name))
            continue;
        const Anchor &an = rs.enabled[name];
        for (const Rule &r : an.rules) {
            if (!matches(r, an, p))
                continue;
            pass = r.pass;
            last = name + QStringLiteral(": ") + r.text;
            if (r.quick) {
                if (why)
                    *why = last;
                return pass;
            }
        }
    }
    if (why)
        *why = last;
    return pass;
}

int main(int argc, char **argv)
{
    const QString dir = argc > 1 ? QString::fromLocal8Bit(argv[1]) : QString();
    auto read = [&](const QString &file) {
        QFile f(QDir(dir).filePath(file));
        if (!f.open(QIODevice::ReadOnly)) {
            std::fprintf(stderr, "FAIL: cannot read %s\n", qPrintable(f.fileName()));
            ++g_failed;
            return QString();
        }
        return QString::fromUtf8(f.readAll());
    };
    QStringList order;
    for (const QString &line : read(QStringLiteral("tribe.conf")).split(QLatin1Char('\n'))) {
        const QRegularExpressionMatch m = QRegularExpression(QStringLiteral("^anchor \"([^\"]+)\"")).match(line.trimmed());
        if (m.hasMatch())
            order << m.captured(1);
    }
    CHECK(order.contains(QStringLiteral("160.allowScan")));
    CHECK(order.indexOf(QStringLiteral("160.allowScan")) < order.indexOf(QStringLiteral("400.allowPIA")));
    auto fileAnchor = [&](const QString &name) { return parseAnchor(read(QStringLiteral("tribe.%1.conf").arg(name))); };
    auto rulesAnchor = [&](const QStringList &rules) { return parseAnchor(rules.join(QLatin1Char('\n'))); };

    // The exemption rule itself: one quick pass, the service's identity, the uplink; unsafe names give none.
    const QStringList ex = MacOSFirewall::scanExemptionRules(QStringLiteral("en0"));
    CHECK(ex.size() == 1 && ex.first().contains(QStringLiteral(" quick ")) && ex.first().contains(QStringLiteral("group { tribevpn }"))
          && ex.first().contains(QStringLiteral(" on en0 ")));
    for (const QString &bad : {QStringLiteral(""), QStringLiteral("en0; pfctl -d"), QStringLiteral("en0'"), QStringLiteral("Ethernet 2"),
                               QStringLiteral("abcdefghijklmnop"), QStringLiteral("en-0")})
        CHECK(MacOSFirewall::scanExemptionRules(bad).isEmpty());
    CHECK(MacOSFirewall::scanExemptionRules(QStringLiteral("abcdefghijklmno")).size() == 1); // 15 = IFNAMSIZ - 1

    const QString peer = QStringLiteral("198.51.100.20");   // the live AWG / Xray node (excluded address)
    const QString tunnelDns = QStringLiteral("10.8.1.1");   // the tunnel's DNS (inside the tunnel)
    const QString probeNode = QStringLiteral("203.0.113.9"); // another node a probe connects to
    const QString lanDns = QStringLiteral("192.168.1.1");

    // --- AmneziaWG tunnel with the kill switch (WireguardUtilsMacos::applyFirewallRules, blockAll) ---------
    Ruleset awg;
    awg.order = order;
    awg.enabled[QStringLiteral("000.allowLoopback")] = fileAnchor(QStringLiteral("000.allowLoopback"));
    awg.enabled[QStringLiteral("100.blockAll")] = fileAnchor(QStringLiteral("100.blockAll"));
    Anchor allow = fileAnchor(QStringLiteral("110.allowNets"));
    allow.tables[QStringLiteral("allownets")] = {peer};
    awg.enabled[QStringLiteral("110.allowNets")] = allow;
    awg.enabled[QStringLiteral("200.allowVPN")] = rulesAnchor({QStringLiteral("pass out on utun9 flags any no state")});
    awg.enabled[QStringLiteral("250.blockIPv6")] = fileAnchor(QStringLiteral("250.blockIPv6"));
    awg.enabled[QStringLiteral("290.allowDHCP")] = fileAnchor(QStringLiteral("290.allowDHCP"));
    awg.enabled[QStringLiteral("300.allowLAN")] = fileAnchor(QStringLiteral("300.allowLAN"));
    Anchor dns = fileAnchor(QStringLiteral("310.blockDNS"));
    dns.tables[QStringLiteral("dnsaddr")] = {tunnelDns};
    awg.enabled[QStringLiteral("310.blockDNS")] = dns;
    CHECK(awg.enabled[QStringLiteral("100.blockAll")].rules.size() == 1 && !awg.enabled[QStringLiteral("100.blockAll")].rules.first().pass);

    Packet svc;
    svc.ifname = QStringLiteral("en0");
    svc.dst = probeNode;
    svc.group = QStringLiteral("tribevpn");
    Packet user = svc;
    user.group = QStringLiteral("staff");
    user.user = QStringLiteral("someone");
    QString why;

    CHECK(!evaluate(awg, svc, &why)); // R6: the probe is dropped without the exemption
    std::printf("awg, no exemption, service probe -> %s\n", qPrintable(why));
    CHECK(!evaluate(awg, user));
    Packet tun = user;
    tun.ifname = QStringLiteral("utun9");
    CHECK(evaluate(awg, tun)); // the user's traffic in the tunnel passes
    Packet toPeer = user;
    toPeer.dst = peer;
    toPeer.proto = QStringLiteral("udp");
    CHECK(evaluate(awg, toPeer)); // the tunnel's own peer (excluded address)

    Ruleset awgScan = awg;
    awgScan.enabled[QStringLiteral("160.allowScan")] = rulesAnchor(ex);
    CHECK(evaluate(awgScan, svc, &why)); // with the exemption the probe passes
    std::printf("awg, exemption, service probe -> %s\n", qPrintable(why));
    Packet svc6 = svc;
    svc6.af = 6;
    svc6.dst = QStringLiteral("2001:db8::9");
    CHECK(!evaluate(awg, svc6) && evaluate(awgScan, svc6)); // IPv6 probes too (250 is overridden by quick)
    Packet svcDns = svc;
    svcDns.proto = QStringLiteral("udp");
    svcDns.dst = lanDns;
    svcDns.dstPort = 53;
    CHECK(!evaluate(awg, svcDns) && evaluate(awgScan, svcDns)); // the probe's own resolution on the uplink
    CHECK(!evaluate(awgScan, user, &why)); // a user application gains nothing
    std::printf("awg, exemption, user app -> %s\n", qPrintable(why));
    Packet user6 = svc6;
    user6.group = QStringLiteral("staff");
    CHECK(!evaluate(awgScan, user6));
    Packet userDns = svcDns;
    userDns.group = QStringLiteral("staff");
    CHECK(!evaluate(awgScan, userDns));
    Packet svcOtherIf = svc;
    svcOtherIf.ifname = QStringLiteral("en1");
    CHECK(!evaluate(awgScan, svcOtherIf)); // only the uplink the probes are bound to
    Packet rootOther = user;
    rootOther.user = QStringLiteral("root"); // another root process without the service's group
    CHECK(!evaluate(awgScan, rootOther));

    // The AmneziaWG probe child (`amneziawg-go probe`, spawned by the service's engine): pf matches the
    // socket's owner, and the child runs with the service's group (launchd GroupName, inherited by every
    // child; the payload installs amneziawg-go without a set-group-id bit - checked below). Its UDP to
    // another node's AmneziaWG port on the uplink passes with the exemption and only then.
    Packet child = svc;
    child.proto = QStringLiteral("udp");
    child.dst = probeNode;
    child.dstPort = 51820;
    CHECK(!evaluate(awg, child) && evaluate(awgScan, child, &why));
    std::printf("awg, exemption, AmneziaWG probe child -> %s\n", qPrintable(why));
    Packet userUdp = child;
    userUdp.group = QStringLiteral("staff");
    CHECK(!evaluate(awgScan, userUdp));
    // The payload's modes (deploy/tribe/tribe-svc-install.sh): plain 755 for amneziawg-go, no setgid, root:wheel.
    if (argc > 2) {
        QFile inst(QString::fromLocal8Bit(argv[2]));
        CHECK(inst.open(QIODevice::ReadOnly));
        const QString text = QString::fromUtf8(inst.readAll());
        bool chmod755 = false;
        for (const QString &line : text.split(QLatin1Char('\n'))) {
            const QString l = line.trimmed();
            if (l.startsWith(QLatin1String("chmod")) && l.contains(QLatin1String("amneziawg-go")))
                chmod755 = chmod755 || l.startsWith(QLatin1String("chmod 755 "));
            if (l.contains(QLatin1String("amneziawg-go")) && QRegularExpression(QStringLiteral("chmod\\s+([gu]\\+s|[2-7][0-7]{3})")).match(l).hasMatch())
                CHECK(!"a set-id mode for amneziawg-go in the installer");
        }
        CHECK(chmod755);
        CHECK(text.contains(QLatin1String("chown -R root:wheel")));
    }

    // --- Xray tunnel with the kill switch (KillSwitch::enableKillSwitch, splitTunnelType 0) ------------------
    Ruleset xr;
    xr.order = order;
    xr.enabled[QStringLiteral("000.allowLoopback")] = fileAnchor(QStringLiteral("000.allowLoopback"));
    xr.enabled[QStringLiteral("100.blockAll")] = fileAnchor(QStringLiteral("100.blockAll"));
    xr.enabled[QStringLiteral("110.allowNets")] = allow;
    xr.enabled[QStringLiteral("200.allowVPN")] = fileAnchor(QStringLiteral("200.allowVPN"));
    xr.enabled[QStringLiteral("250.blockIPv6")] = fileAnchor(QStringLiteral("250.blockIPv6"));
    xr.enabled[QStringLiteral("290.allowDHCP")] = fileAnchor(QStringLiteral("290.allowDHCP"));
    xr.enabled[QStringLiteral("300.allowLAN")] = fileAnchor(QStringLiteral("300.allowLAN"));
    xr.enabled[QStringLiteral("310.blockDNS")] = dns;
    xr.enabled[QStringLiteral("400.allowPIA")] = fileAnchor(QStringLiteral("400.allowPIA"));
    CHECK(evaluate(xr, svc, &why)); // already exempt by 400.allowPIA
    std::printf("xray, no exemption, service probe -> %s\n", qPrintable(why));
    CHECK(evaluate(xr, svc6) && evaluate(xr, svcDns));
    CHECK(!evaluate(xr, user));
    Ruleset xrScan = xr;
    xrScan.enabled[QStringLiteral("160.allowScan")] = rulesAnchor(ex);
    CHECK(evaluate(xrScan, svc) && !evaluate(xrScan, user)); // the exemption changes nothing for users there

    CHECK(g_skipped == 0);
    std::printf("pf_scan_exemption_check: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}
