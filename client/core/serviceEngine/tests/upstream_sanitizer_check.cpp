// AVPN upstream nodes (plan provider-pool v2, D3): XrayProfileSanitizer - every invariant refuses with
// its own code, the bind matches the backend's bind_local_inbound, and nothing else in the profile
// changes (byte-for-byte). Synthetic, hand-written configs only (documentation addresses, neutral
// names). Build/run: build_upstream_sanitizer.sh
#include "../XrayProfileSanitizer.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>

#include <cstdio>
#include <functional>

using namespace avpn;

static int g_fail = 0, g_total = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        ++g_total;                                                                                 \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                           \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

// A normalized profile as the backend emits it: canonical JSON (sorted keys, compact), one socks inbound
// with the three placeholders, a balancer with observatory, dns, routing, a fakedns pool off the tun
// range, an unknown key with a number a double cannot hold, and a non-ASCII string.
static const QByteArray kProfile =
    R"({"burstObservatory":{"pingConfig":{"interval":"1m"},"subjectSelector":["leg-"]},)"
    R"("dns":{"servers":["1.1.1.1",{"address":"fakedns","domains":["example.org"]}]},)"
    R"("fakedns":[{"ipPool":"100.88.0.0/16","poolSize":65535},{"ipPool":"fc00::/18","poolSize":65535}],)"
    R"("inbounds":[{"listen":"127.0.0.1","port":"__TRIBE_SOCKS_PORT__","protocol":"socks",)"
    R"("settings":{"accounts":[{"pass":"__TRIBE_SOCKS_PASS__","user":"__TRIBE_SOCKS_USER__"}],"auth":"password","udp":true},)"
    R"("sniffing":{"destOverride":["http","tls","fakedns"],"enabled":true},"tag":"tribe-in"}],)"
    R"("log":{"access":"none","dnsLog":false,"loglevel":"warning"},)"
    R"("outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"192.0.2.20","port":443,)"
    R"("users":[{"encryption":"none","id":"11111111-2222-4333-8444-555555555555"}]}]},)"
    R"("streamSettings":{"network":"tcp","security":"reality","sockopt":{"dialerProxy":"leg-b","tcpFastOpen":true}},"tag":"leg-a"},)"
    R"({"protocol":"hysteria","settings":{"address":"198.51.100.7","port":8443},"tag":"leg-b"},)"
    R"({"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"},)"
    R"({"protocol":"dns","tag":"dns-out"},{"protocol":"loopback","settings":{"inboundTag":"re"},"tag":"loop"}],)"
    R"("policy":{"levels":{"0":{"connIdle":300,"downlinkOnly":5,"handshake":5,"uplinkOnly":2}}},)"
    R"("providerExtra":{"big":9007199254740993,"name":"profilé","ratio":0.1},)"
    R"("routing":{"balancers":[{"fallbackTag":"block","selector":["leg-"],"tag":"auto"}],)"
    R"("domainStrategy":"IPIfNonMatch","rules":[{"inboundTag":["tribe-in"],"port":"53","outboundTag":"dns-out"},)"
    R"({"ip":["geoip:private"],"outboundTag":"direct"},{"balancerTag":"auto","network":"tcp,udp"}]}})";

static QString sha(const QByteArray &b)
{
    return QString::fromLatin1(QCryptographicHash::hash(b, QCryptographicHash::Sha256).toHex());
}

static LocalInboundBind bind()
{
    LocalInboundBind b;
    b.port = 10808;
    b.user = QStringLiteral("0123456789abcdef");
    b.password = QStringLiteral("fedcba9876543210fedcba9876543210");
    return b;
}

static SanitizedProfile run(const QByteArray &cfg, const ProfileSanitizerOptions &opt = {})
{
    return XrayProfileSanitizer::sanitize(cfg, sha(cfg), bind(), opt);
}

static QJsonObject root()
{
    return QJsonDocument::fromJson(kProfile).object();
}

static QByteArray ser(const QJsonObject &o)
{
    return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

// Edit a copy of the profile, serialize it, run it.
static SanitizedProfile edited(const std::function<void(QJsonObject &)> &edit,
                               const ProfileSanitizerOptions &opt = {})
{
    QJsonObject o = root();
    edit(o);
    return run(ser(o), opt);
}

static QJsonObject inbound(const QJsonObject &o)
{
    return o.value("inbounds").toArray().first().toObject();
}
static void setInbound(QJsonObject &o, const QJsonObject &ib)
{
    o.insert("inbounds", QJsonArray{ib});
}
static void setOutbound(QJsonObject &o, int i, const QJsonObject &ob)
{
    QJsonArray a = o.value("outbounds").toArray();
    a[i] = ob;
    o.insert("outbounds", a);
}

static bool refused(const SanitizedProfile &p, ProfileRefusal r)
{
    if (p.refusal != r)
        std::printf("   got %s, expected %s (%s)\n", profileRefusalCode(p.refusal), profileRefusalCode(r),
                    qPrintable(p.detail));
    return p.refusal == r && p.coreConfig.isEmpty();
}

static void accepted()
{
    const SanitizedProfile p = run(kProfile);
    CHECK(p.ok() && p.code() == QLatin1String("ok"));
    // Byte-for-byte: the input with exactly the three tokens replaced.
    QByteArray expect = kProfile;
    expect.replace(R"("__TRIBE_SOCKS_PORT__")", "10808");
    expect.replace(R"("__TRIBE_SOCKS_USER__")", R"("0123456789abcdef")");
    expect.replace(R"("__TRIBE_SOCKS_PASS__")", R"("fedcba9876543210fedcba9876543210")");
    CHECK(p.coreConfig == expect);
    CHECK(p.coreConfig.contains("9007199254740993"));        // not re-serialized through a double
    CHECK(p.coreConfig.contains("\"ratio\":0.1"));
    CHECK(p.coreConfig.contains(QStringLiteral("profilé").toUtf8()));
    // Semantics = the backend's bind_local_inbound of the input.
    const QJsonObject out = QJsonDocument::fromJson(p.coreConfig).object();
    CHECK(out == XrayProfileSanitizer::bindLocalInbound(root(), bind()));
    const QJsonObject ib = inbound(out);
    CHECK(ib.value("port").toInt() == 10808 && ib.value("listen").toString() == QLatin1String("127.0.0.1"));
    const QJsonObject acc = ib.value("settings").toObject().value("accounts").toArray().first().toObject();
    CHECK(acc.value("user").toString() == bind().user && acc.value("pass").toString() == bind().password);
    // Everything but the inbound is untouched.
    QJsonObject a = out, b = root();
    a.remove("inbounds");
    b.remove("inbounds");
    CHECK(a == b);
    CHECK(!p.coreConfig.contains("__TRIBE_SOCKS_"));
    // Upper-case expected sha is the same sha.
    CHECK(XrayProfileSanitizer::sanitize(kProfile, sha(kProfile).toUpper(), bind()).ok());
    // Credentials that need JSON escapes are bound exactly.
    LocalInboundBind odd = bind();
    odd.user = QStringLiteral("a\"b\\c");
    odd.password = QStringLiteral("p\u00e9\u0001w");
    const SanitizedProfile q = XrayProfileSanitizer::sanitize(kProfile, sha(kProfile), odd);
    CHECK(q.ok());
    const QJsonObject qa = inbound(QJsonDocument::fromJson(q.coreConfig).object())
                               .value("settings").toObject().value("accounts").toArray().first().toObject();
    CHECK(qa.value("user").toString() == odd.user && qa.value("pass").toString() == odd.password);
    // log: "" and absent are fine too; fakedns absent is fine.
    CHECK(edited([](QJsonObject &o) { o.insert("log", QJsonObject{{"access", ""}, {"error", "none"}}); }).ok());
    CHECK(edited([](QJsonObject &o) { o.remove("log"); }).ok());
    CHECK(edited([](QJsonObject &o) { o.remove("fakedns"); }).ok());
    CHECK(edited([](QJsonObject &o) { o.insert("fakedns", QJsonObject{{"ipPool", "100.88.0.0/16"}}); }).ok());
}

static void integrity()
{
    CHECK(refused(XrayProfileSanitizer::sanitize(kProfile, sha(kProfile).left(63), bind()), ProfileRefusal::BadExpectedSha));
    CHECK(refused(XrayProfileSanitizer::sanitize(kProfile, QString(64, QLatin1Char('z')), bind()), ProfileRefusal::BadExpectedSha));
    CHECK(refused(XrayProfileSanitizer::sanitize(kProfile, QString(), bind()), ProfileRefusal::BadExpectedSha));
    QByteArray tampered = kProfile;
    tampered.replace("192.0.2.20", "192.0.2.21");
    CHECK(refused(XrayProfileSanitizer::sanitize(tampered, sha(kProfile), bind()), ProfileRefusal::ShaMismatch));
    QByteArray spaced = kProfile + ' '; // the same JSON, other bytes: the sha is over the exact bytes
    CHECK(refused(XrayProfileSanitizer::sanitize(spaced, sha(kProfile), bind()), ProfileRefusal::ShaMismatch));
    // Size cap 256 KiB over the exact bytes.
    QJsonObject big = root();
    big.insert("providerExtra", QJsonObject{{"pad", QString(262144, QLatin1Char('x'))}});
    CHECK(refused(run(ser(big)), ProfileRefusal::TooLarge));
    QJsonObject fits = root();
    const int room = 262144 - int(ser(fits).size()) - int(QByteArray(R"(,"pad":"")").size());
    QJsonObject extra = fits.value("providerExtra").toObject();
    extra.insert("pad", QString(room, QLatin1Char('x')));
    fits.insert("providerExtra", extra);
    CHECK(ser(fits).size() == 262144);
    CHECK(run(ser(fits)).ok());
    ProfileSanitizerOptions small;
    small.maxBytes = 1024;
    CHECK(refused(run(kProfile, small), ProfileRefusal::TooLarge));
    CHECK(refused(run("not json {"), ProfileRefusal::NotJson));
    CHECK(refused(run(QByteArray()), ProfileRefusal::NotJson));
    CHECK(refused(run("[1,2]"), ProfileRefusal::NotObject));
    // Bind parameters.
    for (int port : {0, -1, 65536}) {
        LocalInboundBind b = bind();
        b.port = port;
        CHECK(refused(XrayProfileSanitizer::sanitize(kProfile, sha(kProfile), b), ProfileRefusal::BadBindParams));
    }
    LocalInboundBind b = bind();
    b.user.clear();
    CHECK(refused(XrayProfileSanitizer::sanitize(kProfile, sha(kProfile), b), ProfileRefusal::BadBindParams));
    b = bind();
    b.password = QString(256, QLatin1Char('p'));
    CHECK(refused(XrayProfileSanitizer::sanitize(kProfile, sha(kProfile), b), ProfileRefusal::BadBindParams));
    b.password = QString(255, QLatin1Char('p'));
    CHECK(XrayProfileSanitizer::sanitize(kProfile, sha(kProfile), b).ok());
}

static void sections()
{
    for (const char *key : {"api", "stats", "metrics", "reverse"}) {
        const SanitizedProfile p = edited([key](QJsonObject &o) { o.insert(QLatin1String(key), QJsonObject{}); });
        CHECK(refused(p, ProfileRefusal::ForbiddenSection) && p.detail == QLatin1String(key));
    }
    CHECK(refused(edited([](QJsonObject &o) { o.insert("stats", QJsonValue()); }), ProfileRefusal::ForbiddenSection));
    // log
    CHECK(refused(edited([](QJsonObject &o) { o.insert("log", QJsonObject{{"access", "/var/log/a.log"}}); }),
                  ProfileRefusal::LogFilePath));
    CHECK(refused(edited([](QJsonObject &o) { o.insert("log", QJsonObject{{"error", "relative.log"}}); }),
                  ProfileRefusal::LogFilePath));
    CHECK(refused(edited([](QJsonObject &o) { o.insert("log", QJsonObject{{"access", 1}}); }),
                  ProfileRefusal::LogFilePath));
    CHECK(refused(edited([](QJsonObject &o) { o.insert("log", "file.log"); }), ProfileRefusal::LogFilePath));
    CHECK(refused(edited([](QJsonObject &o) { o.insert("log", QJsonObject{{"access", "None"}}); }),
                  ProfileRefusal::LogFilePath));
}

static void inbounds()
{
    CHECK(refused(edited([](QJsonObject &o) { o.remove("inbounds"); }), ProfileRefusal::InboundCount));
    CHECK(refused(edited([](QJsonObject &o) { o.insert("inbounds", QJsonArray()); }), ProfileRefusal::InboundCount));
    CHECK(refused(edited([](QJsonObject &o) { o.insert("inbounds", QJsonObject{}); }), ProfileRefusal::InboundCount));
    CHECK(refused(edited([](QJsonObject &o) { o.insert("inbounds", QJsonArray{5}); }), ProfileRefusal::InboundCount));
    CHECK(refused(edited([](QJsonObject &o) {
                      QJsonArray a = o.value("inbounds").toArray();
                      a << QJsonObject{{"protocol", "http"}, {"listen", "127.0.0.1"}, {"port", 10809}, {"tag", "h"}};
                      o.insert("inbounds", a);
                  }),
                  ProfileRefusal::InboundCount));
    const auto ib = [](const std::function<void(QJsonObject &)> &f) {
        return edited([&f](QJsonObject &o) {
            QJsonObject i = inbound(o);
            f(i);
            setInbound(o, i);
        });
    };
    CHECK(refused(ib([](QJsonObject &i) { i.insert("protocol", "http"); }), ProfileRefusal::InboundProtocol));
    CHECK(refused(ib([](QJsonObject &i) { i.insert("protocol", "tun"); }), ProfileRefusal::InboundProtocol));
    CHECK(refused(ib([](QJsonObject &i) { i.insert("tag", "socks"); }), ProfileRefusal::InboundTag));
    CHECK(refused(ib([](QJsonObject &i) { i.remove("tag"); }), ProfileRefusal::InboundTag));
    CHECK(refused(ib([](QJsonObject &i) { i.insert("listen", "0.0.0.0"); }), ProfileRefusal::InboundListen));
    CHECK(refused(ib([](QJsonObject &i) { i.remove("listen"); }), ProfileRefusal::InboundListen));
    const auto st = [&ib](const std::function<void(QJsonObject &)> &f) {
        return ib([&f](QJsonObject &i) {
            QJsonObject s = i.value("settings").toObject();
            f(s);
            i.insert("settings", s);
        });
    };
    CHECK(refused(st([](QJsonObject &s) { s.insert("auth", "noauth"); }), ProfileRefusal::InboundAuth));
    CHECK(refused(st([](QJsonObject &s) { s.remove("auth"); }), ProfileRefusal::InboundAuth));
    CHECK(refused(ib([](QJsonObject &i) { i.insert("port", 10808); }), ProfileRefusal::PlaceholderMissing));
    CHECK(refused(ib([](QJsonObject &i) { i.remove("port"); }), ProfileRefusal::PlaceholderMissing));
    CHECK(refused(st([](QJsonObject &s) { s.remove("accounts"); }), ProfileRefusal::PlaceholderMissing));
    CHECK(refused(st([](QJsonObject &s) {
                      s.insert("accounts", QJsonArray{QJsonObject{{"user", "__TRIBE_SOCKS_USER__"}, {"pass", "fixed"}}});
                  }),
                  ProfileRefusal::PlaceholderMissing));
    CHECK(refused(st([](QJsonObject &s) {
                      s.insert("accounts", QJsonArray{QJsonObject{{"user", "someone"}, {"pass", "__TRIBE_SOCKS_PASS__"}}});
                  }),
                  ProfileRefusal::PlaceholderMissing));
    CHECK(refused(st([](QJsonObject &s) {
                      QJsonArray a = s.value("accounts").toArray();
                      a << QJsonObject{{"user", "second"}, {"pass", "second"}};
                      s.insert("accounts", a);
                  }),
                  ProfileRefusal::PlaceholderMissing));
}

static void placeholders()
{
    // A placeholder elsewhere (value or key) would be bound by mistake: refused.
    CHECK(refused(edited([](QJsonObject &o) {
                      o.insert("providerExtra", QJsonObject{{"note", "__TRIBE_SOCKS_PASS__"}});
                  }),
                  ProfileRefusal::PlaceholderStray));
    CHECK(refused(edited([](QJsonObject &o) {
                      o.insert("providerExtra", QJsonObject{{"__TRIBE_SOCKS_PORT__", 1}});
                  }),
                  ProfileRefusal::PlaceholderStray));
    // The genuine placeholder written with an escape: the parsed value is right, the text token is not
    // there - nothing would be bound.
    QByteArray escaped = kProfile;
    escaped.replace(R"("port":"__TRIBE_SOCKS_PORT__")", QByteArray(R"("port":")") + "\\u005f" + "_TRIBE_SOCKS_PORT__\"");
    CHECK(escaped != kProfile);
    CHECK(refused(run(escaped), ProfileRefusal::PlaceholderStray));
    // ... and with a decoy token inside another string: the text token exists once, but it is not the
    // inbound's - the re-parse after the bind does not match the backend's bind.
    QByteArray decoy = escaped;
    decoy.replace(R"("name":"profilé")", R"("name":"\"__TRIBE_SOCKS_PORT__")");
    CHECK(decoy.count(R"("__TRIBE_SOCKS_PORT__")") == 1);
    CHECK(refused(run(decoy), ProfileRefusal::PlaceholderStray));
    // A decoy that stays valid JSON after the bind (the user token sits inside another string, the real
    // one is escaped): only the re-parse against the backend's bind catches it.
    QByteArray userDecoy = kProfile;
    userDecoy.replace(R"("user":"__TRIBE_SOCKS_USER__")", QByteArray(R"("user":")") + "\\u005f" + "_TRIBE_SOCKS_USER__\"");
    userDecoy.replace(R"("name":"profilé")", R"("name":"\"__TRIBE_SOCKS_USER__")");
    CHECK(userDecoy.count(R"("__TRIBE_SOCKS_USER__")") == 1);
    CHECK(refused(run(userDecoy), ProfileRefusal::PlaceholderStray));
    // A second placeholder written with an escape somewhere else: the text has one token (the real
    // one), the bind would succeed - only the count over the parsed document catches it.
    QByteArray hidden = kProfile;
    hidden.replace(R"("name":"profilé")", QByteArray(R"("name":")") + "\\u005f" + "_TRIBE_SOCKS_PASS__\"");
    CHECK(hidden.count(R"("__TRIBE_SOCKS_PASS__")") == 1);
    CHECK(refused(run(hidden), ProfileRefusal::PlaceholderStray));
    // A credential that equals another placeholder cannot sneak a second token in.
    LocalInboundBind b = bind();
    b.user = QStringLiteral("__TRIBE_SOCKS_PASS__");
    CHECK(refused(XrayProfileSanitizer::sanitize(kProfile, sha(kProfile), b), ProfileRefusal::PlaceholderStray));
}

static void outbounds()
{
    CHECK(refused(edited([](QJsonObject &o) { o.remove("outbounds"); }), ProfileRefusal::NoOutbounds));
    CHECK(refused(edited([](QJsonObject &o) { o.insert("outbounds", QJsonArray()); }), ProfileRefusal::NoOutbounds));
    CHECK(refused(edited([](QJsonObject &o) { o.insert("outbounds", QJsonObject{}); }), ProfileRefusal::NoOutbounds));
    CHECK(refused(edited([](QJsonObject &o) { setOutbound(o, 1, QJsonObject{{"tag", "x"}}); }),
                  ProfileRefusal::OutboundProtocol));
    CHECK(refused(edited([](QJsonObject &o) {
                      QJsonArray a = o.value("outbounds").toArray();
                      a << 7;
                      o.insert("outbounds", a);
                  }),
                  ProfileRefusal::OutboundProtocol));
    for (const char *proto : {"vmess", "trojan", "shadowsocks", "wireguard", "socks", "http", "VLESS", "tun"}) {
        const SanitizedProfile p = edited([proto](QJsonObject &o) {
            setOutbound(o, 1, QJsonObject{{"protocol", QLatin1String(proto)}, {"tag", "leg-b"}});
        });
        CHECK(refused(p, ProfileRefusal::OutboundProtocol));
    }
    // Widened by the caller up to what the core has - never beyond.
    ProfileSanitizerOptions wide;
    wide.allowedOutboundProtocols = upstreamOutboundAllowlist({"vless", "vmess", "freedom", "blackhole", "dns",
                                                               "loopback", "hysteria", "made-up"});
    CHECK(wide.allowedOutboundProtocols.contains("vmess") && !wide.allowedOutboundProtocols.contains("made-up"));
    CHECK(edited([](QJsonObject &o) { setOutbound(o, 1, QJsonObject{{"protocol", "vmess"}, {"tag", "leg-b"}}); },
                 wide).ok());
    CHECK(upstreamOutboundAllowlist({}) == upstreamDefaultOutboundProtocols());
    CHECK(upstreamOutboundAllowlist({"made-up"}) == upstreamDefaultOutboundProtocols());
    for (const QString &p : upstreamDefaultOutboundProtocols())
        CHECK(xrayCoreOutboundProtocols().contains(p));
    // Only helpers: a "VPN" that would send everything direct.
    CHECK(refused(edited([](QJsonObject &o) {
                      o.insert("outbounds", QJsonArray{QJsonObject{{"protocol", "freedom"}, {"tag", "direct"}},
                                                       QJsonObject{{"protocol", "blackhole"}, {"tag", "block"}}});
                  }),
                  ProfileRefusal::NoProxyOutbound));
}

static void sockopt()
{
    for (const char *key : {"interface", "mark", "tproxy"}) {
        const SanitizedProfile p = edited([key](QJsonObject &o) {
            QJsonObject ob = o.value("outbounds").toArray().at(0).toObject();
            QJsonObject ss = ob.value("streamSettings").toObject();
            QJsonObject so = ss.value("sockopt").toObject();
            so.insert(QLatin1String(key), QLatin1String("x"));
            ss.insert("sockopt", so);
            ob.insert("streamSettings", ss);
            setOutbound(o, 0, ob);
        });
        CHECK(refused(p, ProfileRefusal::SockoptPlatform) && p.detail.startsWith(QLatin1String("outbound[0]:")));
    }
    // On a helper outbound too.
    CHECK(refused(edited([](QJsonObject &o) {
                      setOutbound(o, 2, QJsonObject{{"protocol", "freedom"}, {"tag", "direct"},
                                                    {"streamSettings", QJsonObject{{"sockopt", QJsonObject{{"mark", 255}}}}}});
                  }),
                  ProfileRefusal::SockoptPlatform));
}

static void fakedns()
{
    const auto pool = [](const QJsonValue &v) { return edited([&v](QJsonObject &o) { o.insert("fakedns", v); }); };
    CHECK(refused(pool(QJsonObject{{"ipPool", "198.18.0.0/15"}}), ProfileRefusal::FakeDnsOverlap));
    CHECK(refused(pool(QJsonObject{{"ipPool", "198.19.128.0/17"}}), ProfileRefusal::FakeDnsOverlap));
    CHECK(refused(pool(QJsonObject{{"ipPool", "198.18.0.0/16"}}), ProfileRefusal::FakeDnsOverlap));
    CHECK(refused(pool(QJsonObject{{"ipPool", "198.0.0.0/8"}}), ProfileRefusal::FakeDnsOverlap));
    CHECK(refused(pool(QJsonArray{QJsonObject{{"ipPool", "100.88.0.0/16"}}, QJsonObject{{"ipPool", "198.18.5.0/24"}}}),
                  ProfileRefusal::FakeDnsOverlap));
    CHECK(pool(QJsonObject{{"ipPool", "198.20.0.0/16"}}).ok());
    CHECK(pool(QJsonObject{{"ipPool", "198.16.0.0/15"}}).ok());
    CHECK(pool(QJsonObject{{"ipPool", "fc00::/18"}}).ok());
    CHECK(refused(pool(QJsonObject{{"ipPool", "not-a-cidr"}}), ProfileRefusal::FakeDnsInvalid));
    CHECK(refused(pool(QJsonObject{{"poolSize", 10}}), ProfileRefusal::FakeDnsInvalid));
    CHECK(refused(pool(QJsonObject{{"ipPool", 5}}), ProfileRefusal::FakeDnsInvalid));
    CHECK(refused(pool("198.18.0.0/15"), ProfileRefusal::FakeDnsInvalid));
    CHECK(refused(pool(QJsonArray{7}), ProfileRefusal::FakeDnsInvalid));
}

static void codes()
{
    QSet<QString> seen;
    for (int r = int(ProfileRefusal::None); r <= int(ProfileRefusal::FakeDnsOverlap); ++r) {
        const QString c = QLatin1String(profileRefusalCode(ProfileRefusal(r)));
        CHECK(!c.isEmpty() && c != QLatin1String("unknown") && !seen.contains(c));
        seen.insert(c);
    }
    CHECK(seen.size() == int(ProfileRefusal::FakeDnsOverlap) + 1);
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    std::setvbuf(stdout, nullptr, _IONBF, 0); // FAIL lines survive a crash of a mutated build
    CHECK(run(kProfile).ok()); // the fixture itself is valid
    accepted();
    integrity();
    sections();
    inbounds();
    placeholders();
    outbounds();
    sockopt();
    fakedns();
    codes();
    if (g_fail) {
        std::printf("upstream_sanitizer_check: %d of %d FAILED\n", g_fail, g_total);
        return 1;
    }
    std::printf("upstream_sanitizer_check: OK (%d checks)\n", g_total);
    return 0;
}
