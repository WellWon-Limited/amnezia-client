// client/core/serviceEngine/XrayProfileSanitizer.h
// AVPN serviceEngine - the device-side check of an upstream profile before the Xray core gets it.
// [header-only, QtCore + QtNetwork (QHostAddress) values; pure: no I/O, no globals]
//
// Plan provider-pool v2, D3. The backend normalizes every provider profile (upstream_normalize.py) and
// hands it out byte-exact in the signed lease answer. The device does not repair anything: it checks
// that what it got is exactly the shape the normalizer promises and REFUSES the profile otherwise, with
// a stable machine code for telemetry (profileRefusalCode). Then it binds the local inbound exactly like
// the backend's bind_local_inbound (port number, one account with the session's user and password) and
// leaves every other byte as it came: balancers, observatory, dns, routing, fakedns, unknown keys are
// the provider's and are not re-serialized (the output is the input with the three placeholder tokens
// replaced in place - numbers, key order and escapes stay as the backend wrote them).
//
// Checks, in order (each refusal names keys or indices only, never a value or a credential):
//   expected sha is 64 hex (bad_expected_sha) -> size <= 256 KiB (too_large) -> sha256 of the exact
//   bytes (sha_mismatch) -> bind parameters (bad_bind_params) -> JSON object (not_json / not_object)
//   -> no api/stats/metrics/reverse (forbidden_section) -> log without file paths (log_file_path)
//   -> exactly one inbound (inbound_count), socks (inbound_protocol), tag tribe-in (inbound_tag),
//   listen 127.0.0.1 (inbound_listen), auth password (inbound_auth), port/user/pass placeholders in
//   place (placeholder_missing) and nowhere else (placeholder_stray) -> outbounds present
//   (no_outbounds), each protocol allowed (outbound_protocol), at least one proxy (no_proxy_outbound)
//   -> no sockopt interface/mark/tproxy (sockopt_platform) -> every IPv4 fakedns pool parses
//   (fakedns_invalid) and stays off 198.18.0.0/15, the iOS extension's tun range (fakedns_overlap).
//   After the bind the output is parsed again and must equal the backend's bind of the input
//   (placeholder_stray otherwise) - a placeholder hidden behind an escape cannot be bound by mistake.
//
// Outbound allowlist: by default the backend's default (vless, hysteria + freedom, blackhole, dns,
// loopback). The core compiled into the apps carries more (vmess, trojan, shadowsocks, wireguard, socks,
// http - lane-client §1.3, amnezia-xray-core v1.260728.0); upstreamOutboundAllowlist() lets a caller
// widen the list up to what the core has, never beyond it.
//
// Upstream Amnezia has no counterpart (it runs the user's own config as is).
// Tests: tests/upstream_sanitizer_check.cpp (build_upstream_sanitizer.sh), synthetic configs only.
#pragma once

#include <QByteArray>
#include <QCryptographicHash>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QRegularExpression>
#include <QString>
#include <QStringList>

namespace avpn {

// Fixed shape of the local inbound (mirror of upstream_normalize.py).
inline constexpr char kUpstreamInboundTag[] = "tribe-in";
inline constexpr char kUpstreamInboundListen[] = "127.0.0.1";
inline constexpr char kUpstreamPortPlaceholder[] = "__TRIBE_SOCKS_PORT__";
inline constexpr char kUpstreamUserPlaceholder[] = "__TRIBE_SOCKS_USER__";
inline constexpr char kUpstreamPassPlaceholder[] = "__TRIBE_SOCKS_PASS__";
inline constexpr int kUpstreamConfigMaxBytes = 256 * 1024;

enum class ProfileRefusal {
    None,
    BadExpectedSha,
    TooLarge,
    ShaMismatch,
    BadBindParams,
    NotJson,
    NotObject,
    ForbiddenSection,
    LogFilePath,
    InboundCount,
    InboundProtocol,
    InboundTag,
    InboundListen,
    InboundAuth,
    PlaceholderMissing,
    PlaceholderStray,
    NoOutbounds,
    OutboundProtocol,
    NoProxyOutbound,
    SockoptPlatform,
    FakeDnsInvalid,
    FakeDnsOverlap,
};

// Stable machine code (telemetry, journal). Never renamed once shipped.
inline const char *profileRefusalCode(ProfileRefusal r)
{
    switch (r) {
    case ProfileRefusal::None: return "ok";
    case ProfileRefusal::BadExpectedSha: return "bad_expected_sha";
    case ProfileRefusal::TooLarge: return "too_large";
    case ProfileRefusal::ShaMismatch: return "sha_mismatch";
    case ProfileRefusal::BadBindParams: return "bad_bind_params";
    case ProfileRefusal::NotJson: return "not_json";
    case ProfileRefusal::NotObject: return "not_object";
    case ProfileRefusal::ForbiddenSection: return "forbidden_section";
    case ProfileRefusal::LogFilePath: return "log_file_path";
    case ProfileRefusal::InboundCount: return "inbound_count";
    case ProfileRefusal::InboundProtocol: return "inbound_protocol";
    case ProfileRefusal::InboundTag: return "inbound_tag";
    case ProfileRefusal::InboundListen: return "inbound_listen";
    case ProfileRefusal::InboundAuth: return "inbound_auth";
    case ProfileRefusal::PlaceholderMissing: return "placeholder_missing";
    case ProfileRefusal::PlaceholderStray: return "placeholder_stray";
    case ProfileRefusal::NoOutbounds: return "no_outbounds";
    case ProfileRefusal::OutboundProtocol: return "outbound_protocol";
    case ProfileRefusal::NoProxyOutbound: return "no_proxy_outbound";
    case ProfileRefusal::SockoptPlatform: return "sockopt_platform";
    case ProfileRefusal::FakeDnsInvalid: return "fakedns_invalid";
    case ProfileRefusal::FakeDnsOverlap: return "fakedns_overlap";
    }
    return "unknown";
}

// Helper outbounds that carry no user traffic to a proxy.
inline const QStringList &upstreamUtilityOutbounds()
{
    static const QStringList l{QStringLiteral("freedom"), QStringLiteral("blackhole"), QStringLiteral("dns"),
                               QStringLiteral("loopback")};
    return l;
}
// The backend's default allowlist (NormalizeOptions.allowed_protocols).
inline const QStringList &upstreamDefaultOutboundProtocols()
{
    static const QStringList l = QStringList{QStringLiteral("vless"), QStringLiteral("hysteria")}
                                 + upstreamUtilityOutbounds();
    return l;
}
// Outbound protocols compiled into the apps' core (Apple amnezia-xray-core v1.260728.0).
inline const QStringList &xrayCoreOutboundProtocols()
{
    static const QStringList l = QStringList{QStringLiteral("vless"), QStringLiteral("vmess"),
                                             QStringLiteral("trojan"), QStringLiteral("shadowsocks"),
                                             QStringLiteral("hysteria"), QStringLiteral("wireguard"),
                                             QStringLiteral("socks"), QStringLiteral("http")}
                                 + upstreamUtilityOutbounds();
    return l;
}
// A wider list from the caller (a server list, later), cut to what the core has; empty = the default.
inline QStringList upstreamOutboundAllowlist(const QStringList &requested)
{
    if (requested.isEmpty())
        return upstreamDefaultOutboundProtocols();
    QStringList out;
    for (const QString &p : requested)
        if (xrayCoreOutboundProtocols().contains(p) && !out.contains(p))
            out << p;
    return out.isEmpty() ? upstreamDefaultOutboundProtocols() : out;
}

struct LocalInboundBind {
    int port = 0;      // the runners (iOS NE, desktop XrayProtocol) re-pick the port; any valid one here
    QString user;      // random per session, 1..255 bytes (SOCKS5 user/password limit)
    QString password;
};

struct ProfileSanitizerOptions {
    int maxBytes = kUpstreamConfigMaxBytes;
    QStringList allowedOutboundProtocols = upstreamDefaultOutboundProtocols();
};

struct SanitizedProfile {
    ProfileRefusal refusal = ProfileRefusal::None;
    QString detail;        // keys / indices only - safe for a journal
    QByteArray coreConfig; // the final core config (UTF-8 JSON); empty on refusal
    bool ok() const { return refusal == ProfileRefusal::None; }
    QString code() const { return QLatin1String(profileRefusalCode(refusal)); }
};

class XrayProfileSanitizer
{
public:
    // config = the lease answer's `config` string as UTF-8 bytes (QString::toUtf8 of the parsed value);
    // expectedSha256Hex = the stub's / lease's config_sha256.
    static SanitizedProfile sanitize(const QByteArray &config, const QString &expectedSha256Hex,
                                     const LocalInboundBind &bind, const ProfileSanitizerOptions &opt = {})
    {
        static const QRegularExpression shaRe(QStringLiteral("^[0-9a-fA-F]{64}$"));
        if (!shaRe.match(expectedSha256Hex).hasMatch())
            return refuse(ProfileRefusal::BadExpectedSha);
        if (config.isEmpty())
            return refuse(ProfileRefusal::NotJson);
        if (config.size() > opt.maxBytes)
            return refuse(ProfileRefusal::TooLarge, QString::number(config.size()));
        if (QCryptographicHash::hash(config, QCryptographicHash::Sha256).toHex()
            != expectedSha256Hex.toLower().toLatin1())
            return refuse(ProfileRefusal::ShaMismatch);
        if (!bindValid(bind))
            return refuse(ProfileRefusal::BadBindParams);

        QJsonParseError pe;
        const QJsonDocument doc = QJsonDocument::fromJson(config, &pe);
        if (pe.error != QJsonParseError::NoError)
            return refuse(ProfileRefusal::NotJson);
        if (!doc.isObject())
            return refuse(ProfileRefusal::NotObject);
        const QJsonObject root = doc.object();

        for (const char *key : {"api", "stats", "metrics", "reverse"})
            if (root.contains(QLatin1String(key)))
                return refuse(ProfileRefusal::ForbiddenSection, QLatin1String(key));

        if (root.contains(QLatin1String("log"))) {
            const QJsonValue lv = root.value(QLatin1String("log"));
            if (!lv.isObject())
                return refuse(ProfileRefusal::LogFilePath, QStringLiteral("log"));
            const QJsonObject log = lv.toObject();
            for (const char *key : {"access", "error"}) {
                if (!log.contains(QLatin1String(key)))
                    continue;
                const QJsonValue v = log.value(QLatin1String(key));
                // "" = stdout/stderr, "none" = off; anything else is a file path.
                if (!v.isString() || !(v.toString().isEmpty() || v.toString() == QLatin1String("none")))
                    return refuse(ProfileRefusal::LogFilePath, QLatin1String(key));
            }
        }

        const QJsonValue inv = root.value(QLatin1String("inbounds"));
        if (!inv.isArray() || inv.toArray().size() != 1 || !inv.toArray().first().isObject())
            return refuse(ProfileRefusal::InboundCount,
                          QString::number(inv.isArray() ? inv.toArray().size() : -1));
        const QJsonObject in = inv.toArray().first().toObject();
        if (in.value(QLatin1String("protocol")).toString() != QLatin1String("socks"))
            return refuse(ProfileRefusal::InboundProtocol);
        if (in.value(QLatin1String("tag")).toString() != QLatin1String(kUpstreamInboundTag))
            return refuse(ProfileRefusal::InboundTag);
        if (in.value(QLatin1String("listen")).toString() != QLatin1String(kUpstreamInboundListen))
            return refuse(ProfileRefusal::InboundListen);
        const QJsonObject settings = in.value(QLatin1String("settings")).toObject();
        if (settings.value(QLatin1String("auth")).toString() != QLatin1String("password"))
            return refuse(ProfileRefusal::InboundAuth);
        if (in.value(QLatin1String("port")) != QJsonValue(QLatin1String(kUpstreamPortPlaceholder)))
            return refuse(ProfileRefusal::PlaceholderMissing, QStringLiteral("port"));
        const QJsonValue accv = settings.value(QLatin1String("accounts"));
        if (!accv.isArray() || accv.toArray().size() != 1 || !accv.toArray().first().isObject())
            return refuse(ProfileRefusal::PlaceholderMissing, QStringLiteral("accounts"));
        const QJsonObject acc = accv.toArray().first().toObject();
        if (acc.value(QLatin1String("user")) != QJsonValue(QLatin1String(kUpstreamUserPlaceholder)))
            return refuse(ProfileRefusal::PlaceholderMissing, QStringLiteral("user"));
        if (acc.value(QLatin1String("pass")) != QJsonValue(QLatin1String(kUpstreamPassPlaceholder)))
            return refuse(ProfileRefusal::PlaceholderMissing, QStringLiteral("pass"));
        int seen[3] = {0, 0, 0};
        countPlaceholders(QJsonValue(root), seen);
        if (seen[0] != 1 || seen[1] != 1 || seen[2] != 1)
            return refuse(ProfileRefusal::PlaceholderStray);

        const QJsonValue obv = root.value(QLatin1String("outbounds"));
        if (!obv.isArray() || obv.toArray().isEmpty())
            return refuse(ProfileRefusal::NoOutbounds);
        const QJsonArray obs = obv.toArray();
        bool proxy = false;
        for (int i = 0; i < obs.size(); ++i) {
            const QJsonValue p = obs.at(i).toObject().value(QLatin1String("protocol"));
            if (!obs.at(i).isObject() || !p.isString())
                return refuse(ProfileRefusal::OutboundProtocol, QStringLiteral("outbound[%1]").arg(i));
            if (!opt.allowedOutboundProtocols.contains(p.toString()))
                return refuse(ProfileRefusal::OutboundProtocol, safeName(p.toString()));
            if (!upstreamUtilityOutbounds().contains(p.toString()))
                proxy = true;
            const QJsonObject so = obs.at(i)
                                       .toObject()
                                       .value(QLatin1String("streamSettings"))
                                       .toObject()
                                       .value(QLatin1String("sockopt"))
                                       .toObject();
            for (const char *key : {"interface", "mark", "tproxy"})
                if (so.contains(QLatin1String(key)))
                    return refuse(ProfileRefusal::SockoptPlatform,
                                  QStringLiteral("outbound[%1]:%2").arg(i).arg(QLatin1String(key)));
        }
        if (!proxy)
            return refuse(ProfileRefusal::NoProxyOutbound);

        const QJsonValue fd = root.value(QLatin1String("fakedns"));
        if (!fd.isUndefined() && !fd.isNull()) {
            QJsonArray pools;
            if (fd.isObject())
                pools.append(fd);
            else if (fd.isArray())
                pools = fd.toArray();
            else
                return refuse(ProfileRefusal::FakeDnsInvalid, QStringLiteral("fakedns"));
            const QHostAddress neNet(QStringLiteral("198.18.0.0"));
            for (int i = 0; i < pools.size(); ++i) {
                const QJsonValue cidr = pools.at(i).toObject().value(QLatin1String("ipPool"));
                if (!pools.at(i).isObject() || !cidr.isString())
                    return refuse(ProfileRefusal::FakeDnsInvalid, QStringLiteral("fakedns[%1]").arg(i));
                const auto subnet = QHostAddress::parseSubnet(cidr.toString());
                if (subnet.first.isNull() || subnet.second < 0)
                    return refuse(ProfileRefusal::FakeDnsInvalid, QStringLiteral("fakedns[%1]").arg(i));
                if (subnet.first.protocol() != QAbstractSocket::IPv4Protocol)
                    continue;
                if (subnet.first.isInSubnet(neNet, 15) || neNet.isInSubnet(subnet.first, subnet.second))
                    return refuse(ProfileRefusal::FakeDnsOverlap, QStringLiteral("fakedns[%1]").arg(i));
            }
        }

        // Bind: the three placeholder tokens replaced in place, nothing else touched.
        QByteArray out = config;
        if (!replaceOnce(out, kUpstreamPortPlaceholder, QByteArray::number(bind.port))
            || !replaceOnce(out, kUpstreamUserPlaceholder, jsonString(bind.user))
            || !replaceOnce(out, kUpstreamPassPlaceholder, jsonString(bind.password)))
            return refuse(ProfileRefusal::PlaceholderStray);
        const QJsonDocument bound = QJsonDocument::fromJson(out, &pe);
        if (pe.error != QJsonParseError::NoError || !bound.isObject()
            || bound.object() != bindLocalInbound(root, bind))
            return refuse(ProfileRefusal::PlaceholderStray);

        SanitizedProfile ok;
        ok.coreConfig = out;
        return ok;
    }

    // Mirror of upstream_normalize.bind_local_inbound on parsed JSON (listen kept: it is 127.0.0.1).
    static QJsonObject bindLocalInbound(const QJsonObject &config, const LocalInboundBind &bind)
    {
        QJsonObject out = config;
        QJsonArray inbounds = out.value(QLatin1String("inbounds")).toArray();
        for (int i = 0; i < inbounds.size(); ++i) {
            QJsonObject ib = inbounds.at(i).toObject();
            if (ib.value(QLatin1String("tag")).toString() != QLatin1String(kUpstreamInboundTag))
                continue;
            ib.insert(QLatin1String("port"), bind.port);
            QJsonObject settings = ib.value(QLatin1String("settings")).toObject();
            settings.insert(QLatin1String("accounts"),
                            QJsonArray{QJsonObject{{QLatin1String("user"), bind.user},
                                                   {QLatin1String("pass"), bind.password}}});
            ib.insert(QLatin1String("settings"), settings);
            inbounds[i] = ib;
        }
        out.insert(QLatin1String("inbounds"), inbounds);
        return out;
    }

private:
    static SanitizedProfile refuse(ProfileRefusal r, const QString &detail = QString())
    {
        SanitizedProfile s;
        s.refusal = r;
        s.detail = detail;
        return s;
    }

    static bool bindValid(const LocalInboundBind &b)
    {
        const int u = b.user.toUtf8().size(), p = b.password.toUtf8().size();
        return b.port >= 1 && b.port <= 65535 && u >= 1 && u <= 255 && p >= 1 && p <= 255;
    }

    // A protocol name for the journal: short identifier characters only.
    static QString safeName(const QString &s)
    {
        static const QRegularExpression re(QStringLiteral("^[A-Za-z0-9_-]{1,32}$"));
        return re.match(s).hasMatch() ? s : QStringLiteral("?");
    }

    static void countPlaceholders(const QJsonValue &v, int seen[3])
    {
        static const QString ph[3] = {QLatin1String(kUpstreamPortPlaceholder),
                                      QLatin1String(kUpstreamUserPlaceholder),
                                      QLatin1String(kUpstreamPassPlaceholder)};
        const auto check = [&](const QString &s) {
            for (int i = 0; i < 3; ++i)
                if (s == ph[i])
                    ++seen[i];
        };
        if (v.isString()) {
            check(v.toString());
        } else if (v.isArray()) {
            for (const QJsonValue &e : v.toArray())
                countPlaceholders(e, seen);
        } else if (v.isObject()) {
            const QJsonObject o = v.toObject();
            for (auto it = o.begin(); it != o.end(); ++it) {
                check(it.key());
                countPlaceholders(it.value(), seen);
            }
        }
    }

    // Replaces the one literal token "<placeholder>" (with its quotes) by `with`; false unless the
    // token occurs exactly once in the text.
    static bool replaceOnce(QByteArray &text, const char *placeholder, const QByteArray &with)
    {
        const QByteArray token = QByteArray("\"") + placeholder + '"';
        const qsizetype at = text.indexOf(token);
        if (at < 0 || text.indexOf(token, at + 1) >= 0)
            return false;
        text.replace(at, token.size(), with);
        return true;
    }

    static QByteArray jsonString(const QString &s)
    {
        const QByteArray a = QJsonDocument(QJsonArray{s}).toJson(QJsonDocument::Compact);
        return a.mid(1, a.size() - 2); // ["..."] -> "..."
    }
};

} // namespace avpn
