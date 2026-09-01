// AVPN serviceEngine — автономная проверка этапа D1 волны «AWG 3.1 + Xray через v1-контракт»
// (спека 2026-09-01-awg31-xray-v1-fleet-wave.md §2.2/§2.3):
//   1) регресс: старый awg-JSON (fixtures/subscription.example.json) даёт БАЙТ-В-БАЙТ тот же конфиг
//      AwgConfigBuilder::build, что до волны (sha256 снят до правок DTO/парсера);
//   2) DTO/парсер: host_id/location/transport_rank/pool_revision + xray_params с валидацией;
//      xray-нода без валидных xray_params ОТБРАСЫВАЕТСЯ, не роняя ответ; awg — как раньше;
//   3) XrayConfigBuilder: конверт апстрима (protocol=xray, xray_config_data.config = строка JSON
//      xray-core в схеме vnext[]/realitySettings, inbound socks 127.0.0.1:10808 udp);
//   4) reportSummary без uuid/publicKey (отчёт бенча уходит наружу);
//   5) AwgConfigBuilder::stripUnknownWgQuickKeys — незнакомые ключи вырезаются, известные
//      остаются в исходном порядке (awg-apple 3.1.4 бросает invalidLine на незнакомом ключе).
// Сборка/запуск: core/serviceEngine/tests/build_xray_config.sh
#include "../AwgConfigBuilder.h"
#include "../SubscriptionParser.h"
#include "../XrayConfigBuilder.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <cstdio>

using namespace avpn;

static int g_failed = 0;
static int g_total = 0;

#define CHECK(expr)                                                                                 \
    do {                                                                                            \
        ++g_total;                                                                                  \
        if (!(expr)) {                                                                              \
            ++g_failed;                                                                             \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #expr);                       \
        }                                                                                           \
    } while (0)

// Ключи-заглушки (не секрет): только для детерминированного хеша конфига.
static ClientKeys testKeys()
{
    ClientKeys k;
    k.privateKey = QStringLiteral("cGxhY2Vob2xkZXItcHJpdmF0ZS1rZXktMDAwMDAwMDA=");
    k.publicKey = QStringLiteral("cGxhY2Vob2xkZXItcHVibGljLWtleS0wMDAwMDAwMDA=");
    return k;
}

static const char *kValidUuid = "8f14e45f-ceea-4a7c-9d6b-2a1b3c4d5e6f";
static const char *kValidPubKey = "SbVjZ9Yl3dR3QpG1v8k2Wx0aU7Hq4Nn6Tt5Bc8Jd1mE";

static QJsonObject xrayParamsJson()
{
    return QJsonObject{ { "uuid", QLatin1String(kValidUuid) },
                        { "public_key", QLatin1String(kValidPubKey) },
                        { "short_id", "a1b2c3d4" },
                        { "server_name", "wavecom.ee" },
                        { "fingerprint", "chrome" },
                        { "flow", "xtls-rprx-vision" },
                        { "network", "tcp" },
                        { "security", "reality" } };
}

static QJsonObject awgNodeJson(const char *id, int transportRank = -1)
{
    QJsonObject n{ { "node_id", id },
                   { "region", "eu" },
                   { "endpoint", "203.0.113.10:51820" },
                   { "server_pubkey", "K1nDpUbLiCkEyExAmPlE0000000000000000000000=" },
                   { "proto", "awg" },
                   { "weight", 1.0 },
                   { "country_code", "DE" },
                   { "allowed_ips", QJsonArray{ "0.0.0.0/0", "::/0" } },
                   { "dns", QJsonArray{ "1.1.1.1", "1.0.0.1" } },
                   { "mtu", 1280 },
                   { "persistent_keepalive", 25 },
                   { "awg_params",
                     QJsonObject{ { "Jc", 4 }, { "Jmin", 50 }, { "Jmax", 1000 }, { "S1", 86 },
                                  { "S2", 57 }, { "H1", 1 }, { "H2", 2 }, { "H3", 3 }, { "H4", 4 } } } };
    if (transportRank >= 0)
        n.insert("transport_rank", transportRank);
    return n;
}

static QJsonObject xrayNodeJson(const char *id, const QJsonObject &params, bool withParams = true)
{
    QJsonObject n{ { "node_id", id },
                   { "host_id", 9 },
                   { "location", "ee" },
                   { "region", "eu" },
                   { "country_code", "EE" },
                   { "endpoint", "38.180.164.134:443" },
                   { "proto", "xray" },
                   { "weight", 1.0 },
                   { "dns", QJsonArray{ "1.1.1.1", "1.0.0.1" } } };
    if (withParams)
        n.insert("xray_params", params);
    return n;
}

static QByteArray subJson(const QJsonArray &nodes, qint64 poolRevision = -1)
{
    QJsonObject root{ { "version", 1 },
                      { "address", QJsonArray{ "10.7.0.5/32" } },
                      { "status", "active" },
                      { "expires_at", "2026-09-01T00:00:00Z" },
                      { "traffic", QJsonObject{ { "used", 0 }, { "limit", 0 } } },
                      { "nodes", nodes } };
    if (poolRevision >= 0)
        root.insert("pool_revision", double(poolRevision));
    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

static bool parseXray(QJsonObject params, XrayParams &out, QString &why)
{
    return SubscriptionParser::parseXrayParams(params, out, why);
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    // --- 1) регресс: старый awg-JSON байт-в-байт → тот же конфиг, что до волны ---
    {
        QFile f(QStringLiteral("fixtures/subscription.example.json"));
        CHECK(f.open(QIODevice::ReadOnly));
        Subscription sub;
        QString err;
        CHECK(SubscriptionParser::parse(f.readAll(), sub, err));
        CHECK(sub.nodes.size() == 1);
        CHECK(sub.poolRevision == 0);
        const SubscriptionNode &n = sub.nodes.first();
        CHECK(n.proto == QLatin1String("awg"));
        CHECK(n.hostId == 0);
        CHECK(n.location.isEmpty());
        CHECK(n.transportRank == 10);
        CHECK(!n.xray.has_value());
        const QByteArray built =
            QJsonDocument(AwgConfigBuilder::build(sub, n, testKeys())).toJson(QJsonDocument::Compact);
        const QByteArray sha = QCryptographicHash::hash(built, QCryptographicHash::Sha256).toHex();
        // Снято на ci-build 26a19af9 (до этапа D1) тем же build() с теми же ключами-заглушками.
        CHECK(sha == QByteArray("a1ddc1bd62a2c1ae9c1b053d42127c70b6eba5621177f80364ea3ce6fff5fd14"));
        if (sha != "a1ddc1bd62a2c1ae9c1b053d42127c70b6eba5621177f80364ea3ce6fff5fd14")
            fprintf(stderr, "  regression sha256=%s\n  json=%s\n", sha.constData(), built.constData());
        // Наш wg-quick целиком из известных awg-apple ключей → фильтр ничего не трогает.
        const QString wq = AwgConfigBuilder::wgQuick(sub, n, testKeys());
        CHECK(AwgConfigBuilder::stripUnknownWgQuickKeys(wq, AwgConfigBuilder::awgAppleWgQuickKeys()) == wq);
        CHECK(SubscriptionParser::validate(sub).isEmpty());
    }

    // --- 2) парсер: awg + валидный xray + xray с битым uuid + xray без params → 2 ноды ---
    {
        QJsonObject bad = xrayParamsJson();
        bad.insert("uuid", "not-a-uuid");
        const QByteArray json = subJson(QJsonArray{ awgNodeJson("fra-01", 5),
                                                    xrayNodeJson("9:xray", xrayParamsJson()),
                                                    xrayNodeJson("x-bad", bad),
                                                    xrayNodeJson("x-none", {}, false) },
                                        17);
        Subscription sub;
        QString err;
        CHECK(SubscriptionParser::parse(json, sub, err));
        CHECK(sub.poolRevision == 17);
        CHECK(sub.nodes.size() == 2);
        if (sub.nodes.size() == 2) {
            const SubscriptionNode &a = sub.nodes.at(0);
            CHECK(a.nodeId == QLatin1String("fra-01"));
            CHECK(a.transportRank == 5);        // явный ранг уважаем
            CHECK(a.hostId == 0 && !a.xray.has_value());
            CHECK(a.awg.hasFullBundle());

            const SubscriptionNode &x = sub.nodes.at(1);
            CHECK(x.nodeId == QLatin1String("9:xray"));
            CHECK(x.proto == QLatin1String("xray"));
            CHECK(x.hostId == 9);
            CHECK(x.location == QLatin1String("ee"));
            CHECK(x.transportRank == 20);       // дефолт xray без transport_rank
            CHECK(x.xray.has_value());
            if (x.xray) {
                CHECK(x.xray->uuid == QLatin1String(kValidUuid));
                CHECK(x.xray->publicKey == QLatin1String(kValidPubKey));
                CHECK(x.xray->shortId == QLatin1String("a1b2c3d4"));
                CHECK(x.xray->serverName == QLatin1String("wavecom.ee"));
                CHECK(x.xray->fingerprint == QLatin1String("chrome"));
                CHECK(x.xray->flow == QLatin1String("xtls-rprx-vision"));
                CHECK(x.xray->network == QLatin1String("tcp"));
                CHECK(x.xray->security == QLatin1String("reality"));
            }
            // validate: xray-нода с host:port и параметрами — без претензий; awg-претензий к ней нет.
            const QStringList issues = SubscriptionParser::validate(sub);
            for (const QString &i : issues)
                fprintf(stderr, "  unexpected issue: %s\n", i.toUtf8().constData());
            CHECK(issues.isEmpty());
        }
        // awg-нода без transport_rank → 10; строковый transport_rank → дефолт (не 0).
        Subscription s2;
        QJsonObject weird = awgNodeJson("w");
        weird.insert("transport_rank", "high");
        CHECK(SubscriptionParser::parse(subJson(QJsonArray{ awgNodeJson("d"), weird }), s2, err));
        CHECK(s2.nodes.size() == 2 && s2.nodes.at(0).transportRank == 10 && s2.nodes.at(1).transportRank == 10);
        // пул только из битых xray → парс ок, пул пуст (штатная ветка «нет нод», не ошибка).
        Subscription s3;
        CHECK(SubscriptionParser::parse(subJson(QJsonArray{ xrayNodeJson("x-bad", bad) }), s3, err));
        CHECK(s3.nodes.isEmpty());
        // xray-нода с endpoint без порта → validate жалуется (fail-closed на уровне валидации).
        Subscription s4;
        QJsonObject noPort = xrayNodeJson("x-np", xrayParamsJson());
        noPort.insert("endpoint", "38.180.164.134");
        CHECK(SubscriptionParser::parse(subJson(QJsonArray{ noPort }), s4, err));
        CHECK(s4.nodes.size() == 1);
        CHECK(!SubscriptionParser::validate(s4).isEmpty());
    }

    // --- 3) parseXrayParams: матрица валидации ---
    {
        XrayParams p;
        QString why;
        CHECK(parseXray(xrayParamsJson(), p, why));

        auto with = [](const char *key, const QJsonValue &v) {
            QJsonObject o = xrayParamsJson();
            o.insert(QLatin1String(key), v);
            return o;
        };
        auto without = [](const char *key) {
            QJsonObject o = xrayParamsJson();
            o.remove(QLatin1String(key));
            return o;
        };
        // uuid
        CHECK(!parseXray(with("uuid", "8f14e45fceea4a7c9d6b2a1b3c4d5e6f"), p, why)); // без дефисов
        CHECK(!parseXray(with("uuid", "8f14e45f-ceea-4a7c-9d6b-2a1b3c4d5e6g"), p, why)); // не hex
        CHECK(!parseXray(without("uuid"), p, why));
        CHECK(parseXray(with("uuid", "8F14E45F-CEEA-4A7C-9D6B-2A1B3C4D5E6F"), p, why)); // верхний регистр ок
        // public_key
        CHECK(!parseXray(without("public_key"), p, why));
        CHECK(!parseXray(with("public_key", ""), p, why));
        CHECK(!parseXray(with("public_key", "has space in it"), p, why));
        // short_id: hex чётной длины 2..16
        CHECK(parseXray(with("short_id", "ab"), p, why));
        CHECK(parseXray(with("short_id", "0123456789abcdef"), p, why));
        CHECK(!parseXray(with("short_id", ""), p, why));
        CHECK(!parseXray(with("short_id", "abc"), p, why));                 // нечётная
        CHECK(!parseXray(with("short_id", "0123456789abcdef01"), p, why));  // 18
        CHECK(!parseXray(with("short_id", "zz"), p, why));                  // не hex
        CHECK(!parseXray(without("short_id"), p, why));
        // server_name
        CHECK(!parseXray(with("server_name", ""), p, why));
        CHECK(!parseXray(without("server_name"), p, why));
        // fingerprint: allowlist; отсутствует → chrome
        for (const char *fp : { "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
                                "random", "randomized" })
            CHECK(parseXray(with("fingerprint", fp), p, why));
        CHECK(!parseXray(with("fingerprint", "Mozilla/5.0"), p, why));
        CHECK(parseXray(without("fingerprint"), p, why) && p.fingerprint == QLatin1String("chrome"));
        // flow: xtls-rprx-vision или пусто
        CHECK(parseXray(with("flow", ""), p, why) && p.flow.isEmpty());
        CHECK(parseXray(without("flow"), p, why) && p.flow.isEmpty());
        CHECK(!parseXray(with("flow", "xtls-rprx-vision-udp443"), p, why));
        // network: tcp (raw = синоним xray-core, нормализуем в tcp); отсутствует → tcp
        CHECK(parseXray(with("network", "raw"), p, why) && p.network == QLatin1String("tcp"));
        CHECK(parseXray(without("network"), p, why) && p.network == QLatin1String("tcp"));
        CHECK(!parseXray(with("network", "xhttp"), p, why));
        CHECK(!parseXray(with("network", "kcp"), p, why));
        // security: reality; отсутствует → reality
        CHECK(parseXray(without("security"), p, why) && p.security == QLatin1String("reality"));
        CHECK(!parseXray(with("security", "tls"), p, why));
        CHECK(!parseXray(with("security", "none"), p, why));
        // пустой объект → невалидно, why непустой
        CHECK(!parseXray(QJsonObject{}, p, why) && !why.isEmpty());
    }

    // --- 4) XrayConfigBuilder::build — конверт апстрима + JSON xray-core ---
    {
        Subscription sub;
        QString err;
        CHECK(SubscriptionParser::parse(subJson(QJsonArray{ xrayNodeJson("9:xray", xrayParamsJson()) }, 3),
                                        sub, err));
        CHECK(sub.nodes.size() == 1);
        const SubscriptionNode &x = sub.nodes.first();
        const QJsonObject root = XrayConfigBuilder::build(sub, x, testKeys());
        CHECK(root.value("protocol").toString() == QLatin1String("xray"));
        CHECK(root.value("hostName").toString() == QLatin1String("38.180.164.134"));
        CHECK(root.value("dns1").toString() == QLatin1String("1.1.1.1"));
        CHECK(root.value("dns2").toString() == QLatin1String("1.0.0.1"));
        CHECK(root.value("splitTunnelType").isDouble() && root.value("splitTunnelType").toInt() == 0);
        CHECK(root.value("config_version").toInt() == 0);
        CHECK(!root.contains("awg_config_data"));
        const QJsonObject inner = root.value("xray_config_data").toObject();
        CHECK(inner.value("config").isString());
        CHECK(inner.value("hostName").toString() == QLatin1String("38.180.164.134"));
        CHECK(inner.value("port").toInt() == 443);

        const QJsonObject core =
            QJsonDocument::fromJson(inner.value("config").toString().toUtf8()).object();
        CHECK(!core.isEmpty());
        CHECK(core.value("log").toObject().value("loglevel").toString() == QLatin1String("error"));
        const QJsonArray outbounds = core.value("outbounds").toArray();
        CHECK(outbounds.size() == 1);
        const QJsonObject ob = outbounds.at(0).toObject();
        CHECK(ob.value("protocol").toString() == QLatin1String("vless"));
        const QJsonArray vnext = ob.value("settings").toObject().value("vnext").toArray();
        CHECK(vnext.size() == 1);
        const QJsonObject v = vnext.at(0).toObject();
        CHECK(v.value("address").toString() == QLatin1String("38.180.164.134"));
        CHECK(v.value("port").isDouble() && v.value("port").toInt() == 443);
        const QJsonArray users = v.value("users").toArray();
        CHECK(users.size() == 1);
        const QJsonObject u = users.at(0).toObject();
        CHECK(u.value("id").toString() == QLatin1String(kValidUuid));
        CHECK(u.value("encryption").toString() == QLatin1String("none"));
        CHECK(u.value("flow").toString() == QLatin1String("xtls-rprx-vision"));
        const QJsonObject ss = ob.value("streamSettings").toObject();
        CHECK(ss.value("network").toString() == QLatin1String("tcp"));
        CHECK(ss.value("security").toString() == QLatin1String("reality"));
        const QJsonObject rs = ss.value("realitySettings").toObject();
        CHECK(rs.value("publicKey").toString() == QLatin1String(kValidPubKey));
        CHECK(rs.value("shortId").toString() == QLatin1String("a1b2c3d4"));
        CHECK(rs.value("serverName").toString() == QLatin1String("wavecom.ee"));
        CHECK(rs.value("fingerprint").toString() == QLatin1String("chrome"));
        CHECK(rs.contains("spiderX") && rs.value("spiderX").toString().isEmpty());
        const QJsonArray inbounds = core.value("inbounds").toArray();
        CHECK(inbounds.size() == 1);
        const QJsonObject ib = inbounds.at(0).toObject();
        CHECK(ib.value("listen").toString() == QLatin1String("127.0.0.1"));
        CHECK(ib.value("port").isDouble() && ib.value("port").toInt() == 10808);
        CHECK(ib.value("protocol").toString() == QLatin1String("socks"));
        CHECK(ib.value("settings").toObject().value("udp").toBool() == true);

        // flow пустой → ключа flow в users[0] нет (паттерн апстрима).
        SubscriptionNode noFlow = x;
        noFlow.xray->flow.clear();
        const QJsonObject core2 = XrayConfigBuilder::coreConfig(noFlow);
        const QJsonObject u2 = core2.value("outbounds").toArray().at(0).toObject().value("settings").toObject()
                                   .value("vnext").toArray().at(0).toObject().value("users").toArray().at(0).toObject();
        CHECK(!u2.contains("flow"));

        // dns пустой → дефолты 1.1.1.1/1.0.0.1 (как AwgConfigBuilder: iOS требует оба).
        SubscriptionNode noDns = x;
        noDns.dns.clear();
        const QJsonObject root2 = XrayConfigBuilder::build(sub, noDns, testKeys());
        CHECK(root2.value("dns1").toString() == QLatin1String("1.1.1.1"));
        CHECK(root2.value("dns2").toString() == QLatin1String("1.0.0.1"));

        // нода без xray-параметров → пустой конверт (вызывающий обязан проверить isEmpty).
        SubscriptionNode bare = x;
        bare.xray.reset();
        CHECK(XrayConfigBuilder::build(sub, bare, testKeys()).isEmpty());

        // --- 5) reportSummary: без uuid/publicKey/адреса; с фактами транспорта ---
        const QJsonObject rep = XrayConfigBuilder::reportSummary(sub, x);
        const QByteArray repText = QJsonDocument(rep).toJson(QJsonDocument::Compact);
        CHECK(!repText.contains(kValidUuid));
        CHECK(!repText.contains(kValidPubKey));
        CHECK(!repText.contains("38.180.164.134"));
        CHECK(!repText.contains("10.7.0.5"));
        CHECK(rep.value("proto").toString() == QLatin1String("xray"));
        CHECK(rep.value("port").toInt() == 443);
        CHECK(rep.value("security").toString() == QLatin1String("reality"));
        CHECK(rep.value("network").toString() == QLatin1String("tcp"));
        CHECK(rep.value("flow").toString() == QLatin1String("xtls-rprx-vision"));
        CHECK(rep.value("fingerprint").toString() == QLatin1String("chrome"));
        CHECK(rep.value("server_name").toString() == QLatin1String("wavecom.ee"));
        CHECK(rep.value("short_id_len").toInt() == 8);
        CHECK(rep.value("dns").toArray().size() == 2);
        CHECK(rep.value("transport_rank").toInt() == 20);
        CHECK(rep.value("host_id").toInt() == 9);
    }

    // --- 6) stripUnknownWgQuickKeys ---
    {
        const QString in = QStringLiteral(
            "[Interface]\n"
            "PrivateKey = abc=\n"
            "# comment line\n"
            "FooBar = 1\n"
            "Address = 10.7.0.5/32\n"
            "jc = 4\n"
            "RandomTrailers = 1\n"
            "DisableCookies = 0\n"
            "NewExperimentalKey = zzz\n"
            "\n"
            "[Peer]\n"
            "PublicKey = def=\n"
            "Junk = x\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "Endpoint = 1.2.3.4:51820\n"
            "PersistentKeepalive = 25\n");
        const QString expected = QStringLiteral(
            "[Interface]\n"
            "PrivateKey = abc=\n"
            "# comment line\n"
            "Address = 10.7.0.5/32\n"
            "jc = 4\n"
            "RandomTrailers = 1\n"
            "DisableCookies = 0\n"
            "\n"
            "[Peer]\n"
            "PublicKey = def=\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "Endpoint = 1.2.3.4:51820\n"
            "PersistentKeepalive = 25\n");
        const QString out = AwgConfigBuilder::stripUnknownWgQuickKeys(in, AwgConfigBuilder::awgAppleWgQuickKeys());
        CHECK(out == expected);
        if (out != expected)
            fprintf(stderr, "  strip out:\n%s\n", out.toUtf8().constData());
        // Пользовательский allowlist уважается (нижний регистр в наборе, сравнение без регистра).
        const QSet<QString> tiny{ QStringLiteral("privatekey"), QStringLiteral("publickey") };
        const QString tinyOut = AwgConfigBuilder::stripUnknownWgQuickKeys(in, tiny);
        CHECK(tinyOut.contains(QLatin1String("PrivateKey = abc=")) && tinyOut.contains(QLatin1String("PublicKey = def=")));
        CHECK(!tinyOut.contains(QLatin1String("Address")) && !tinyOut.contains(QLatin1String("Endpoint")));
        // Все 3.0/3.1 ключи awg-apple 3.1.4 — в наборе (иначе фильтр вырезал бы живой конфиг).
        const QSet<QString> &ap = AwgConfigBuilder::awgAppleWgQuickKeys();
        for (const char *k : { "headerprotectionkey", "contentpaddingaddition", "rekeyaftertime", "rekeytimeout",
                               "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts", "randomtrailers",
                               "disablecookies", "i1", "i5", "s3", "s4", "mtu", "dns", "presharedkey" })
            CHECK(ap.contains(QLatin1String(k)));
        // Пустой вход → пустой выход; без завершающего \n — не добавляем лишнего.
        CHECK(AwgConfigBuilder::stripUnknownWgQuickKeys(QString(), ap).isEmpty());
        CHECK(AwgConfigBuilder::stripUnknownWgQuickKeys(QStringLiteral("[Interface]\nJc = 1"), ap)
              == QStringLiteral("[Interface]\nJc = 1"));
    }

    if (g_failed) {
        fprintf(stderr, "xray_config_check: FAILED %d/%d\n", g_failed, g_total);
        return 1;
    }
    printf("xray_config_check: OK (%d checks — регресс awg, парсер xray_params/host_id/pool_revision, "
           "XrayConfigBuilder, reportSummary, stripUnknownWgQuickKeys)\n",
           g_total);
    return 0;
}
