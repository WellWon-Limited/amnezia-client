// client/core/serviceEngine/tests/config_parse_check.cpp
// AVPN: форвард-совместимый парсер /v1/config.
#include "../ConfigTypes.h"
#include <QCoreApplication>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, msg) do { if (cond) printf("OK   %s\n", msg); \
    else { printf("FAIL %s\n", msg); ++g_fail; } } while (0)

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    // Полный ответ + НЕИЗВЕСТНОЕ поле "future_thing" — должно игнорироваться.
    const QByteArray full = R"({
        "min_app_version": {"ios":"5.1.0","android":"5.1.0"},
        "recommended_version": {"ios":"5.2.0"},
        "probe_targets": [{"target":"telegram","kind":"tcp","host":"web.telegram.org","port":443,"interval_s":60}],
        "subscription_refresh_interval_s": 43200,
        "edges": ["https://api.tribevpn.com","https://vpn.wellwon.hk"],
        "features": {"support_chat": true, "xray": false},
        "urls": {"cabinet":"https://tribevpn.com/account"},
        "numbers": {"edge_fail_threshold": 3},
        "lists": {"bench_http_ru": ["https://ya.ru"]},
        "future_thing": {"nested": [1,2,3]}
    })";
    avpn::RemoteConfig c;
    QString err;
    CHECK(avpn::parseConfig(full, c, err), "full parses");
    CHECK(c.valid, "valid flag set");
    CHECK(c.minAppVersion.value("ios") == "5.1.0", "min ios");
    CHECK(c.recommendedVersion.value("ios") == "5.2.0", "recommended ios");
    CHECK(c.probeTargets.size() == 1 && c.probeTargets[0].host == "web.telegram.org", "probe host");
    CHECK(c.probeTargets[0].port == 443 && c.probeTargets[0].intervalS == 60, "probe port/interval");
    CHECK(c.edges.size() == 2 && c.edges[1] == "https://vpn.wellwon.hk", "edges");
    CHECK(avpn::featureFlag(c, "support_chat", false) == true, "feature true");
    CHECK(avpn::featureFlag(c, "xray", true) == false, "feature false overrides default");
    CHECK(avpn::featureFlag(c, "missing", true) == true, "missing feature => default");
    CHECK(c.urls.value("cabinet") == "https://tribevpn.com/account", "url cabinet");
    CHECK(avpn::numberOr(c, "edge_fail_threshold", 99) == 3, "number");
    CHECK(avpn::numberOr(c, "missing", 7) == 7, "missing number => default");
    CHECK(c.lists.value("bench_http_ru") == QStringList{"https://ya.ru"}, "lists bench_http_ru");

    // Отсутствующие поля => дефолты, не крэш.
    avpn::RemoteConfig c2; QString err2;
    CHECK(avpn::parseConfig(R"({"min_app_version":{"ios":"1.0.0"}})", c2, err2), "minimal parses");
    CHECK(c2.subscriptionRefreshIntervalS == 43200, "refresh default when absent");
    CHECK(c2.edges.isEmpty(), "edges empty when absent");
    CHECK(c2.lists.isEmpty(), "lists empty when absent");

    // Битый JSON => false, valid=false.
    avpn::RemoteConfig c3; QString err3;
    CHECK(!avpn::parseConfig("{not json", c3, err3), "broken json => false");
    CHECK(!c3.valid && !err3.isEmpty(), "broken json sets err");

    // Поля с неверным типом => скипаются, дефолты остаются (type-guards).
    const QByteArray wrongTyped = R"({
        "features": {"support_chat": "yes"},
        "numbers": {"x": "nan"},
        "edges": [123, "https://ok"],
        "probe_targets": [{"target":"t","host":123}],
        "lists": {"bench_http_ru": ["https://ya.ru", 123, true, null]}
    })";
    avpn::RemoteConfig c4; QString err4;
    CHECK(avpn::parseConfig(wrongTyped, c4, err4), "wrong-typed fields still parse");
    CHECK(avpn::featureFlag(c4, "support_chat", false) == false, "string feature ignored => default");
    CHECK(avpn::numberOr(c4, "x", 7) == 7, "string number ignored => default");
    CHECK(c4.edges.size() == 1 && c4.edges[0] == "https://ok", "non-string edge skipped");
    CHECK(c4.probeTargets.isEmpty(), "probe target with non-string host skipped");
    CHECK(c4.lists.value("bench_http_ru") == QStringList{"https://ya.ru"}, "lists non-string entries dropped");

    // Идемпотентность: повторный parseConfig в ТОТ ЖЕ struct не оставляет стейл.
    avpn::RemoteConfig c5; QString err5;
    CHECK(avpn::parseConfig(full, c5, err5), "reuse: first parse ok");
    CHECK(avpn::parseConfig(R"({"edges":["https://only.one"]})", c5, err5), "reuse: second parse ok");
    CHECK(c5.edges.size() == 1 && c5.edges[0] == "https://only.one", "reuse: edges not accumulated");
    CHECK(c5.probeTargets.isEmpty(), "reuse: stale probe targets gone");
    CHECK(c5.features.isEmpty(), "reuse: stale features gone");
    CHECK(c5.lists.isEmpty(), "reuse: stale lists gone");
    CHECK(avpn::featureFlag(c5, "support_chat", false) == false, "reuse: stale flag => default");
    // Битый JSON поверх валидного => struct очищен, не полу-валиден.
    CHECK(!avpn::parseConfig("{not json", c5, err5), "reuse: broken json => false");
    CHECK(!c5.valid && c5.edges.isEmpty(), "reuse: broken json clears struct");

    printf(g_fail ? "\n%d FAIL\n" : "\nALL OK\n", g_fail);
    return g_fail ? 1 : 0;
}
