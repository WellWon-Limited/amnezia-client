// AVPN (upstream nodes, release C, lane P1): the real ConfigService.cpp with the platform forced by
// -DAVPN_TEST_XRAY_PLATFORM (build_xray_platform_config.sh builds it for Apple, Android and Windows). The
// cached signed config at a cold start: on Apple the bounded trust of a signed xray_client / upstream_nodes
// = true is as before release C, whatever the new switches say; on Android/Windows the cached copy stays
// frozen exactly as before unless THEIR OWN signed switch is on and the runtime is present. No network: the
// service has no QNetworkAccessManager (every request is skipped).
#define AVPN_CONFIGSTORE_TEST
#include <QByteArray>
#include <QStringList>
namespace avpn {
static QByteArray cachedConfig;
static qint64 cachedConfigAtMs = 0;
class ConfigStore {
public:
    static QByteArray loadConfig() { return cachedConfig; }
    static void saveConfig(const QByteArray &body, qint64 receivedAtMs)
    {
        cachedConfig = body;
        cachedConfigAtMs = receivedAtMs;
    }
    static qint64 configReceivedAtMs() { return cachedConfigAtMs; }
    static QStringList loadEdges() { return {}; }
    static void saveEdges(const QStringList &) {}
    static QString activeEdge(const QString &value) { return value; }
    static void setActiveEdge(const QString &) {}
};
bool verifyDetached(const QString &, const QByteArray &, const QByteArray &sig)
{
    return sig == "fixture-signature";
}
} // namespace avpn
#include "../ConfigService.cpp"

#include <QCoreApplication>
#include <cstdio>

static int g_fail = 0, g_ok = 0;
static void check(bool ok, const char *what, const char *scenario)
{
    if (ok) {
        ++g_ok;
        return;
    }
    std::printf("FAIL %s [%s]\n", what, scenario);
    ++g_fail;
}

static constexpr qint64 kNowMs = 1763300000000LL;
static constexpr qint64 kHourMs = 3600LL * 1000;

struct Outcome {
    bool xrayClient = false;
    bool upstreamNodes = false;
    avpn::XrayPolicy policy = avpn::XrayPolicy::NoConfig;
};

static Outcome coldStart(const QByteArray &cached, bool runtimeReady)
{
    avpn::cachedConfig = cached;
    avpn::cachedConfigAtMs = kNowMs - kHourMs; // within both 72 h bounds
    avpn::xrayPlatformRuntimeReady().store(runtimeReady);
    avpn::ConfigService service(nullptr, QStringLiteral("http://127.0.0.1:9"), QStringLiteral("fixture-key"), {});
    service.setNowMsForTest([] { return kNowMs; });
    service.start();
    Outcome o;
    o.xrayClient = service.config().features.value(QStringLiteral("xray_client"), false);
    o.upstreamNodes = service.config().features.value(QStringLiteral("upstream_nodes"), false);
    o.policy = service.xrayPolicy();
    avpn::xrayPlatformRuntimeReady().store(true);
    return o;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    constexpr avpn::XrayPlatform p = avpn::xrayBuildPlatform();
    const bool apple = p == avpn::XrayPlatform::Apple;
    const char *ownKey = p == avpn::XrayPlatform::Android ? "xray_client_android" : "xray_client_windows";
    const char *otherKey = p == avpn::XrayPlatform::Android ? "xray_client_windows" : "xray_client_android";

    struct Scenario {
        const char *name;
        QByteArray body;
        bool runtime;
        bool trustedWanted; // the cached signed true is honoured (else frozen, as before release C)
    };
    const QByteArray base = R"("xray_client":true,"upstream_nodes":true)";
    const Scenario scenarios[] = {
        // Today's cached copy: no new switch at all.
        {"no new switch", "{\"features\":{" + base + "}}", true, apple},
        // The platform's own switch, runtime present: Android/Windows join; Apple unchanged.
        {"own switch on", "{\"features\":{" + base + ",\"" + ownKey + "\":true}}", true, true},
        // Own switch on but no runtime: Android/Windows stay frozen; Apple does not read the runtime here.
        {"own switch on, no runtime", "{\"features\":{" + base + ",\"" + ownKey + "\":true}}", false, apple},
        // Explicit false of the own switch = absent.
        {"own switch false", "{\"features\":{" + base + ",\"" + ownKey + "\":false}}", true, apple},
        // The other platform's switch never opens this one.
        {"other platform's switch", "{\"features\":{" + base + ",\"" + otherKey + "\":true}}", true, apple},
    };
    for (const Scenario &s : scenarios) {
        const Outcome o = coldStart(s.body, s.runtime);
        check(o.xrayClient == s.trustedWanted, "xray_client", s.name);
        check(o.upstreamNodes == s.trustedWanted, "upstream_nodes", s.name);
        check((o.policy == avpn::XrayPolicy::CacheTrusted) == s.trustedWanted, "policy", s.name);
    }
    // A signed false stays false everywhere (the gate only narrows).
    {
        const Outcome o = coldStart("{\"features\":{\"xray_client\":false,\"" + QByteArray(ownKey) + "\":true}}", true);
        check(!o.xrayClient && !o.upstreamNodes, "signed false stays false", "xray_client false");
    }
    const char *name = apple ? "Apple" : (p == avpn::XrayPlatform::Android ? "Android" : "Windows");
    std::printf("xray_platform_config_check [%s]: %d ok, %d failed\n", name, g_ok, g_fail);
    return g_fail == 0 ? 0 : 1;
}
