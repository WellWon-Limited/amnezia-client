// AVPN «Доступ к сайтам РФ» (owner 26.11.2026, AND-67): the route budget (RouteBudget.h), the cut of the split list to it
// (RouteReduce.h) and the Android app layer's list -> config mapping (RuApps.h). Build/run: tests/build_route_budget.sh.
// `route_budget_check --table` prints the coverage of the compiled RU list per budget (ANDROID-DEFECTS.md).
#include "../RouteBudget.h"
#include "../RouteReduce.h"
#include "../RuApps.h"
#include "../ru_prefixes.h"

#include <QCoreApplication>
#include <QSet>
#include <cstdio>
#include <cstring>

using namespace avpn;

static int g_fail = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                            \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

static void budget()
{
    const std::optional<double> none;
    const std::optional<int> noDev;
    // off Android and Android 12 and lower: unlimited whatever the server or a developer file says
    for (const int sdk : {0, 99})
        CHECK(bypassRouteBudget(false, sdk, 1500.0, 700) == kRouteBudgetUnlimited);
    for (const int sdk : {28, 31, 32})
        CHECK(bypassRouteBudget(true, sdk, 1500.0, 700) == kRouteBudgetUnlimited);
    // Android 13+: the compiled N, overridden by the server number, overridden by the developer file
    for (const int sdk : {33, 36}) {
        CHECK(bypassRouteBudget(true, sdk, none, noDev) == kAndroidBypassRouteBudget);
        CHECK(bypassRouteBudget(true, sdk, 500.0, noDev) == 500);
        CHECK(bypassRouteBudget(true, sdk, 500.0, 700) == 700);
        CHECK(bypassRouteBudget(true, sdk, none, 0) == 0);
        // the ceiling (the service's own guard): a larger server or developer value is the ceiling, never more
        CHECK(bypassRouteBudget(true, sdk, 1500.0, noDev) == kAndroidSplitRouteCeiling);
        CHECK(bypassRouteBudget(true, sdk, 1e9, noDev) == kAndroidSplitRouteCeiling);
        CHECK(bypassRouteBudget(true, sdk, none, 50000) == kAndroidSplitRouteCeiling);
        // negative or non-finite = the compiled default: never "unlimited" (-1 is the code's own word) and never 0
        CHECK(bypassRouteBudget(true, sdk, -1.0, noDev) == kAndroidBypassRouteBudget);
        CHECK(bypassRouteBudget(true, sdk, -5.0, noDev) == kAndroidBypassRouteBudget);
        CHECK(bypassRouteBudget(true, sdk, std::nan(""), noDev) == kAndroidBypassRouteBudget);
        CHECK(bypassRouteBudget(true, sdk, INFINITY, noDev) == kAndroidBypassRouteBudget);
        CHECK(bypassRouteBudget(true, sdk, none, -1) == kAndroidBypassRouteBudget);
        CHECK(bypassRouteBudget(true, sdk, 500.7, noDev) == 500);
    }
    CHECK(kRouteBudgetNumberKey == QStringLiteral("android_bypass_route_budget"));
    CHECK(kAndroidBypassRouteBudget >= 0 && kAndroidBypassRouteBudget <= kAndroidSplitRouteCeiling);
    // where the mode's sites go directly (TribeEngine.bypassSitesDirect = budget != 0): not only on Android 13+ at N = 0
    for (const int sdk : {33, 36})
        CHECK((bypassRouteBudget(true, sdk, std::nullopt, std::nullopt) != 0) == (kAndroidBypassRouteBudget != 0));
    CHECK(bypassRouteBudget(true, 33, std::nullopt, 0) == 0);
    CHECK(bypassRouteBudget(true, 32, std::nullopt, 0) != 0); // Android 12 and lower: today's routes
    CHECK(bypassRouteBudget(false, 0, std::nullopt, 0) != 0); // iOS, macOS, Windows: untouched
    // the host is not Android: unlimited here
    CHECK(bypassRouteBudgetHere() == kRouteBudgetUnlimited);
    RouteBudgetInputs::setServer(10.0);
    RouteBudgetInputs::setDev(3);
    CHECK(bypassRouteBudgetHere() == kRouteBudgetUnlimited);
    RouteBudgetInputs::setServer(std::nullopt);
    RouteBudgetInputs::setDev(std::nullopt);
    CHECK(!RouteBudgetInputs::serverValue().has_value() && !RouteBudgetInputs::devValue().has_value());
}

static QSet<QString> set(const QStringList &l)
{
    return QSet<QString>(l.cbegin(), l.cend());
}

// every address of `a` is in `b`, by the merged prefixes (containment)
static bool covered(const QStringList &a, const QStringList &b)
{
    const std::vector<RoutePrefix> mb = mergeRoutePrefixes(b);
    for (const RoutePrefix &p : mergeRoutePrefixes(a)) {
        bool in = false;
        for (const RoutePrefix &q : mb)
            in = in || routes_detail::contains(q, p);
        if (!in)
            return false;
    }
    return true;
}

static void merge()
{
    // siblings join, duplicates and nested ones go, host bits are cleared - the same addresses
    const QStringList in = {QStringLiteral("10.0.0.0/25"), QStringLiteral("10.0.0.128/26"), QStringLiteral("10.0.0.192/26"),
                            QStringLiteral("10.0.0.200/32"), QStringLiteral("10.0.0.0/25"), QStringLiteral("10.0.1.7/24"),
                            QStringLiteral("192.168.0.0/24"), QStringLiteral("2a00:1fa0::/30"),
                            QStringLiteral("2a00:1fa4::/30"), QStringLiteral("2a00:1fa0::1/128")};
    const std::vector<RoutePrefix> m = mergeRoutePrefixes(in);
    QStringList out;
    for (const RoutePrefix &p : m)
        out << formatRoutePrefix(p);
    CHECK(out == (QStringList{QStringLiteral("10.0.0.0/23"), QStringLiteral("192.168.0.0/24"),
                              QStringLiteral("2a00:1fa0::/29")}));
    // nothing added, nothing lost
    CHECK(covered(in, out) && covered(out, in));
    const RouteCoverage a = routeCoverage(in), b = routeCoverage(out);
    CHECK(a.v4 == b.v4 && a.v6 == b.v6);
    CHECK(a.v4 == 512 + 256);
    // a hole stays a hole: the carve-out's pieces around one /32 never re-join over it
    const QStringList holed = {QStringLiteral("10.0.0.0/25"), QStringLiteral("10.0.0.128/26"),
                               QStringLiteral("10.0.0.192/27"), QStringLiteral("10.0.0.224/28"),
                               QStringLiteral("10.0.0.240/29"), QStringLiteral("10.0.0.248/30"),
                               QStringLiteral("10.0.0.252/31"), QStringLiteral("10.0.0.255/32")}; // no 10.0.0.254
    QStringList ho;
    for (const RoutePrefix &p : mergeRoutePrefixes(holed))
        ho << formatRoutePrefix(p);
    CHECK(set(ho) == set(holed));
    CHECK(!covered({QStringLiteral("10.0.0.254/32")}, ho));
    // the compiled RU list: the merge loses nothing and adds nothing
    const QStringList ru = ruPrefixes();
    QStringList ruMerged;
    for (const RoutePrefix &p : mergeRoutePrefixes(ru))
        ruMerged << formatRoutePrefix(p);
    const RouteCoverage c1 = routeCoverage(ru), c2 = routeCoverage(ruMerged);
    CHECK(c1.v4 == c2.v4 && c1.v6 == c2.v6);
    CHECK(ruMerged.size() <= ru.size());
}

static void cut()
{
    // rule 1: unlimited, or the list fits -> the input exactly (not even re-written)
    const QStringList in = {QStringLiteral("10.0.0.0/25"), QStringLiteral("10.0.0.128/25"), QStringLiteral("1.2.3.0/24"),
                            QStringLiteral("5.0.0.0/16"), QStringLiteral("6.0.0.0/20"), QStringLiteral("2a00::/32")};
    RouteReduction r = reduceRoutes(in, kRouteBudgetUnlimited);
    CHECK(r.routes == in && !r.changed && r.total == 6);
    r = reduceRoutes(in, 6);
    CHECK(r.routes == in && !r.changed);
    r = reduceRoutes(in, 100);
    CHECK(r.routes == in && !r.changed);
    // rule 2: the merge is enough (10.0.0.0/25 + /25 -> /24)
    r = reduceRoutes(in, 5);
    CHECK(r.changed && r.routes.size() == 5 && r.merged == 5);
    CHECK(r.routes.contains(QStringLiteral("10.0.0.0/24")));
    CHECK(covered(r.routes, in) && covered(in, r.routes));
    // rule 3: IPv4 first, the largest first; a subset, never widened
    r = reduceRoutes(in, 3);
    CHECK(r.routes.size() == 3);
    CHECK(covered(r.routes, in)); // nothing outside the input
    // ties (two /24s): the lower address first
    CHECK(set(r.routes) == set({QStringLiteral("5.0.0.0/16"), QStringLiteral("6.0.0.0/20"), QStringLiteral("1.2.3.0/24")}));
    r = reduceRoutes(in, 4);
    CHECK(set(r.routes) == set({QStringLiteral("5.0.0.0/16"), QStringLiteral("6.0.0.0/20"), QStringLiteral("1.2.3.0/24"),
                                QStringLiteral("10.0.0.0/24")}));
    // IPv6 takes what IPv4 leaves
    CHECK(reduceRoutes(in, 5).routes.contains(QStringLiteral("2a00::/32")));
    CHECK(!reduceRoutes(in, 4).routes.contains(QStringLiteral("2a00::/32")));
    // the order of the result is by family and address, whatever the order given
    QStringList shuffled = in;
    std::reverse(shuffled.begin(), shuffled.end());
    CHECK(reduceRoutes(shuffled, 4).routes == r.routes);
    // the priority hook (empty in the app today): entries overlapping it go first, in its order
    r = reduceRoutes(in, 2, {QStringLiteral("10.0.0.0/8"), QStringLiteral("1.2.3.4/32")});
    CHECK(set(r.routes) == set({QStringLiteral("10.0.0.0/24"), QStringLiteral("1.2.3.0/24")}));
    // N = 0: nothing (the engine never gets here: 0 = the mode is unavailable, BypassMaster.h)
    r = reduceRoutes(in, 0);
    CHECK(r.routes.isEmpty() && r.changed);
    // an unparsable entry is kept as it is and counted
    r = reduceRoutes({QStringLiteral("junk"), QStringLiteral("5.0.0.0/16"), QStringLiteral("6.0.0.0/16")}, 2);
    CHECK(r.routes.contains(QStringLiteral("junk")) && r.routes.size() == 2);
    // the compiled RU list at a budget: exactly N entries, all inside the list
    const QStringList ru = ruPrefixes();
    for (const int n : {500, 1500, 5000}) {
        const RouteReduction rr = reduceRoutes(ru, n);
        CHECK(rr.routes.size() == n);
        CHECK(rr.total == ru.size());
        CHECK(covered(rr.routes, ru));
    }
    CHECK(reduceRoutes(ru, int(ru.size())).routes == ru); // N >= count: identity
}

static void apps()
{
    const QStringList listed = {QStringLiteral("ru.sberbankmobile"), QStringLiteral("com.android.chrome"),
                                QStringLiteral("com.tribevpn.client"), QStringLiteral("ru.ozon.app.android"),
                                QStringLiteral("ru.sberbankmobile"), QStringLiteral(" com.wildberries.ru ")};
    const QStringList never = {QStringLiteral("com.android.chrome"), QStringLiteral("org.mozilla.firefox")};
    // the mode off: no app excluded, exactly as before
    CHECK(bypassAppsForConfig(false, listed, never, kTribeAndroidPackage).isEmpty());
    // on: the listed ones without browsers and without our own package, once each, sorted
    const QStringList on = bypassAppsForConfig(true, listed, never, kTribeAndroidPackage);
    CHECK(on == (QStringList{QStringLiteral("com.wildberries.ru"), QStringLiteral("ru.ozon.app.android"),
                             QStringLiteral("ru.sberbankmobile")}));
    QStringList reversed = listed;
    std::reverse(reversed.begin(), reversed.end());
    CHECK(bypassAppsForConfig(true, reversed, never, kTribeAndroidPackage) == on); // order stable
    // the compiled list: sorted, no browser of the never-list, never our own package
    const QStringList compiled = ruAppPackages(), compiledNever = ruAppNever();
    QStringList sorted = compiled;
    sorted.sort();
    CHECK(!compiled.isEmpty() && compiled == sorted);
    CHECK(!compiled.contains(kTribeAndroidPackage));
    for (const QString &b : compiledNever)
        CHECK(!compiled.contains(b));
    CHECK(compiledNever.contains(QStringLiteral("com.android.chrome")));
    CHECK(bypassAppsForConfig(true, compiled, compiledNever, kTribeAndroidPackage) == compiled);
}

static void table()
{
    const QStringList ru = ruPrefixes();
    const RouteCoverage all = routeCoverage(ru);
    const int merged = int(mergeRoutePrefixes(ru).size());
    std::printf("compiled RU list (ru_prefixes.h): %d prefixes, after the lossless merge %d\n", int(ru.size()), merged);
    std::printf("| N | routes | RU IPv4 addresses kept | IPv4 share | IPv6 share |\n|---|---|---|---|---|\n");
    for (const int n : {500, 1000, 1500, 2000, 3000, 5000}) {
        const RouteReduction r = reduceRoutes(ru, n);
        const RouteCoverage c = routeCoverage(r.routes);
        std::printf("| %d | %d | %.0f of %.0f | %.1f%% | %.1f%% |\n", n, int(r.routes.size()), c.v4, all.v4,
                    100.0 * c.v4 / all.v4, all.v6 > 0 ? 100.0 * c.v6 / all.v6 : 0.0);
    }
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (argc > 1 && std::strcmp(argv[1], "--table") == 0) {
        table();
        return 0;
    }
    budget();
    merge();
    cut();
    apps();
    if (g_fail == 0)
        std::printf("route_budget_check: OK\n");
    return g_fail == 0 ? 0 : 1;
}
