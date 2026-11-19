// client/core/serviceEngine/tests/edge_walk_check.cpp
#include "../EdgeWalk.h"
#include <QCoreApplication>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, msg) do { if (cond) printf("OK   %s\n", msg); \
    else { printf("FAIL %s\n", msg); ++g_fail; } } while (0)

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QStringList e{"https://a", "https://b", "https://c"};
    CHECK(avpn::nextEdge(e, "https://a") == "https://b", "a->b");
    CHECK(avpn::nextEdge(e, "https://c") == "https://a", "c wraps to a");
    CHECK(avpn::nextEdge(e, "https://x") == "https://a", "unknown => first");
    CHECK(avpn::nextEdge({"https://only"}, "https://only") == "https://only", "single stays");
    CHECK(avpn::nextEdge({}, "https://a") == "https://a", "empty keeps current");

    const QStringList baked{"https://api.tribevpn.com", "https://vpn.wellwon.hk"};
    CHECK(avpn::edgeCandidates({}, baked) == baked, "empty cached => baked");
    const QStringList cached{"https://vpn.wellwon.hk", "https://api.tribevpn.com"};
    CHECK(avpn::edgeCandidates(cached, baked).contains("https://api.tribevpn.com"),
          "primary present after cached");
    // дедуп
    const QStringList dup{"https://a", "https://a", "https://b"};
    CHECK(avpn::edgeCandidates(dup, baked).size() == 3, "dedup cached + primary");

    // AVPN (разбор 2026-09-23): хосты ВСЕХ кандидатов резолвятся в carve-out заранее — смена edge
    // не требует перезапуска туннеля (tests/check_edge_switch_no_restart.sh).
    const QStringList hosts = avpn::edgeHosts({"https://api.tribevpn.com", "https://api.tribevpn.com/",
                                               "https://vpn.wellwon.hk:443/v1", "https://159.194.214.36",
                                               "", "not a url"});
    CHECK(hosts == QStringList({"api.tribevpn.com", "vpn.wellwon.hk", "159.194.214.36"}),
          "edgeHosts: unique hosts, literal IP kept, junk dropped");
    CHECK(avpn::edgeHosts({}).isEmpty(), "edgeHosts: empty list");

    // Decision 2026-11-05: per-edge /v1/subscription streak (small calls never reach it).
    {
        const QString a = "https://vpn.wellwon.hk", b = "https://api.tribevpn.com";
        avpn::SubscriptionEdgeStreak st;
        CHECK(!st.note(a, a, true), "subscription streak: 1st failure on the active edge -> stay");
        CHECK(st.note(a, a, true), "subscription streak: 2nd failure in a row -> switch");
        CHECK(!st.note(a, a, true), "subscription streak: counting restarts after a switch signal");
        avpn::SubscriptionEdgeStreak mixed;
        CHECK(!mixed.note(a, a, true) && !mixed.note(a, a, false) && !mixed.note(a, a, true),
              "subscription streak: failure, delivered, failure -> stay (delivered resets)");
        CHECK(mixed.note(a, a, true), "subscription streak: then a 2nd failure in a row -> switch");
        avpn::SubscriptionEdgeStreak other;
        CHECK(!other.note(b, a, true) && !other.note(b, a, true),
              "subscription streak: failures of requests sent to another edge do not count");
        CHECK(!other.note(b, b, true) && other.note(b, b, true), "subscription streak: the new edge counts from 0");
        avpn::SubscriptionEdgeStreak moved;
        CHECK(!moved.note(a, a, true), "subscription streak: one failure on a");
        CHECK(!moved.note(b, b, true), "subscription streak: active edge changed -> the old count is gone");
    }

    printf(g_fail ? "\n%d FAIL\n" : "\nALL OK\n", g_fail);
    // R1a (device round 4): the edge is a function of the route a request takes, evaluated per request.
    {
        using avpn::ApiRoute;
        const QString hk = QStringLiteral("https://vpn.wellwon.hk");
        // a provider session just ended (the tunnel reports down): direct -> the walk's direct edge (Russian entry)
        CHECK(avpn::apiRouteNow(false, true) == ApiRoute::Direct, "session ended -> direct");
        CHECK(avpn::apiSessionEdgeFor(ApiRoute::Direct, false, hk).isEmpty(), "direct -> the Russian entry");
        // during a session (connected or being checked): through the tunnel -> the edge reachable from abroad
        CHECK(avpn::apiRouteNow(true, true) == ApiRoute::Tunnel, "carrying tunnel -> tunnel");
        CHECK(avpn::apiSessionEdgeFor(ApiRoute::Tunnel, false, hk) == hk, "through the tunnel -> the foreign edge");
        // a leg being brought up while the old tunnel still reports up: its seat request is direct
        CHECK(avpn::apiRouteNow(true, false) == ApiRoute::Direct, "leg being brought up -> direct");
        // a pinned dev backend keeps its base
        CHECK(avpn::apiSessionEdgeFor(ApiRoute::Tunnel, true, hk).isEmpty(), "pinned dev backend -> its own base");
    }
    {
        // R9: the pause between unsuccessful rounds grows and is capped
        CHECK(avpn::edgeRoundPauseMs(1) == 10000, "round 1: 10 s");
        CHECK(avpn::edgeRoundPauseMs(2) == 20000, "round 2: 20 s");
        CHECK(avpn::edgeRoundPauseMs(4) == 80000, "round 4: 80 s");
        CHECK(avpn::edgeRoundPauseMs(5) == 120000, "round 5: capped");
        CHECK(avpn::edgeRoundPauseMs(1000) == 120000, "a huge round number stays capped");
        CHECK(avpn::edgeRoundPauseMs(0) == 10000, "round 0 is treated as 1");
        CHECK(avpn::edgeRoundPauseMs(3, 100, 400) == 400, "server numbers: base 100, cap 400");
        CHECK(avpn::edgeRoundPauseMs(1, 500, 100) == 500, "a cap below the base never shortens the base");
    }
    return g_fail ? 1 : 0;
}
