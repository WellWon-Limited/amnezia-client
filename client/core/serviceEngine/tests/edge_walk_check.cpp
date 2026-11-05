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
    return g_fail ? 1 : 0;
}
