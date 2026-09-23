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

    printf(g_fail ? "\n%d FAIL\n" : "\nALL OK\n", g_fail);
    return g_fail ? 1 : 0;
}
