// AVPN: version-compare для force-update (без Settings — чистая функция).
#include "../ConfigStore.h"
#include <QCoreApplication>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, msg) do { if (cond) printf("OK   %s\n", msg); \
    else { printf("FAIL %s\n", msg); ++g_fail; } } while (0)

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    using V = avpn::UpdateVerdict;
    // ниже min => Block
    CHECK(avpn::compareVersions("5.0.0", "5.1.0", "5.2.0") == V::Block, "below min => block");
    // между min и recommended => Recommend
    CHECK(avpn::compareVersions("5.1.5", "5.1.0", "5.2.0") == V::Recommend, "below rec => recommend");
    // app == min (ниже rec) => Recommend, НЕ Block (граница минимума не блокирует)
    CHECK(avpn::compareVersions("5.1.0", "5.1.0", "5.2.0") == V::Recommend, "app==min (below rec) => recommend not block");
    // >= recommended => Ok
    CHECK(avpn::compareVersions("5.2.0", "5.1.0", "5.2.0") == V::Ok, "at rec => ok");
    CHECK(avpn::compareVersions("5.2.0", "5.1.0", "5.2.0") == V::Ok, "app==rec => ok");
    CHECK(avpn::compareVersions("5.3.1", "5.1.0", "5.2.0") == V::Ok, "above rec => ok");
    // пустые пороги => Ok (сервер не прислал floor для платформы)
    CHECK(avpn::compareVersions("5.1.0", "", "") == V::Ok, "empty thresholds => ok");
    CHECK(avpn::compareVersions("5.1.0", "0.0.0", "0.0.0") == V::Ok, "zero thresholds => ok");
    // 4-компонентная версия форка (5.1.43.69) сравнивается корректно
    CHECK(avpn::compareVersions("5.1.43.69", "5.1.44.0", "5.1.45.0") == V::Block, "4-part below min");

    printf(g_fail ? "\n%d FAIL\n" : "\nALL OK\n", g_fail);
    return g_fail ? 1 : 0;
}
