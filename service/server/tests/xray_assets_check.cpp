// AVPN service/server: unit check of xrayassets.h (geo data only from the service's own directory).
// Build and run: service/server/tests/build_xray_assets.sh
#include "../xrayassets.h"

#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#include <cstdio>

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

static void touch(const QString &path)
{
    QFile f(path);
    if (f.open(QIODevice::WriteOnly))
        f.write("x");
}

int main()
{
    using avpn::xrayAssetFiles;
    using avpn::xrayMissingAssets;

    // 1. A config without geo rules needs no files (own-node Xray keeps working without the pair).
    const QString plain = QStringLiteral(
        R"({"routing":{"rules":[{"ip":["10.0.0.0/8"],"outboundTag":"direct"},)"
        R"({"domain":["domain:example.com","full:geoipless.test"],"outboundTag":"proxy"}]}})");
    CHECK(xrayAssetFiles(plain).isEmpty());

    // 2. geosite:/geoip: (also negated, also inside dns) map to the two file names.
    const QString geo = QStringLiteral(
        R"({"dns":{"servers":[{"address":"1.1.1.1","domains":["geosite:category-ru"]}]},)"
        R"("routing":{"rules":[{"ip":["geoip:private","!geoip:ru"],"outboundTag":"direct"}]}})");
    CHECK(xrayAssetFiles(geo) == QStringList({QStringLiteral("geoip.dat"), QStringLiteral("geosite.dat")}));

    // 3. ext:<file>:<code> and its typed forms name their own files.
    const QString ext = QStringLiteral(
        R"({"routing":{"rules":[{"domain":["ext:custom.dat:ads","ext-domain:geosite.dat:youtube"]},)"
        R"({"ip":["ext-ip:geoip.dat:ru"]}]}})");
    CHECK(xrayAssetFiles(ext)
          == QStringList({QStringLiteral("custom.dat"), QStringLiteral("geoip.dat"), QStringLiteral("geosite.dat")}));

    // 4. Words that merely contain the prefix are not rules.
    CHECK(xrayAssetFiles(QStringLiteral(R"({"tag":"mygeoip:x","remarks":"next:door:"})")).isEmpty());

    QTemporaryDir dir;
    CHECK(dir.isValid());
    // 5. Missing pair -> both reported; config without geo -> nothing missing.
    CHECK(xrayMissingAssets(geo, dir.path())
          == QStringList({QStringLiteral("geoip.dat"), QStringLiteral("geosite.dat")}));
    CHECK(xrayMissingAssets(plain, dir.path()).isEmpty());

    // 6. One file present -> only the other is missing; both present -> none.
    touch(QDir(dir.path()).filePath(QStringLiteral("geosite.dat")));
    CHECK(xrayMissingAssets(geo, dir.path()) == QStringList({QStringLiteral("geoip.dat")}));
    touch(QDir(dir.path()).filePath(QStringLiteral("geoip.dat")));
    CHECK(xrayMissingAssets(geo, dir.path()).isEmpty());

    // 7. A directory with the file's name is not a file; a path is never accepted.
    QDir(dir.path()).mkdir(QStringLiteral("custom.dat"));
    CHECK(xrayMissingAssets(ext, dir.path()) == QStringList({QStringLiteral("custom.dat")}));
    CHECK(xrayMissingAssets(QStringLiteral(R"(["ext:../geoip.dat:ru"])"), dir.path())
          == QStringList({QStringLiteral("../geoip.dat")}));

    printf("xray_assets_check: %d/%d passed\n", g_total - g_failed, g_total);
    return g_failed == 0 ? 0 : 1;
}
