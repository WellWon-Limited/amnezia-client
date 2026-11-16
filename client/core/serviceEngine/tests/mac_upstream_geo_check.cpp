// AVPN: unit check of MacUpstreamGeo.h (upstream nodes, macOS: the cut geo pair next to the service).
// Build and run: client/core/serviceEngine/tests/build_mac_upstream_geo.sh
#include "../MacUpstreamGeo.h"

#include <QCryptographicHash>
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

static QByteArray put(const QString &dir, const QString &name, const QByteArray &data)
{
    QFile f(QDir(dir).filePath(name));
    if (f.open(QIODevice::WriteOnly))
        f.write(data);
    return QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex();
}

int main()
{
    using avpn::upstreamGeoPresentAt;
    using avpn::upstreamGeoPresentIn;

    QTemporaryDir svc;
    CHECK(svc.isValid());
    const QByteArray ip = put(svc.path(), QStringLiteral("geoip.dat"), QByteArray(4096, 'i'));
    const QByteArray site = put(svc.path(), QStringLiteral("geosite.dat"), QByteArray(2048, 's'));
    const QByteArray sums = ip + "  geoip.dat\n" + site + "  geosite.dat\n";

    // 1. Both files present with the manifest's hashes.
    CHECK(upstreamGeoPresentIn(svc.path(), sums));
    // shasum's binary marker and upper-case hex are accepted; order does not matter.
    CHECK(upstreamGeoPresentIn(svc.path(), site.toUpper() + " *geosite.dat\n" + ip + "  geoip.dat"));

    // 2. Manifest problems: empty, one file only, an extra file, a duplicate, a malformed line.
    CHECK(!upstreamGeoPresentIn(svc.path(), QByteArray()));
    CHECK(!upstreamGeoPresentIn(svc.path(), ip + "  geoip.dat\n"));
    CHECK(!upstreamGeoPresentIn(svc.path(), sums + ip + "  other.dat\n"));
    CHECK(!upstreamGeoPresentIn(svc.path(), sums + ip + "  geoip.dat\n"));
    CHECK(!upstreamGeoPresentIn(svc.path(), "abc  geoip.dat\n" + site + "  geosite.dat\n"));
    CHECK(!upstreamGeoPresentIn(svc.path(), QByteArray(64, 'z') + "  geoip.dat\n" + site + "  geosite.dat\n"));

    // 3. Another directory (no files) -> false.
    QTemporaryDir empty;
    CHECK(!upstreamGeoPresentIn(empty.path(), sums));

    // 4. Changed content (other data release) -> false; restored -> true.
    put(svc.path(), QStringLiteral("geosite.dat"), QByteArray(2048, 'S'));
    CHECK(!upstreamGeoPresentIn(svc.path(), sums));
    put(svc.path(), QStringLiteral("geosite.dat"), QByteArray(2048, 's'));
    CHECK(upstreamGeoPresentIn(svc.path(), sums));

    // 5. Missing file -> false.
    QFile::remove(QDir(svc.path()).filePath(QStringLiteral("geoip.dat")));
    CHECK(!upstreamGeoPresentIn(svc.path(), sums));
    put(svc.path(), QStringLiteral("geoip.dat"), QByteArray(4096, 'i'));

    // 6. A symlink in place of a file -> false (the installer always writes regular files).
    QTemporaryDir other;
    put(other.path(), QStringLiteral("geoip.dat"), QByteArray(4096, 'i'));
    QFile::remove(QDir(svc.path()).filePath(QStringLiteral("geoip.dat")));
    CHECK(QFile::link(QDir(other.path()).filePath(QStringLiteral("geoip.dat")),
                      QDir(svc.path()).filePath(QStringLiteral("geoip.dat"))));
    CHECK(!upstreamGeoPresentIn(svc.path(), sums));
    QFile::remove(QDir(svc.path()).filePath(QStringLiteral("geoip.dat")));
    put(svc.path(), QStringLiteral("geoip.dat"), QByteArray(4096, 'i'));

    // 7. File-based entry point: missing manifest file -> false; present -> true.
    CHECK(!upstreamGeoPresentAt(svc.path(), QDir(other.path()).filePath(QStringLiteral("none.sha256"))));
    QFile m(QDir(other.path()).filePath(QStringLiteral("tribe-svc-geo.sha256")));
    if (m.open(QIODevice::WriteOnly)) {
        m.write(sums);
        m.close();
    }
    CHECK(upstreamGeoPresentAt(svc.path(), m.fileName()));

    // 8. The real artifact when given: GEO_DIR=<tribe-xray-geo package>/geo.
    const QByteArray geoDir = qgetenv("GEO_DIR");
    if (!geoDir.isEmpty()) {
        const QString d = QString::fromLocal8Bit(geoDir);
        CHECK(upstreamGeoPresentAt(d, QDir(d).filePath(QStringLiteral("SHA256SUMS"))));
    }

    printf("mac_upstream_geo_check: %d/%d passed\n", g_total - g_failed, g_total);
    return g_failed == 0 ? 0 : 1;
}
