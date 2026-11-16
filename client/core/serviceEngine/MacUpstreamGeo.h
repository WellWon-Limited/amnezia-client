#pragma once
// AVPN (macOS desktop, upstream nodes): is the cut geo pair (recipes/tribe-xray-geo) installed next to
// the service, byte for byte the one this app build carries? Pure part of
// MacServiceInstaller::macUpstreamGeoPresent (QtCore only, any directory, no /Library, no bundle), so it
// is unit-tested on the host: tests/build_mac_upstream_geo.sh.
//
// expectedSums = the build's manifest in `shasum -a 256` format, one "<64 hex>  <name>" line per file
// (the app resource tribe-svc-geo.sha256 = tribe-xray-geo's SHA256SUMS). It must list exactly
// geoip.dat and geosite.dat; each must be a regular file directly in serviceDir with that sha256.
// Cost: reads both files (~380 KB) per call.
#include <QByteArray>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QList>
#include <QMap>
#include <QString>

namespace avpn {

inline bool upstreamGeoPresentIn(const QString &serviceDir, const QByteArray &expectedSums)
{
    QMap<QString, QByteArray> want;
    const QList<QByteArray> lines = expectedSums.split('\n');
    for (QByteArray line : lines) {
        line = line.trimmed();
        if (line.isEmpty())
            continue;
        const int sep = line.indexOf(' ');
        if (sep != 64)
            return false;
        const QByteArray hex = line.left(64).toLower();
        QByteArray name = line.mid(sep).trimmed();
        if (name.startsWith('*')) // binary-mode marker of shasum
            name = name.mid(1);
        for (const char c : hex) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                return false;
        }
        if (want.contains(QString::fromUtf8(name)))
            return false;
        want.insert(QString::fromUtf8(name), hex);
    }
    if (want.size() != 2 || !want.contains(QStringLiteral("geoip.dat"))
        || !want.contains(QStringLiteral("geosite.dat")))
        return false;
    for (auto it = want.cbegin(); it != want.cend(); ++it) {
        const QString path = QDir(serviceDir).filePath(it.key());
        const QFileInfo info(path);
        if (!info.isFile() || info.isSymLink())
            return false;
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly))
            return false;
        QCryptographicHash hash(QCryptographicHash::Sha256);
        if (!hash.addData(&file))
            return false;
        if (hash.result().toHex() != it.value())
            return false;
    }
    return true;
}

inline bool upstreamGeoPresentAt(const QString &serviceDir, const QString &expectedSumsPath)
{
    QFile sums(expectedSumsPath);
    if (!sums.open(QIODevice::ReadOnly))
        return false;
    return upstreamGeoPresentIn(serviceDir, sums.read(4096));
}

} // namespace avpn
