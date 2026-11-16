#ifndef AVPN_XRAYASSETS_H
#define AVPN_XRAYASSETS_H

// AVPN (upstream nodes, core amnezia-xray-core v1.261101.0): geo data only from the service's own
// directory. The core resolves `geosite:`/`geoip:`/`ext:` files as <asset dir>/<file> and, on
// macOS/Linux, falls back to /usr/local/share/xray, /usr/share/xray and /opt/share/xray when that
// file is missing (common/platform/others.go). The service leaves the asset location unset (=
// its executable directory), so a pair missing next to Tribe-service would silently route by a
// foreign copy (a Homebrew xray). Xray::startXray refuses such a config instead.
// Pure (QtCore only), covered by service/server/tests/xray_assets_check.cpp.

#include <QDir>
#include <QFileInfo>
#include <QRegularExpression>
#include <QSet>
#include <QString>
#include <QStringList>

namespace avpn {

// Asset files a core config would open: geosite.dat for `geosite:`, geoip.dat for `geoip:`, and
// <file> for `ext:<file>:<code>` / `ext-ip:` / `ext-domain:` / `ext-site:` (Xray's rule syntax,
// common/geodata/rule_parser.go; a leading `!` negates the rule and is irrelevant here).
inline QStringList xrayAssetFiles(const QString &config)
{
    QSet<QString> files;
    static const QRegularExpression geo(QStringLiteral(R"((?:^|[^A-Za-z0-9_-])(geosite|geoip):)"));
    for (auto it = geo.globalMatch(config); it.hasNext();)
        files.insert(it.next().captured(1) + QStringLiteral(".dat"));
    static const QRegularExpression ext(
        QStringLiteral(R"((?:^|[^A-Za-z0-9_-])ext(?:-ip|-domain|-site)?:([^:"\\]+):)"));
    for (auto it = ext.globalMatch(config); it.hasNext();)
        files.insert(it.next().captured(1));
    QStringList out(files.begin(), files.end());
    out.sort();
    return out;
}

// Files from xrayAssetFiles(config) that are not regular files directly inside `dir`. A name that
// is not a plain file name (a path, `..`) counts as missing: the core refuses it anyway.
inline QStringList xrayMissingAssets(const QString &config, const QString &dir)
{
    QStringList missing;
    for (const QString &name : xrayAssetFiles(config)) {
        const bool plain = !name.isEmpty() && name != QStringLiteral(".") && name != QStringLiteral("..")
                           && !name.contains(QLatin1Char('/')) && !name.contains(QLatin1Char('\\'));
        if (!plain || !QFileInfo(QDir(dir).filePath(name)).isFile())
            missing.append(name);
    }
    return missing;
}

} // namespace avpn

#endif // AVPN_XRAYASSETS_H
