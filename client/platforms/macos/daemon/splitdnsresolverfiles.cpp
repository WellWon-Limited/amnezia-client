// AVPN (Tribe split-DNS): см. splitdnsresolverfiles.h. Только macOS, только из root-демона.
#include "splitdnsresolverfiles.h"

#include <QDir>
#include <QFile>
#include <QTextStream>

namespace {
const QString kResolverDir = QStringLiteral("/etc/resolver");
// маркер первой строкой файла — clear() трогает ТОЛЬКО такие файлы (чужие resolver-конфиги целы)
const QByteArray kMarker = QByteArrayLiteral("# tribe-split-dns v1");
// защита от мусора в имени файла (суффикс домена → имя в /etc/resolver)
bool safeSuffix(const QString &s)
{
    if (s.isEmpty() || s.size() > 64 || s.startsWith(QLatin1Char('.')))
        return false;
    for (const QChar c : s)
        if (!c.isLetterOrNumber() && c != QLatin1Char('.') && c != QLatin1Char('-'))
            return false;
    return true;
}
} // namespace

namespace SplitDnsResolverFiles {

bool apply(const QStringList &suffixes, const QString &server, const QString &server2)
{
    clear(); // реконсиляция: прошлый сев не аккумулируется
    if (suffixes.isEmpty() || server.isEmpty())
        return true; // «выключено» — чисто и выходим
    QDir dir(kResolverDir);
    if (!dir.exists() && !QDir::root().mkpath(kResolverDir))
        return false;
    bool ok = true;
    for (const QString &suffix : suffixes) {
        if (!safeSuffix(suffix)) {
            ok = false;
            continue;
        }
        QFile f(kResolverDir + QLatin1Char('/') + suffix);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            ok = false;
            continue;
        }
        QTextStream out(&f);
        out << kMarker << '\n' << "nameserver " << server << '\n';
        if (!server2.isEmpty())
            out << "nameserver " << server2 << '\n';
    }
    return ok;
}

void clear()
{
    QDir dir(kResolverDir);
    if (!dir.exists())
        return;
    const QStringList entries = dir.entryList(QDir::Files | QDir::NoDotAndDotDot);
    for (const QString &name : entries) {
        QFile f(dir.filePath(name));
        if (!f.open(QIODevice::ReadOnly))
            continue;
        const QByteArray first = f.readLine().trimmed();
        f.close();
        if (first == kMarker)
            QFile::remove(dir.filePath(name));
    }
}

} // namespace SplitDnsResolverFiles
