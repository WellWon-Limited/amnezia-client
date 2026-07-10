#pragma once
#include <QString>
#include <QStringList>
#include <QVersionNumber>

namespace avpn {

enum class UpdateVerdict { Ok, Recommend, Block };

// Чистая логика (тестируется без Settings).
// Пустой порог отсекается isNull(); 0.0.0 не блокирует, т.к. ни одна реальная версия не ниже нуля.
inline UpdateVerdict compareVersions(const QString &appVer, const QString &minVer,
                                     const QString &recVer)
{
    const QVersionNumber app = QVersionNumber::fromString(appVer);
    const QVersionNumber mn = QVersionNumber::fromString(minVer);
    const QVersionNumber rc = QVersionNumber::fromString(recVer);
    if (!mn.isNull() && QVersionNumber::compare(app, mn) < 0)
        return UpdateVerdict::Block;
    if (!rc.isNull() && QVersionNumber::compare(app, rc) < 0)
        return UpdateVerdict::Recommend;
    return UpdateVerdict::Ok;
}

} // namespace avpn

#ifndef AVPN_CONFIGSTORE_TEST
#include "version.h"
#include "core/SecureQSettings.h"

namespace avpn {

class ConfigStore
{
public:
    static constexpr QLatin1String kLkgConfigKey{"avpn/lkgConfig"};
    static constexpr QLatin1String kLkgEdgesKey{"avpn/lkgEdges"};
    static constexpr QLatin1String kActiveEdgeKey{"avpn/activeEdge"};

    static void saveConfig(const QByteArray &body)
    {
        settings().setValue(kLkgConfigKey, body);
    }
    static QByteArray loadConfig() { return settings().value(kLkgConfigKey).toByteArray(); }

    static void saveEdges(const QStringList &edges)
    {
        settings().setValue(kLkgEdgesKey, edges.join(QLatin1Char('\n')));
    }
    static QStringList loadEdges()
    {
        const QString s = settings().value(kLkgEdgesKey).toString();
        return s.isEmpty() ? QStringList() : s.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    }

    static void setActiveEdge(const QString &base) { settings().setValue(kActiveEdgeKey, base); }
    static QString activeEdge(const QString &def)
    {
        const QString s = settings().value(kActiveEdgeKey).toString();
        return s.isEmpty() ? def : s;
    }

private:
    static SecureQSettings &settings()
    {
        static SecureQSettings s(QStringLiteral(ORGANIZATION_NAME), QStringLiteral(APPLICATION_NAME));
        return s;
    }
};

} // namespace avpn
#endif // AVPN_CONFIGSTORE_TEST
