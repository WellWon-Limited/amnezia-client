// Tribe subscription request contract shared by synchronous and asynchronous callers.
#pragma once

#include <QDebug>
#include <QRegularExpression>
#include <QUrl>
#include <QUrlQuery>

namespace avpn {

inline QUrl versionedSubscriptionUrl(const QString &baseUrl,
                                     const QString &applicationVersion)
{
    QUrl url(baseUrl + QStringLiteral("/v1/subscription"));
    static const QRegularExpression version(
        QStringLiteral("^[0-9]+(?:\\.[0-9]+){2,3}$"));
    if (!version.match(applicationVersion).hasMatch()
        || applicationVersion.size() > 32) {
        // Never turn a packaging/version regression into an empty URL and a
        // broken subscription. The backend keeps the legacy request compatible.
        qWarning() << "invalid application version; using unversioned subscription URL";
        return url;
    }
    QUrlQuery query;
    query.addQueryItem(QStringLiteral("app_version"), applicationVersion);
    url.setQuery(query);
    return url;
}

} // namespace avpn
