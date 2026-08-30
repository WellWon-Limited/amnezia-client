// Tribe subscription request contract shared by synchronous and asynchronous callers.
#pragma once

#include <QRegularExpression>
#include <QUrl>
#include <QUrlQuery>

namespace avpn {

inline QUrl versionedSubscriptionUrl(const QString &baseUrl,
                                     const QString &applicationVersion)
{
    // Byte-match the backend cohort grammar.  If packaging ever regresses to Qt's bare build
    // number or a decorated store string, fail the request locally instead of silently joining
    // an unversioned/wrong rollout cohort.
    static const QRegularExpression version(
        QStringLiteral("^[0-9]+(?:\\.[0-9]+){2,3}$"));
    if (!version.match(applicationVersion).hasMatch()
        || applicationVersion.size() > 32)
        return {};
    QUrl url(baseUrl + QStringLiteral("/v1/subscription"));
    QUrlQuery query;
    query.addQueryItem(QStringLiteral("app_version"), applicationVersion);
    url.setQuery(query);
    return url;
}

} // namespace avpn
