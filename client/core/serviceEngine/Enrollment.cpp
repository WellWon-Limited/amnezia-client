#include "Enrollment.h"

// [IN-FORK BUILD] сетевой стек и хранилище форка:
#include "core/repositories/secureAppSettingsRepository.h"
#include "secureQSettings.h"
#include "version.h"

#include <QEventLoop>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>

namespace avpn {

// AVPN: токен в том же зашифрованном сторе форка (SecureQSettings — публичный API).
void Enrollment::saveToken(const QString &token)
{
    SecureQSettings s(QStringLiteral(ORGANIZATION_NAME), QStringLiteral(APPLICATION_NAME));
    s.setValue(kTokenKey, token);
}

QString Enrollment::loadToken()
{
    SecureQSettings s(QStringLiteral(ORGANIZATION_NAME), QStringLiteral(APPLICATION_NAME));
    return s.value(kTokenKey).toString();
}

void Enrollment::clearToken()
{
    SecureQSettings s(QStringLiteral(ORGANIZATION_NAME), QStringLiteral(APPLICATION_NAME));
    s.setValue(kTokenKey, QString());
}

bool Enrollment::enroll(QNetworkAccessManager *nam, const QString &baseUrl, Identity &identity,
                        SecureAppSettingsRepository *store, TrialResponse &out, QString &error)
{
    if (!nam) {
        error = QStringLiteral("no network manager");
        return false;
    }
    if (!identity.ensureKeys(store, error))
        return false;

    const QString deviceId = Identity::deviceId(store);
    const QByteArray body = buildTrialBody(identity.publicKey(), deviceId, detectPlatform());

    QNetworkRequest req{QUrl(baseUrl + QStringLiteral("/v1/trial"))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("application/json"));

    // Синхронно (движок в фоновом потоке) — паттерн как в gatewayController.
    QNetworkReply *reply = nam->post(req, body);
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QByteArray respBody = reply->readAll();
    const QNetworkReply::NetworkError netErr = reply->error();
    const QString netErrStr = reply->errorString();
    reply->deleteLater();

    if (netErr != QNetworkReply::NoError && code == 0) {
        error = QStringLiteral("network error: %1").arg(netErrStr);
        return false;
    }
    if (code == 429) {
        error = QStringLiteral("trial rate-limited (429)");
        return false;
    }
    if (code < 200 || code >= 300) {
        error = QStringLiteral("trial HTTP %1").arg(code);
        return false;
    }
    if (!parseTrialResponse(respBody, out, error))
        return false;

    Q_UNUSED(store)
    saveToken(out.subscriptionToken); // токен — в защ. хранилище (AVPN)
    return true;
}

bool Enrollment::fetchSubscription(QNetworkAccessManager *nam, const QString &baseUrl,
                                   const QString &token, QByteArray &body, QString &error)
{
    if (!nam) { error = QStringLiteral("no network manager"); return false; }
    QNetworkRequest req{QUrl(baseUrl + QStringLiteral("/v1/subscription"))};
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + token.toUtf8());

    QNetworkReply *reply = nam->get(req);
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    body = reply->readAll();
    const QNetworkReply::NetworkError netErr = reply->error();
    const QString netErrStr = reply->errorString();
    reply->deleteLater();

    if (netErr != QNetworkReply::NoError && code == 0) {
        error = QStringLiteral("network error: %1").arg(netErrStr);
        return false;
    }
    if (code == 401) { error = QStringLiteral("subscription unauthorized (token)"); return false; }
    if (code < 200 || code >= 300) { error = QStringLiteral("subscription HTTP %1").arg(code); return false; }
    return true;
}

} // namespace avpn
