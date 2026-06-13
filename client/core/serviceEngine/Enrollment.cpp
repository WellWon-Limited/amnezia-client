#include "Enrollment.h"

// [IN-FORK BUILD] сетевой стек и хранилище форка:
#include "core/repositories/secureAppSettingsRepository.h"
#include "secureQSettings.h"
#include "version.h"

#include "NetAwait.h" // AVPN: awaitReply() — синхронное ожидание с таймаутом (анти-фриз)
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
    const QByteArray body = buildTrialBody(identity.publicKey(), deviceId, detectPlatform(), deviceModel());

    QNetworkRequest req{QUrl(baseUrl + QStringLiteral("/v1/trial"))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("application/json"));

    // Синхронно (движок в фоновом потоке) — паттерн как в gatewayController.
    QNetworkReply *reply = nam->post(req, body);
    awaitReply(reply); // AVPN: было QEventLoop без таймаута → фриз при зависшем бэке

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
    awaitReply(reply); // AVPN: было QEventLoop без таймаута → фриз при зависшем бэке

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

// AVPN: вход/восстановление по коду доступа (P-B12; код = креденшл). Синхронно, паттерн как enroll().
CodeRedeemResult Enrollment::redeemCode(QNetworkAccessManager *nam, const QString &baseUrl,
                                        Identity &identity, SecureAppSettingsRepository *store,
                                        const QString &code, const QString &evictDeviceId,
                                        CodeRedeemResponse &out, QVariantList &devices, QString &error)
{
    if (!nam) {
        error = QStringLiteral("no network manager");
        return CodeRedeemResult::Failed;
    }
    if (!identity.ensureKeys(store, error))
        return CodeRedeemResult::Failed;

    const QString deviceId = Identity::deviceId(store);
    const QByteArray body = buildRedeemBody(code, identity.publicKey(), deviceId,
                                            detectPlatform(), deviceModel(), evictDeviceId);

    QNetworkRequest req{QUrl(baseUrl + QStringLiteral("/v1/code/redeem"))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("application/json"));

    QNetworkReply *reply = nam->post(req, body);
    awaitReply(reply); // AVPN: было QEventLoop без таймаута → фриз при зависшем бэке

    const int httpCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QByteArray respBody = reply->readAll();
    const QNetworkReply::NetworkError netErr = reply->error();
    const QString netErrStr = reply->errorString();
    reply->deleteLater();

    if (netErr != QNetworkReply::NoError && httpCode == 0) {
        error = QStringLiteral("network error: %1").arg(netErrStr);
        return CodeRedeemResult::Failed;
    }
    if (httpCode == 401) {
        error = QStringLiteral("invalid code (401)");
        return CodeRedeemResult::BadCode;
    }
    if (httpCode == 409) {
        // Мест нет — отдаём devices[] для UI-выбора кого отключить (DELETE /v1/devices/{id} или evict).
        devices = parseDeviceList(respBody);
        error = QStringLiteral("device limit reached (409)");
        return CodeRedeemResult::SeatLimit;
    }
    if (httpCode == 429) {
        error = QStringLiteral("redeem rate-limited (429)");
        return CodeRedeemResult::Failed;
    }
    if (httpCode < 200 || httpCode >= 300) {
        error = QStringLiteral("redeem HTTP %1").arg(httpCode);
        return CodeRedeemResult::Failed;
    }
    if (!parseRedeemResponse(respBody, out, error))
        return CodeRedeemResult::Failed;

    saveToken(out.subscriptionToken); // РОТАЦИЯ: per-device subscription_token перезаписывает стор (AVPN)
    return CodeRedeemResult::Ok;
}

// AVPN (Task 13): принять перенос «как SIM» на ЭТО устройство. Токен переноса = авторизация
// (security: []), поэтому Bearer НЕ шлём — токен в теле. Паттерн как redeemCode().
TransferRedeemResult Enrollment::redeemTransfer(QNetworkAccessManager *nam, const QString &baseUrl,
                                                Identity &identity, SecureAppSettingsRepository *store,
                                                const QString &transferToken,
                                                TransferRedeemResponse &out, QString &error)
{
    if (!nam) {
        error = QStringLiteral("no network manager");
        return TransferRedeemResult::Failed;
    }
    if (transferToken.isEmpty()) {
        error = QStringLiteral("empty transfer token");
        return TransferRedeemResult::Failed;
    }
    if (!identity.ensureKeys(store, error))
        return TransferRedeemResult::Failed;

    const QString deviceId = Identity::deviceId(store);
    const QByteArray body = buildTransferRedeemBody(transferToken, identity.publicKey(), deviceId,
                                                    detectPlatform(), deviceModel());

    QNetworkRequest req{QUrl(baseUrl + QStringLiteral("/v1/transfer/redeem"))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("application/json"));

    QNetworkReply *reply = nam->post(req, body);
    awaitReply(reply); // AVPN: было QEventLoop без таймаута → фриз при зависшем бэке

    const int httpCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QByteArray respBody = reply->readAll();
    const QNetworkReply::NetworkError netErr = reply->error();
    const QString netErrStr = reply->errorString();
    reply->deleteLater();

    if (netErr != QNetworkReply::NoError && httpCode == 0) {
        error = QStringLiteral("network error: %1").arg(netErrStr);
        return TransferRedeemResult::Failed;
    }
    if (httpCode == 401) {
        error = QStringLiteral("invalid or expired transfer token (401)");
        return TransferRedeemResult::BadToken;
    }
    if (httpCode == 409) {
        error = QStringLiteral("device limit reached (409)");
        return TransferRedeemResult::SeatLimit;
    }
    if (httpCode == 429) {
        error = QStringLiteral("transfer rate-limited (429)");
        return TransferRedeemResult::Failed;
    }
    if (httpCode < 200 || httpCode >= 300) {
        error = QStringLiteral("transfer/redeem HTTP %1").arg(httpCode);
        return TransferRedeemResult::Failed;
    }
    if (!parseTransferRedeemResponse(respBody, out, error))
        return TransferRedeemResult::Failed;

    saveToken(out.subscriptionToken); // РОТАЦИЯ: новый per-device subscription_token (AVPN)
    return TransferRedeemResult::Ok;
}

// AVPN (Task 13): выпустить одноразовый токен переноса (+ deep_link) для QR/копирования. Bearer.
bool Enrollment::createTransfer(QNetworkAccessManager *nam, const QString &baseUrl,
                                const QString &authToken, TransferMintResponse &out, QString &error)
{
    if (!nam) { error = QStringLiteral("no network manager"); return false; }
    if (authToken.isEmpty()) { error = QStringLiteral("not authorized (no token)"); return false; }

    QNetworkRequest req{QUrl(baseUrl + QStringLiteral("/v1/transfer"))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QByteArrayLiteral("application/json"));
    req.setRawHeader(QByteArrayLiteral("Authorization"),
                     QByteArrayLiteral("Bearer ") + authToken.toUtf8());

    QNetworkReply *reply = nam->post(req, QByteArray()); // тело не требуется (контекст из токена)
    awaitReply(reply); // AVPN: было QEventLoop без таймаута → фриз при зависшем бэке

    const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QByteArray respBody = reply->readAll();
    const QNetworkReply::NetworkError netErr = reply->error();
    const QString netErrStr = reply->errorString();
    reply->deleteLater();

    if (netErr != QNetworkReply::NoError && code == 0) {
        error = QStringLiteral("network error: %1").arg(netErrStr);
        return false;
    }
    if (code == 401) { error = QStringLiteral("transfer unauthorized (token)"); return false; }
    if (code < 200 || code >= 300) { error = QStringLiteral("transfer HTTP %1").arg(code); return false; }
    return parseTransferMintResponse(respBody, out, error);
}

} // namespace avpn
