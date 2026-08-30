#include "CatalogResolveClient.h"

#include "SignedEnvelope.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QTimer>

#include <cstring>
#include <cmath>
#include <utility>

namespace avpn {
namespace {

QByteArray randomBytes(int count)
{
    QByteArray bytes(count, Qt::Uninitialized);
    for (int offset = 0; offset < count; offset += int(sizeof(quint32))) {
        const quint32 word = QRandomGenerator::system()->generate();
        const int chunk = qMin(int(sizeof(word)), count - offset);
        memcpy(bytes.data() + offset, &word, size_t(chunk));
    }
    return bytes;
}

QString freshNonce()
{
    return QString::fromLatin1(randomBytes(32).toBase64(
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

bool exactKeys(const QJsonObject &object, const QSet<QString> &required,
               const QSet<QString> &optional = {})
{
    for (const QString &key : required)
        if (!object.contains(key)) return false;
    for (auto it = object.constBegin(); it != object.constEnd(); ++it)
        if (!required.contains(it.key()) && !optional.contains(it.key())) return false;
    return true;
}

bool canonicalPositiveInt(const QJsonValue &value, int minimum, int maximum, int &out)
{
    if (!value.isDouble()) return false;
    const double number = value.toDouble();
    if (!std::isfinite(number) || number < minimum || number > maximum
        || std::floor(number) != number) return false;
    out = int(number);
    return true;
}

bool noStoreHeader(const QHash<QByteArray, QByteArray> &headers)
{
    const QList<QByteArray> parts = headers.value(QByteArrayLiteral("cache-control")).toLower()
                                        .split(',');
    QSet<QByteArray> tokens;
    static const QSet<QByteArray> allowed{
        QByteArrayLiteral("private"), QByteArrayLiteral("no-store"),
        QByteArrayLiteral("no-cache"), QByteArrayLiteral("max-age=0")};
    for (QByteArray part : parts) {
        part = part.trimmed();
        if (part.isEmpty() || !allowed.contains(part) || tokens.contains(part)) return false;
        tokens.insert(part);
    }
    return tokens.contains(QByteArrayLiteral("private"))
           && tokens.contains(QByteArrayLiteral("no-store"));
}

bool retryHeader(const QHash<QByteArray, QByteArray> &headers, int &value)
{
    const QByteArray raw = headers.value(QByteArrayLiteral("retry-after"));
    static const QRegularExpression decimal(QStringLiteral("^[1-9][0-9]{0,3}$"));
    if (!decimal.match(QString::fromLatin1(raw)).hasMatch()) return false;
    bool ok = false;
    value = raw.toInt(&ok);
    return ok;
}

bool parseErrorBody(const QByteArray &body, QJsonObject &object, QString &error, int maximum)
{
    QJsonDocument document;
    if (!parseStrictJsonDocument(body, document, error, maximum) || !document.isObject()) {
        error = QStringLiteral("v2 error body is not strict JSON");
        return false;
    }
    object = document.object();
    const QSet<QString> required{QStringLiteral("schema_version"),
                                 QStringLiteral("code"), QStringLiteral("message")};
    const QSet<QString> optional{QStringLiteral("minimum_app_build"),
                                 QStringLiteral("retry_after"), QStringLiteral("reason")};
    int schema = 0;
    if (!exactKeys(object, required, optional)
        || !canonicalPositiveInt(object.value(QStringLiteral("schema_version")), 1, 1,
                                 schema)
        || !object.value(QStringLiteral("code")).isString()
        || !object.value(QStringLiteral("message")).isString()
        || object.value(QStringLiteral("message")).toString().isEmpty()
        || object.value(QStringLiteral("message")).toString().size() > 255) {
        error = QStringLiteral("v2 error body fields are invalid");
        return false;
    }
    return true;
}

} // namespace

bool parseCatalogResolveHttpResponse(const CatalogResolveHttpResponse &response,
                                     const QString &requestNonce,
                                     CatalogResolveResult &result, QString &error,
                                     int maximumBodyBytes)
{
    result = {};
    result.httpStatus = response.status;
    result.requestNonce = requestNonce;
    error.clear();
    const int bodyLimit = qBound(4096, maximumBodyBytes, 2 * 1024 * 1024);
    if (!canonicalCatalogOpaque32(requestNonce)) {
        error = QStringLiteral("resolve attempt nonce is invalid");
        return false;
    }
    if (response.status == 0 || response.transportFailed) {
        result.kind = CatalogResolveResultKind::NetworkUnavailable;
        return true;
    }
    if (response.status >= 300 && response.status < 400) {
        error = QStringLiteral("resolve redirect rejected");
        return false;
    }
    if (response.body.isEmpty() || response.body.size() > bodyLimit || !noStoreHeader(response.headers)) {
        error = QStringLiteral("resolve response body/cache policy rejected");
        return false;
    }
    if (response.headers.value(QByteArrayLiteral("content-type")).trimmed().toLower()
            != QByteArrayLiteral("application/json")) {
        error = QStringLiteral("resolve response content type rejected");
        return false;
    }
    if (response.status == 200) {
        if (response.headers.contains(QByteArrayLiteral("retry-after"))) {
            error = QStringLiteral("unexpected retry header on signed catalog");
            return false;
        }
        QJsonDocument document;
        if (!parseStrictJsonDocument(response.body, document, error, bodyLimit)
            || !document.isObject()) {
            error = QStringLiteral("signed catalog envelope JSON invalid");
            return false;
        }
        const QJsonObject envelope = document.object();
        const QSet<QString> keys{QStringLiteral("alg"), QStringLiteral("kid"),
                                 QStringLiteral("payload"), QStringLiteral("signature")};
        if (!exactKeys(envelope, keys) || envelope.value(QStringLiteral("alg")).toString()
                                                != QLatin1String("Ed25519")
            || !envelope.value(QStringLiteral("kid")).isString()
            || !envelope.value(QStringLiteral("payload")).isString()
            || !envelope.value(QStringLiteral("signature")).isString()) {
            error = QStringLiteral("signed catalog envelope fields invalid");
            return false;
        }
        result.kind = CatalogResolveResultKind::SignedCatalog;
        result.signedEnvelope = response.body;
        result.authoritativeV2Endpoint = true;
        return true;
    }
    if (response.status == 202) {
        QJsonDocument document;
        if (!parseStrictJsonDocument(response.body, document, error, bodyLimit)
            || !document.isObject()) {
            error = QStringLiteral("catalog preparing body invalid");
            return false;
        }
        const QJsonObject object = document.object();
        const QSet<QString> keys{QStringLiteral("code"), QStringLiteral("retry_after")};
        int bodyRetry = 0, headerRetry = 0;
        if (!exactKeys(object, keys)
            || object.value(QStringLiteral("code")).toString()
                   != QLatin1String("catalog_preparing")
            || !canonicalPositiveInt(object.value(QStringLiteral("retry_after")), 1, 300,
                                     bodyRetry)
            || !retryHeader(response.headers, headerRetry) || bodyRetry != headerRetry) {
            error = QStringLiteral("catalog preparing retry contract mismatch");
            return false;
        }
        result.kind = CatalogResolveResultKind::Preparing;
        result.serverCode = QStringLiteral("catalog_preparing");
        result.retryAfterS = bodyRetry;
        result.authoritativeV2Endpoint = true;
        return true;
    }
    if (response.status == 401) {
        QJsonObject object;
        if (!parseErrorBody(response.body, object, error, bodyLimit)
            || object.value(QStringLiteral("code")).toString()
                   != QLatin1String("auth_invalid")
            || object.contains(QStringLiteral("minimum_app_build"))
            || object.contains(QStringLiteral("retry_after"))
            || object.contains(QStringLiteral("reason"))
            || response.headers.contains(QByteArrayLiteral("retry-after"))) {
            error = QStringLiteral("unauthorized response contract mismatch");
            return false;
        }
        result.kind = CatalogResolveResultKind::Unauthorized;
        result.authoritativeV2Endpoint = true;
        return true;
    }
    if (response.status == 410) {
        QJsonObject object;
        if (!parseErrorBody(response.body, object, error, bodyLimit)
            || object.value(QStringLiteral("code")).toString()
                   != QLatin1String("device_revoked")
            || (object.value(QStringLiteral("reason")).toString()
                    != QLatin1String("transferred")
                && object.value(QStringLiteral("reason")).toString()
                    != QLatin1String("revoked"))
            || object.contains(QStringLiteral("minimum_app_build"))
            || object.contains(QStringLiteral("retry_after"))
            || response.headers.contains(QByteArrayLiteral("retry-after"))) {
            error = QStringLiteral("transferred response contract mismatch");
            return false;
        }
        result.kind = CatalogResolveResultKind::RevokedOrTransferred;
        result.authoritativeV2Endpoint = true;
        return true;
    }
    if (response.status == 429) {
        QJsonObject object;
        int retry = 0;
        int bodyRetry = 0;
        if (!parseErrorBody(response.body, object, error, bodyLimit)
            || object.value(QStringLiteral("code")).toString()
                   != QLatin1String("rate_limited")
            || object.contains(QStringLiteral("minimum_app_build"))
            || object.contains(QStringLiteral("reason"))
            || !canonicalPositiveInt(object.value(QStringLiteral("retry_after")),
                                     1, 300, bodyRetry)
            || !retryHeader(response.headers, retry) || retry != bodyRetry) {
            error = QStringLiteral("rate-limit response contract mismatch");
            return false;
        }
        result.kind = CatalogResolveResultKind::RateLimited;
        result.retryAfterS = bodyRetry;
        result.authoritativeV2Endpoint = true;
        return true;
    }
    if (response.status != 400 && response.status != 403 && response.status != 409
        && response.status != 426 && response.status != 503) {
        error = QStringLiteral("unexpected resolve HTTP status");
        return false;
    }
    QJsonObject object;
    if (!parseErrorBody(response.body, object, error, bodyLimit)) return false;
    const QString code = object.value(QStringLiteral("code")).toString();
    int minimumBuild = 0, bodyRetry = 0, headerRetry = 0;
    if (object.contains(QStringLiteral("minimum_app_build"))
        && !canonicalPositiveInt(object.value(QStringLiteral("minimum_app_build")), 1,
                                 2147483647, minimumBuild)) {
        error = QStringLiteral("minimum app build is invalid");
        return false;
    }
    const bool hasRetry = object.contains(QStringLiteral("retry_after"));
    if (hasRetry && !canonicalPositiveInt(object.value(QStringLiteral("retry_after")), 1,
                                          300, bodyRetry)) {
        error = QStringLiteral("error retry interval is invalid");
        return false;
    }
    const bool hasRetryHeader = response.headers.contains(QByteArrayLiteral("retry-after"));
    if (hasRetry != hasRetryHeader
        || (hasRetry && (!retryHeader(response.headers, headerRetry)
                         || headerRetry != bodyRetry))) {
        error = QStringLiteral("error Retry-After header/body mismatch");
        return false;
    }
    if (object.contains(QStringLiteral("reason"))) {
        error = QStringLiteral("unexpected reason on catalog application error");
        return false;
    }
    CatalogResolveResultKind expected = CatalogResolveResultKind::ProtocolError;
    if (response.status == 400 && code == QLatin1String("invalid_request"))
        expected = CatalogResolveResultKind::InvalidRequest;
    else if (response.status == 403 && code == QLatin1String("account_blocked"))
        expected = CatalogResolveResultKind::AccountBlocked;
    else if (response.status == 409 && code == QLatin1String("device_key_mismatch"))
        expected = CatalogResolveResultKind::DeviceKeyMismatch;
    else if (response.status == 426 && code == QLatin1String("upgrade_required"))
        expected = CatalogResolveResultKind::UpgradeRequired;
    else if (response.status == 503 && code == QLatin1String("no_capacity"))
        expected = CatalogResolveResultKind::NoCapacity;
    else if (response.status == 503 && code == QLatin1String("temporarily_unavailable"))
        expected = CatalogResolveResultKind::TemporarilyUnavailable;
    else {
        error = QStringLiteral("resolve status/error code mismatch");
        return false;
    }
    // 426 can be authoritative even when the resolver has no higher audited build to recommend
    // (for example an engine/adapter tuple mismatch on the current build).  A minimum is useful
    // when known, but is forbidden on every other status.
    if ((minimumBuild > 0 && expected != CatalogResolveResultKind::UpgradeRequired)
        || (response.status != 503 && hasRetry)) {
        error = QStringLiteral("resolve status optional fields mismatch");
        return false;
    }
    result.kind = expected;
    result.serverCode = code;
    result.minimumAppBuild = minimumBuild;
    result.retryAfterS = bodyRetry;
    result.authoritativeV2Endpoint = true;
    return true;
}

CatalogResolveClient::CatalogResolveClient(QNetworkAccessManager *network, QObject *parent,
                                           int timeoutMs, int maximumBodyBytes)
    : QObject(parent), m_network(network), m_timer(new QTimer(this)),
      m_timeoutMs(qBound(3000, timeoutMs, 60000)),
      m_maximumBodyBytes(qBound(4096, maximumBodyBytes, 2 * 1024 * 1024))
{
    m_timer->setSingleShot(true);
    connect(m_timer, &QTimer::timeout, this, [this]() {
        if (!m_reply || m_activeOperation == 0) return;
        QNetworkReply *reply = m_reply;
        const quint64 operation = m_activeOperation;
        const QString nonce = reply->property("catalog_request_nonce").toString();
        m_reply.clear();
        m_activeOperation = 0;
        QObject::disconnect(reply, nullptr, this, nullptr);
        m_body.fill('\0');
        m_body.clear();
        reply->abort();
        reply->deleteLater();
        CatalogResolveResult result;
        result.operation = operation;
        result.kind = CatalogResolveResultKind::NetworkUnavailable;
        result.requestNonce = nonce;
        deliver(result);
    });
}

CatalogResolveClient::~CatalogResolveClient()
{
    m_observer = nullptr;
    if (m_reply) {
        QNetworkReply *reply = m_reply;
        m_reply.clear();
        m_activeOperation = 0;
        QObject::disconnect(reply, nullptr, this, nullptr);
        reply->abort();
    }
    m_body.fill('\0');
    m_body.clear();
}

bool CatalogResolveClient::start(QUrl apiBaseUrl, QByteArray bearerToken,
                                 CatalogResolveRequest runtimeRequest,
                                 CatalogResolveAttempt &attempt, QString &error)
{
    attempt = {};
    error.clear();
    if (!m_network || m_reply || !apiBaseUrl.isValid()
        || apiBaseUrl.scheme().toLower() != QLatin1String("https")
        || apiBaseUrl.host().isEmpty() || !apiBaseUrl.userInfo().isEmpty()
        || !apiBaseUrl.query().isEmpty() || !apiBaseUrl.fragment().isEmpty()
        || (apiBaseUrl.path() != QLatin1String("/") && !apiBaseUrl.path().isEmpty())) {
        error = QStringLiteral("resolve network/base URL unavailable or busy");
        return false;
    }
    if (bearerToken.isEmpty() || bearerToken.size() > 8192
        || bearerToken.contains('\r') || bearerToken.contains('\n')) {
        error = QStringLiteral("resolve bearer credential unavailable");
        return false;
    }
    runtimeRequest.requestNonce = freshNonce();
    QJsonObject body;
    if (!buildCatalogResolveRequest(runtimeRequest, body, error)) return false;
    QUrl endpoint = apiBaseUrl;
    endpoint.setPath(QStringLiteral("/v2/catalog/resolve"));
    QNetworkRequest request(endpoint);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    request.setRawHeader(QByteArrayLiteral("Accept"), QByteArrayLiteral("application/json"));
    request.setRawHeader(QByteArrayLiteral("Authorization"),
                         QByteArrayLiteral("Bearer ") + bearerToken);
    request.setRawHeader(QByteArrayLiteral("Cache-Control"), QByteArrayLiteral("no-store"));
    request.setRawHeader(QByteArrayLiteral("Pragma"), QByteArrayLiteral("no-cache"));
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::ManualRedirectPolicy);
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute,
                         QNetworkRequest::AlwaysNetwork);
    request.setAttribute(QNetworkRequest::CacheSaveControlAttribute, false);
    request.setTransferTimeout(m_timeoutMs);
    const quint64 operation = ++m_counter == 0 ? ++m_counter : m_counter;
    QNetworkReply *reply = m_network->post(
        request, QJsonDocument(body).toJson(QJsonDocument::Compact));
    if (!reply) {
        error = QStringLiteral("resolve transport did not create a reply");
        return false;
    }
    m_reply = reply;
    m_activeOperation = operation;
    m_body.clear();
    reply->setReadBufferSize(qint64(m_maximumBodyBytes) + 1);
    reply->setProperty("catalog_request_nonce", runtimeRequest.requestNonce);
    connect(reply, &QIODevice::readyRead, this,
            [this, reply, operation, nonce = runtimeRequest.requestNonce]() {
                consumeBody(reply, operation, nonce);
            });
    connect(reply, &QNetworkReply::finished, this,
            [this, reply, operation, nonce = runtimeRequest.requestNonce]() {
                finish(reply, operation, nonce);
            });
    m_timer->start(m_timeoutMs);
    attempt = {operation, runtimeRequest.requestNonce,
               runtimeRequest.selection.value_or(CatalogResolveSelection{}),
               runtimeRequest.selection.has_value()};
    bearerToken.fill('\0');
    return true;
}

void CatalogResolveClient::cancel(quint64 operation)
{
    if (!m_reply || operation == 0 || operation != m_activeOperation) return;
    m_timer->stop();
    QNetworkReply *reply = m_reply;
    m_reply.clear();
    m_activeOperation = 0;
    QObject::disconnect(reply, nullptr, this, nullptr);
    m_body.fill('\0');
    m_body.clear();
    reply->abort();
    reply->deleteLater();
}

void CatalogResolveClient::finish(QNetworkReply *reply, quint64 operation, QString nonce)
{
    if (!reply || reply != m_reply || operation != m_activeOperation) {
        if (reply) reply->deleteLater();
        return;
    }
    if (!consumeBody(reply, operation, nonce))
        return;
    m_timer->stop();
    m_reply.clear();
    m_activeOperation = 0;
    CatalogResolveHttpResponse response;
    response.status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    response.transportFailed = response.status == 0 && reply->error() != QNetworkReply::NoError;
    for (const QByteArray &name : reply->rawHeaderList())
        response.headers.insert(name.toLower(), reply->rawHeader(name));
    const QVariant redirect = reply->attribute(QNetworkRequest::RedirectionTargetAttribute);
    if (redirect.isValid()) response.status = 302;
    const QVariant contentLength = reply->header(QNetworkRequest::ContentLengthHeader);
    if (contentLength.isValid() && contentLength.toLongLong() > m_maximumBodyBytes)
        response.body = QByteArray(m_maximumBodyBytes + 1, 'x');
    else
        response.body = std::move(m_body);
    reply->deleteLater();
    CatalogResolveResult result;
    QString ignored;
    if (!parseCatalogResolveHttpResponse(response, nonce, result, ignored, m_maximumBodyBytes)) {
        result = {};
        result.kind = CatalogResolveResultKind::ProtocolError;
        result.httpStatus = response.status;
        result.requestNonce = nonce;
    }
    response.body.fill('\0');
    response.body.clear();
    result.operation = operation;
    deliver(result);
}

bool CatalogResolveClient::consumeBody(QNetworkReply *reply, quint64 operation,
                                       const QString &nonce)
{
    if (!reply || reply != m_reply || operation != m_activeOperation)
        return false;
    while (reply->bytesAvailable() > 0) {
        const qint64 remaining = qint64(m_maximumBodyBytes) + 1 - m_body.size();
        if (remaining <= 0) {
            failProtocol(reply, operation, nonce,
                         reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt());
            return false;
        }
        const QByteArray chunk = reply->read(qMin(remaining, reply->bytesAvailable()));
        if (chunk.isEmpty() && reply->bytesAvailable() > 0) {
            failProtocol(reply, operation, nonce,
                         reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt());
            return false;
        }
        m_body += chunk;
        if (m_body.size() > m_maximumBodyBytes) {
            failProtocol(reply, operation, nonce,
                         reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt());
            return false;
        }
    }
    return true;
}

void CatalogResolveClient::failProtocol(QNetworkReply *reply, quint64 operation,
                                        const QString &nonce, int httpStatus)
{
    if (!reply || reply != m_reply || operation != m_activeOperation)
        return;
    m_timer->stop();
    m_reply.clear();
    m_activeOperation = 0;
    QObject::disconnect(reply, nullptr, this, nullptr);
    m_body.fill('\0');
    m_body.clear();
    reply->abort();
    reply->deleteLater();
    CatalogResolveResult result;
    result.operation = operation;
    result.kind = CatalogResolveResultKind::ProtocolError;
    result.httpStatus = httpStatus;
    result.requestNonce = nonce;
    deliver(result);
}

void CatalogResolveClient::deliver(const CatalogResolveResult &result)
{
    QTimer::singleShot(0, this, [this, result]() {
        if (m_observer) m_observer->onCatalogResolveResult(result);
    });
}

} // namespace avpn
