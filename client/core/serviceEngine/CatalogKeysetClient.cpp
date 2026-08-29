#include "CatalogKeysetClient.h"

#include "SignedEnvelope.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>
#include <QSet>

#include <cmath>

namespace avpn {
namespace {

bool exactNoStore(const QNetworkReply *reply)
{
    QSet<QByteArray> tokens;
    const QList<QByteArray> parts = reply->rawHeader(QByteArrayLiteral("Cache-Control"))
                                        .toLower().split(',');
    for (QByteArray part : parts) {
        part = part.trimmed();
        if (part.isEmpty() || tokens.contains(part)) return false;
        tokens.insert(part);
    }
    return tokens == QSet<QByteArray>{QByteArrayLiteral("private"),
                                     QByteArrayLiteral("no-store")};
}

bool retryAfter(const QNetworkReply *reply, int &value)
{
    const QByteArray raw = reply->rawHeader(QByteArrayLiteral("Retry-After")).trimmed();
    bool ok = false;
    value = raw.toInt(&ok);
    return ok && value >= 1 && value <= 300 && raw == QByteArray::number(value);
}

bool exactJsonInt(const QJsonValue &value, int minimum, int maximum, int &out)
{
    if (!value.isDouble()) return false;
    const double number = value.toDouble();
    if (!std::isfinite(number) || number < minimum || number > maximum
        || std::floor(number) != number) return false;
    out = int(number);
    return true;
}

} // namespace

CatalogKeysetClient::CatalogKeysetClient(QNetworkAccessManager *network, QObject *parent,
                                         int timeoutMs, int maximumBodyBytes)
    : QObject(parent), m_network(network), m_timer(new QTimer(this)),
      m_timeoutMs(qBound(3000, timeoutMs, 30000)),
      m_maximumBodyBytes(qBound(4096, maximumBodyBytes, 256 * 1024))
{
    m_timer->setSingleShot(true);
    connect(m_timer, &QTimer::timeout, this, [this]() {
        if (!m_reply || !m_activeOperation) return;
        const quint64 operation = m_activeOperation;
        QNetworkReply *reply = m_reply;
        reset(reply, true);
        deliver({operation, CatalogKeysetFetchKind::NetworkUnavailable, {}, 0});
    });
}

CatalogKeysetClient::~CatalogKeysetClient()
{
    m_observer = nullptr;
    if (m_reply) reset(m_reply, true);
}

bool CatalogKeysetClient::start(const QUrl &apiBaseUrl, quint64 &operation, QString &error)
{
    operation = 0;
    error.clear();
    if (!m_network || m_reply || !apiBaseUrl.isValid()
        || apiBaseUrl.scheme() != QLatin1String("https") || apiBaseUrl.host().isEmpty()
        || !apiBaseUrl.userInfo().isEmpty() || !apiBaseUrl.query().isEmpty()
        || !apiBaseUrl.fragment().isEmpty()
        || (!apiBaseUrl.path().isEmpty() && apiBaseUrl.path() != QLatin1String("/"))) {
        error = QStringLiteral("keyset endpoint unavailable/busy");
        return false;
    }
    QUrl endpoint = apiBaseUrl;
    endpoint.setPath(QStringLiteral("/v2/keys/manifest"));
    QNetworkRequest request(endpoint);
    request.setRawHeader(QByteArrayLiteral("Accept"), QByteArrayLiteral("application/json"));
    request.setRawHeader(QByteArrayLiteral("Cache-Control"), QByteArrayLiteral("no-store"));
    request.setRawHeader(QByteArrayLiteral("Pragma"), QByteArrayLiteral("no-cache"));
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::ManualRedirectPolicy);
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute,
                         QNetworkRequest::AlwaysNetwork);
    request.setAttribute(QNetworkRequest::CacheSaveControlAttribute, false);
    request.setTransferTimeout(m_timeoutMs);
    QNetworkReply *reply = m_network->get(request);
    if (!reply) {
        error = QStringLiteral("keyset request dispatch unavailable");
        return false;
    }
    if (++m_counter == 0) ++m_counter;
    m_activeOperation = m_counter;
    m_reply = reply;
    m_body.clear();
    reply->setReadBufferSize(qint64(m_maximumBodyBytes) + 1);
    connect(reply, &QIODevice::readyRead, this,
            [this, reply, op = m_activeOperation]() { consume(reply, op); });
    connect(reply, &QNetworkReply::finished, this,
            [this, reply, op = m_activeOperation]() { finish(reply, op); });
    m_timer->start(m_timeoutMs);
    operation = m_activeOperation;
    return true;
}

void CatalogKeysetClient::cancel(quint64 operation)
{
    if (!m_reply || operation == 0 || operation != m_activeOperation) return;
    reset(m_reply, true);
}

bool CatalogKeysetClient::consume(QNetworkReply *reply, quint64 operation)
{
    if (!reply || reply != m_reply || operation != m_activeOperation) return false;
    while (reply->bytesAvailable() > 0) {
        const qint64 remaining = qint64(m_maximumBodyBytes) + 1 - m_body.size();
        if (remaining <= 0) {
            reset(reply, true);
            deliver({operation, CatalogKeysetFetchKind::ProtocolError, {}, 0});
            return false;
        }
        m_body += reply->read(qMin(remaining, reply->bytesAvailable()));
        if (m_body.size() > m_maximumBodyBytes) {
            reset(reply, true);
            deliver({operation, CatalogKeysetFetchKind::ProtocolError, {}, 0});
            return false;
        }
    }
    return true;
}

void CatalogKeysetClient::finish(QNetworkReply *reply, quint64 operation)
{
    if (!reply || reply != m_reply || operation != m_activeOperation) {
        if (reply) reply->deleteLater();
        return;
    }
    if (!consume(reply, operation)) return;
    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const bool transportOk = reply->error() == QNetworkReply::NoError;
    const bool redirect = status >= 300 && status < 400;
    const bool headers = exactNoStore(reply)
                         && reply->rawHeader(QByteArrayLiteral("Content-Type"))
                                .trimmed().toLower() == QByteArrayLiteral("application/json");
    const QByteArray body = std::move(m_body);
    int retry = 0;
    const bool retryHeader = retryAfter(reply, retry);
    reset(reply, false);
    if (!transportOk || status == 0) {
        deliver({operation, CatalogKeysetFetchKind::NetworkUnavailable, {}, 0});
        return;
    }
    if (redirect || !headers || body.isEmpty()) {
        deliver({operation, CatalogKeysetFetchKind::ProtocolError, {}, 0});
        return;
    }
    if (status == 200 && !retryHeader) {
        QJsonDocument document;
        QString error;
        if (parseStrictJsonDocument(body, document, error, m_maximumBodyBytes)
            && document.isObject()) {
            deliver({operation, CatalogKeysetFetchKind::Artifact, body, 0});
            return;
        }
    }
    if (status == 503 && retryHeader) {
        QJsonDocument document;
        QString parseError;
        if (parseStrictJsonDocument(body, document, parseError, 4096)
            && document.isObject()) {
            const QJsonObject object = document.object();
            int schema = 0;
            int bodyRetry = 0;
            const bool exact = object.size() == 4
                               && exactJsonInt(
                                   object.value(QStringLiteral("schema_version")), 1, 1,
                                   schema)
                               && object.value(QStringLiteral("code")).toString()
                                      == QLatin1String("keyset_unavailable")
                               && object.value(QStringLiteral("message")).isString()
                               && exactJsonInt(
                                   object.value(QStringLiteral("retry_after")), 1, 300,
                                   bodyRetry)
                               && bodyRetry == retry;
            if (exact) {
                deliver({operation, CatalogKeysetFetchKind::TemporarilyUnavailable, {}, retry});
                return;
            }
        }
    }
    deliver({operation, CatalogKeysetFetchKind::ProtocolError, {}, 0});
}

void CatalogKeysetClient::deliver(CatalogKeysetFetchResult result)
{
    ICatalogKeysetFetchObserver *observer = m_observer;
    QTimer::singleShot(0, this, [this, observer, result = std::move(result)]() {
        if (m_observer == observer && observer) observer->onCatalogKeysetFetchResult(result);
    });
}

void CatalogKeysetClient::reset(QNetworkReply *reply, bool abort)
{
    m_timer->stop();
    m_reply.clear();
    m_activeOperation = 0;
    m_body.fill('\0');
    m_body.clear();
    if (!reply) return;
    disconnect(reply, nullptr, this, nullptr);
    if (abort) reply->abort();
    reply->deleteLater();
}

} // namespace avpn
