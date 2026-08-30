// Tribe catalog v2 — cancellable fetch of the offline-root-signed online keyset artifact.
#pragma once

#include <QObject>
#include <QPointer>
#include <QUrl>

class QNetworkAccessManager;
class QNetworkReply;
class QTimer;

namespace avpn {

enum class CatalogKeysetFetchKind { Artifact = 0, TemporarilyUnavailable, NetworkUnavailable,
                                    ProtocolError };

struct CatalogKeysetFetchResult {
    quint64 operation = 0;
    CatalogKeysetFetchKind kind = CatalogKeysetFetchKind::ProtocolError;
    QByteArray envelope;
    int retryAfterS = 0;
};

class ICatalogKeysetFetchObserver {
public:
    virtual ~ICatalogKeysetFetchObserver() = default;
    virtual void onCatalogKeysetFetchResult(const CatalogKeysetFetchResult &result) = 0;
};

class ICatalogKeysetClient {
public:
    virtual ~ICatalogKeysetClient() = default;
    virtual void setObserver(ICatalogKeysetFetchObserver *observer) = 0;
    virtual void clearObserver(ICatalogKeysetFetchObserver *expected) = 0;
    virtual bool start(const QUrl &apiBaseUrl, quint64 &operation, QString &error) = 0;
    virtual void cancel(quint64 operation) = 0;
};

class CatalogKeysetClient final : public QObject, public ICatalogKeysetClient {
public:
    explicit CatalogKeysetClient(QNetworkAccessManager *network, QObject *parent = nullptr,
                                 int timeoutMs = 10000, int maximumBodyBytes = 128 * 1024);
    ~CatalogKeysetClient() override;
    void setObserver(ICatalogKeysetFetchObserver *observer) override { m_observer = observer; }
    void clearObserver(ICatalogKeysetFetchObserver *expected) override
    { if (m_observer == expected) m_observer = nullptr; }
    bool start(const QUrl &apiBaseUrl, quint64 &operation, QString &error) override;
    void cancel(quint64 operation) override;

private:
    bool consume(QNetworkReply *reply, quint64 operation);
    void finish(QNetworkReply *reply, quint64 operation);
    void deliver(CatalogKeysetFetchResult result);
    void reset(QNetworkReply *reply, bool abort);

    QPointer<QNetworkAccessManager> m_network;
    QPointer<QNetworkReply> m_reply;
    QTimer *m_timer = nullptr;
    ICatalogKeysetFetchObserver *m_observer = nullptr;
    QByteArray m_body;
    quint64 m_counter = 0;
    quint64 m_activeOperation = 0;
    int m_timeoutMs = 10000;
    int m_maximumBodyBytes = 128 * 1024;
};

} // namespace avpn
