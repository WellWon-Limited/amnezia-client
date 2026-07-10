// client/core/serviceEngine/ConfigService.h
// AVPN: оркестратор серверного remote-config (/v1/config + /v1/edges): fetch, verify(ed25519),
// LKG-кеш, edge-фолбэк. Async (armTimeout) — UI не блокируется.
#pragma once
#include "ConfigTypes.h"
#include <QObject>
#include <QStringList>

class QNetworkAccessManager;

namespace avpn {

class ConfigService : public QObject
{
    Q_OBJECT
public:
    ConfigService(QNetworkAccessManager *nam, const QString &baseUrl, const QString &pubKeyHex,
                  const QStringList &bakedEdges, QObject *parent = nullptr);

    void start();
    const RemoteConfig &config() const { return m_config; }
    QString activeBaseUrl() const { return m_activeBase; }

    void reportNetworkFailure();
    void reportNetworkSuccess();

signals:
    void configApplied(const avpn::RemoteConfig &cfg);
    void activeEdgeChanged(const QString &base);

private:
    void fetchConfig();
    void fetchEdges();
    void applyBody(const QByteArray &body, const QByteArray &sigB64); // verify → parse → cache → emit
    int  failThreshold() const;

    QNetworkAccessManager *m_nam = nullptr;
    QString      m_activeBase;
    QString      m_pubKeyHex;
    QStringList  m_bakedEdges;
    RemoteConfig m_config;
    int          m_failStreak = 0;
};

} // namespace avpn
