// client/core/serviceEngine/ConfigService.h
// AVPN: оркестратор серверного remote-config (/v1/config + /v1/edges): fetch, verify(ed25519),
// LKG-кеш, edge-фолбэк. Async (armTimeout) — UI не блокируется.
#pragma once
#include "ConfigTypes.h"
#include <QObject>
#include <QStringList>
#include <QTimer>

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
    // true после первого конфига, пришедшего из сети (подпись проверена); LKG-кеш — false.
    // Тихая установка и подтверждение «жива» опираются только на свежий конфиг (ревью 2026-09-22).
    bool isFresh() const { return m_fresh; }
    QString activeBaseUrl() const { return m_activeBase; }

    void reportNetworkFailure();
    void reportNetworkSuccess();
    // Волна-4 (ENG-03): iOS обновлял конфиг только перезапуском процесса (таймер — macOS-only).
    // Координатор выхода на экран зовёт это раз в >= 15 мин; дедуп по m_configInFlight внутри.
    void refreshIfStale(qint64 maxAgeMs);

signals:
    void configApplied(const avpn::RemoteConfig &cfg);
    void activeEdgeChanged(const QString &base);
    // AVPN (белые списки): транспортный фейл/успех фетча конфига — второй (после bootstrap)
    // источник сигналов для WhitelistDetector (noteControlPlaneFailure/Ok в AvpnEngineQml).
    void transportFailed();
    void transportOk();

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
    qint64       m_lastFailMs = -1;     // волна-4 (P2-2): затухание стрика — 3 отказа за час не повод шагать
    qint64       m_lastFetchMs = -1;    // волна-4 (ENG-03): когда последний раз ходили за конфигом
    QTimer       m_refreshTimer;
    bool         m_configInFlight = false;
    bool         m_fresh = false;
};

} // namespace avpn
