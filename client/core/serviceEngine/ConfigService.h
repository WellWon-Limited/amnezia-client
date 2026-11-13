// client/core/serviceEngine/ConfigService.h
// AVPN: оркестратор серверного remote-config (/v1/config + /v1/edges): fetch, verify(ed25519),
// LKG-кеш, edge-фолбэк. Async (armTimeout) — UI не блокируется.
#pragma once
#include "ConfigCachePolicy.h"
#include "ConfigTypes.h"
#include "EdgeWalk.h"
#include <QObject>
#include <QStringList>
#include <QTimer>
#include <functional>

class QNetworkAccessManager;
class QNetworkReply;

namespace avpn {

class ConfigService : public QObject
{
    Q_OBJECT
public:
    // pinned (5.1.108) = the control plane is pinned by AVPN_API_URL (dev/E2E backend): baseUrl is the
    // only edge - the stored active edge is not taken, the edge walk never moves, /v1/edges and the
    // config's edges are not stored (a dev backend's list must not leak into the prod edge cache).
    ConfigService(QNetworkAccessManager *nam, const QString &baseUrl, const QString &pubKeyHex,
                  const QStringList &bakedEdges, QObject *parent = nullptr, bool pinned = false);

    void start();
    const RemoteConfig &config() const { return m_config; }
    // true после первого конфига, пришедшего из сети (подпись проверена); LKG-кеш — false.
    // Тихая установка и подтверждение «жива» опираются только на свежий конфиг (ревью 2026-09-22).
    bool isFresh() const { return m_fresh; }
    bool isPinned() const { return m_pinned; }
    QString activeBaseUrl() const { return m_activeBase; }
    // 5.1.109: why features.xray_client of config() is what it is (ConfigCachePolicy.h::decideXrayClient).
    // On the cached copy the signed "true" is honoured for a bounded time since it was received; while
    // the process is still on that copy the trust is judged again before every config request, on the
    // foreground refresh (throttled or not) and on every API outcome reported here, and once it has
    // ended it stays ended for the run. A fresh signed answer wins at once and stays in force.
    XrayPolicy xrayPolicy() const { return m_xrayPolicy; }
    // Age of the cached signed config when it was last judged, minutes; -1 = fresh or unknown.
    qint64 cachedConfigAgeMin() const;
    void setNowMsForTest(std::function<qint64()> nowMs) { m_nowMsFn = std::move(nowMs); }
    // 5.1.109: "this failed reply says nothing about the edge" - the facade's existing classification
    // of API outcomes (DebugSnapshot.h::classifyApiOutcome == Ignore: the request outlived a freeze of
    // the process or fell into the window of our own tunnel transition). Such a config failure does
    // not vote in the edge walk. Not set (tests) = every transport failure votes, as before.
    void setFailureIgnoredFn(std::function<bool(QNetworkReply *)> fn) { m_failureIgnoredFn = std::move(fn); }

    void reportNetworkFailure();
    // Another API request got an answer on the active edge. 5.1.109 (iOS, macOS): while the process is
    // still on the cached config and the config is owed (its own request of the usual kind got no
    // answer), this also asks for /v1/config - once per owed episode, not closer than the refresh
    // throttle to the previous refetch (ConfigCachePolicy.h::refetchConfigOnApiSuccess); true = it was
    // asked for now. The failure of such a refetch does not vote in the edge walk.
    bool reportNetworkSuccess();
    // Decision 2026-11-05: /v1/subscription outcome for its own per-edge streak (EdgeWalk.h::
    // SubscriptionEdgeStreak); requestBase = the edge the request went to. failed = transport failure
    // (classifySubscriptionEdgeOutcome); ignored outcomes are not reported. true = the active edge
    // was switched now (2 failures in a row on it).
    bool reportSubscriptionOutcome(const QString &requestBase, bool failed);
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
    void fetchConfig();                             // a config request of the usual kind
    void requestConfig(bool startedByApiSuccess);   // 5.1.109: + the refetch of reportNetworkSuccess
    void rejudgeCachedXray();                       // 5.1.109: judgeCachedXray + announce a change
    void fetchEdges();
    void applyBody(const QByteArray &body, const QByteArray &sigB64); // verify → parse → cache → emit
    int  failThreshold() const;
    bool switchToNextEdge(); // existing rotation (cached /v1/edges order, baked fallback); false = no other edge
    qint64 nowMs() const;
    // The cached copy: features.xray_client by the bounded trust. true = the value in m_config changed.
    bool judgeCachedXray();

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
    bool         m_pinned = false;      // 5.1.108: AVPN_API_URL pins the edge (see the constructor)
    SubscriptionEdgeStreak m_subscriptionStreak; // decision 2026-11-05, see reportSubscriptionOutcome
    // 5.1.109: what the cached signed copy says and when it was received - the inputs of
    // decideXrayClient while !m_fresh (m_config carries the judged value, never the raw one).
    bool         m_cachedXraySigned = false;
    qint64       m_cachedAtMs = 0;
    qint64       m_cachedMaxAgeMs = 0;
    qint64       m_cachedAgeMs = -1;
    XrayPolicy   m_xrayPolicy = XrayPolicy::NoConfig;
    CachedTrust  m_cachedTrust;         // one-way within a run: ended trust is not revived
    std::function<qint64()> m_nowMsFn;  // test clock (empty = the system clock)
    // 5.1.109 (review of d5d739403): the config request in flight and the owed refetch.
    quint64        m_configSeq = 0;       // bumped by an edge switch: the reply in flight is stale
    QNetworkReply *m_configReply = nullptr; // the request in flight (cleared in its handler / on a switch)
    bool           m_refetchOwed = false; // a usual request got no answer while on the cached copy
    qint64         m_lastRefetchMs = -1;  // when reportNetworkSuccess last asked (spacing)
    std::function<bool(QNetworkReply *)> m_failureIgnoredFn;
};

} // namespace avpn
