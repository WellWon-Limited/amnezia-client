// client/core/serviceEngine/ConfigService.h
// AVPN: оркестратор серверного remote-config (/v1/config + /v1/edges): fetch, verify(ed25519),
// LKG-кеш, edge-фолбэк. Async (armTimeout) — UI не блокируется.
#pragma once
#include "ApiReach.h"
#include "ConfigCachePolicy.h"
#include "ConfigTypes.h"
#include "EdgeWalk.h"
#include <QObject>
#include <QSet>
#include <QStringList>
#include <QTimer>
#include <functional>

class QNetworkAccessManager;

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
    // The edge requests go to: the session edge while a tunnel carries requests (EdgeWalk.h::apiSessionEdgeFor), else
    // the walk's direct edge.
    QString activeBaseUrl() const { return m_sessionEdge.isEmpty() ? m_activeBase : m_sessionEdge; }
    // E10: set (non-empty) while a provider session is up, cleared when it ends. Never stored; the edge walk does
    // not move while it is set (a failure there says nothing about the stored edge). Emits activeEdgeChanged with
    // the edge requests go to now when that changes.
    void setSessionEdge(const QString &edge);
    // R1a: the edge a DIRECT request goes to now (no tunnel carries it): the walk's edge of this run, never the
    // session edge - a new leg's seat request and a release after a stop use this.
    QString directBaseUrl() const { return m_activeBase; }
    // AVPN upstream nodes: the config signing key (dev or prod, as chosen by the facade) - the lease
    // answer is signed by the same key under its own context (SignedContext.h).
    const QString &publicKeyHex() const { return m_pubKeyHex; }
    // 5.1.109: why features.xray_client of config() is what it is (ConfigCachePolicy.h::decideXrayClient).
    // On the cached copy the signed "true" is honoured for a bounded time since it was received; while
    // the process is still on that copy the trust is judged again before every config request, on the
    // foreground refresh (throttled or not) and on every API outcome reported here, and once it has
    // expired it stays expired for the run. A fresh signed answer wins at once and stays in force.
    XrayPolicy xrayPolicy() const { return m_xrayPolicy; }
    // Age of the cached signed config when it was last judged, minutes; -1 = fresh or unknown.
    qint64 cachedConfigAgeMin() const;
    void setNowMsForTest(std::function<qint64()> nowMs) { m_nowMsFn = std::move(nowMs); }

    void reportNetworkFailure();
    // The physical network changed or the app came to the foreground: if the edge walk is backing off after a full
    // unsuccessful round (EdgeWalk.h::edgeRoundPauseMs), the back-off is forgotten and a new round starts now.
    // Touches nothing tunnel-related (an edge switch never does).
    void resumeEdgeWalk();
    // The physical network changed (not our own tunnel): resume as above, and ask the new network at once - the walk
    // starts over with the quick first try (an edge that answered on the old network proves nothing here), so
    // directApiReach() converges in a few seconds instead of waiting for the next config refresh. Not under a
    // session edge (a tunnel carries the requests) and not on a pinned dev backend.
    void noteNetworkChanged();
    // Our tunnel went down (the facade's one place that sees it): the direct route is observable again and nothing
    // learned through the tunnel applies - when the fact of this network generation is not known directly (Unknown),
    // the direct route is asked once (askDirectOnce).
    void noteTunnelDown();
    // Read-only: is a tunnel of ours up now (any state in which it may carry the app's requests). A request sent while
    // one is up says nothing about the direct route; stamped at send time. Unset = never.
    void setTunnelUpSource(std::function<bool()> up) { m_tunnelUpFn = std::move(up); }
    // When the physical network last changed (the system clock of nowMs); the facade uses it to tell whether an API
    // request was sent before the change.
    qint64 lastNetworkChangeMs() const { return m_netChangeMs; }
    // Lane C: can the direct control plane be reached on this network now (see ApiReach.h). Unknown when nothing was
    // observed under the CURRENT generation of the network (the source below). The one owner of this fact.
    ApiReach directApiReach() const;
    void setNetworkGenerationSource(std::function<quint64()> generation) { m_generationFn = std::move(generation); }
    // Test hook: the first-try limit and the round pause numbers (replace the defaults and the server's numbers).
    void setEdgeWalkTimingForTest(int fastFirstTryMs, qint64 pauseBaseMs, qint64 pauseCapMs)
    {
        m_fastEdgeMs = fastFirstTryMs; m_pauseBaseTest = pauseBaseMs; m_pauseCapTest = pauseCapMs;
    }
    // Another API request got an answer on the active edge. 5.1.109 (iOS, macOS): while the process is
    // still on the cached config and the config is owed (a config request got no answer), this also
    // asks for /v1/config - at once, then not closer than the refresh throttle to the previous such
    // refetch (ConfigCachePolicy.h::refetchConfigOnApiSuccess); true = it was asked for now. The
    // failure of such a refetch does not vote in the edge walk.
    // directRoute: the request that succeeded was sent while no tunnel of ours was up and after the last network
    // change (only then does the success say the DIRECT control plane is reachable on this network).
    bool reportNetworkSuccess(bool directRoute = false);
    // Decision 2026-11-05: /v1/subscription outcome for its own per-edge streak (EdgeWalk.h::
    // SubscriptionEdgeStreak); requestBase = the edge the request went to. failed = transport failure
    // (classifySubscriptionEdgeOutcome); ignored outcomes are not reported. true = the active edge
    // was switched now (2 failures in a row on it).
    bool reportSubscriptionOutcome(const QString &requestBase, bool failed);
    // Волна-4 (ENG-03): iOS обновлял конфиг только перезапуском процесса (таймер — macOS-only).
    // Координатор выхода на экран зовёт это раз в >= 15 мин; дедуп по m_configInFlight внутри.
    void refreshIfStale(qint64 maxAgeMs);

signals:
    void directApiReachChanged(avpn::ApiReach reach); // every flip of directApiReach() as observed here
    void directRouteProved();                         // every answer of the API on the direct route (also with the fact unchanged)
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
    // verify → parse → cache → emit. order - the start number of the request that carried the body:
    // an answer is not applied once a request started LATER has been applied (see m_appliedOrder).
    void applyBody(const QByteArray &body, const QByteArray &sigB64, quint64 order);
    int  failThreshold() const;
    bool switchToNextEdge(); // existing rotation (cached /v1/edges order, baked fallback); false = no other edge
    qint64 nowMs() const;
    // The cached copy: features.xray_client by the bounded trust. true = the value in m_config changed.
    bool judgeCachedXray();

    QNetworkAccessManager *m_nam = nullptr;
    QString      m_activeBase;
    QString      m_sessionEdge; // the control plane's edge while a tunnel carries requests (R1a)
    bool         m_edgeAnswered = false; // the direct edge gave an HTTP answer in this run (fast failover)
    static constexpr int kFastEdgeFirstTryMs = 2500;
    int          m_fastEdgeMs = kFastEdgeFirstTryMs;
    qint64       m_pauseBaseTest = -1, m_pauseCapTest = -1; // test overrides of the round pause numbers
    // R9: silent edges since the last HTTP answer / round start, finished unsuccessful rounds, and the pause timer.
    int          m_walkSilent = 0;       // pacing of the walk's rounds only; the FACT is derived from m_silentEdges
    QSet<QString> m_silentEdges;         // edges silent on their quick try under m_silentGen, sent with no tunnel up
    quint64      m_silentGen = 0;
    void clearReach();
    int          m_walkRounds = 0;
    QTimer       m_walkPause;
    QTimer       m_askLater;                         // the one deferred direct ask (askDirectOnce's spacing)
    void setReach(ApiReach r);
    void noteEdgeNotTheApi(const QString &edge, quint64 generation);
    bool tunnelUp() const { return m_tunnelUpFn && m_tunnelUpFn(); }
    quint64 generationNow() const { return m_generationFn ? m_generationFn() : 0; }
    void askDirectOnce();
    // At most one direct ask per network generation and per kAskSpacingMs (flapping LTE: a few asks a minute at most).
    static constexpr qint64 kAskSpacingMs = 30000;
    static constexpr int kAskBusyRetryMs = 1000;     // an ask that found a request in flight comes back after this
    std::function<bool()> m_tunnelUpFn;
    quint64        m_askedGen = 0;
    bool           m_askedAny = false;
    qint64         m_lastAskMs = -1;
    qint64         m_netChangeMs = 0;
    ApiReach       m_reach = ApiReach::Unknown;
    quint64        m_reachGen = 0;                    // the network generation the fact was observed under
    std::function<quint64()> m_generationFn;
    void walkPauseElapsed();
    bool leaveWalkPause();
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
    bool         m_cachedUpstreamSigned = false;   // upstream nodes: the cached signed value
    qint64       m_cachedUpstreamMaxAgeMs = 0;     // its own bound (numbers.upstream_nodes_cache_max_age_h)
    bool         m_upstreamTrustExpired = false;   // one-way within a run, as the Xray trust
    qint64       m_cachedAtMs = 0;
    qint64       m_cachedMaxAgeMs = 0;
    qint64       m_cachedAgeMs = -1;
    XrayPolicy   m_xrayPolicy = XrayPolicy::NoConfig;
    CachedTrust  m_cachedTrust;         // one-way within a run: an expired trust is not revived
    std::function<qint64()> m_nowMsFn;  // test clock (empty = the system clock)
    // 5.1.109 (reviews of d5d739403 and 3dbe0361f): the edge switch and the owed refetch.
    quint64        m_configSeq = 0;       // bumped by an edge switch: the request in flight went to the old edge
    // 5.1.109 (review of df7f49db8): after an edge switch two requests are in flight and the body
    // carries no version - only the order in which the requests were STARTED tells which answer is
    // newer. An answer of an earlier request is still applied when it comes first.
    quint64        m_requestOrder = 0;    // the start number of the last config request
    quint64        m_appliedOrder = 0;    // the start number of the request whose answer is in force
    bool           m_refetchOwed = false; // a config request got no answer while on the cached copy
    qint64         m_lastRefetchMs = -1;  // when reportNetworkSuccess last asked (spacing)
};

} // namespace avpn
