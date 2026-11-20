// client/core/serviceEngine/ConfigService.cpp
#include "ConfigService.h"

#include "ConfigStore.h"
#include "Ed25519Verify.h"
#include "EdgeWalk.h"
#include "NetAwait.h"
#include "NodeRotation.h" // AVPN release C: xrayPlatformEnabledBy (Android/Windows platform switch)
#include "UpstreamNode.h" // AVPN upstream nodes: the bounded trust of the cached features.upstream_nodes

#include <QDateTime>
#include <QDebug>
#include <QTimer>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>

namespace avpn {

ConfigService::ConfigService(QNetworkAccessManager *nam, const QString &baseUrl,
                             const QString &pubKeyHex, const QStringList &bakedEdges,
                             QObject *parent, bool pinned)
    : QObject(parent), m_nam(nam), m_pubKeyHex(pubKeyHex), m_bakedEdges(bakedEdges), m_refreshTimer(this), m_walkPause(this), m_askLater(this),
      m_pinned(pinned && !baseUrl.isEmpty())
{
    // 5.1.108: a pinned control plane (AVPN_API_URL) is used as is. Before, the stored active edge of
    // an earlier run won over the env var, and the edge walk moved a dev session to the prod edges.
    // R1a (device round 4): every run starts at the Russian entry for direct requests; the walk of an earlier run
    // (and a session edge of a run that was force-quit) is never restored - a sticky foreign edge froze every seat
    // answer above ~15 KB from Russia.
    m_activeBase = m_pinned || !baseUrl.isEmpty() ? baseUrl : (bakedEdges.isEmpty() ? QString() : bakedEdges.first());
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // macOS часто работает неделями без выхода: обновления должны обнаруживаться
    // и в уже открытом приложении. После сна Qt доставит просроченный timeout.
    m_refreshTimer.setObjectName(QStringLiteral("macosConfigRefresh"));
    m_refreshTimer.setInterval(15 * 60 * 1000);
    connect(&m_refreshTimer, &QTimer::timeout, this, &ConfigService::fetchConfig);
#endif
    m_walkPause.setObjectName(QStringLiteral("edgeRoundPause"));
    m_walkPause.setSingleShot(true);
    connect(&m_walkPause, &QTimer::timeout, this, &ConfigService::walkPauseElapsed);
    m_askLater.setSingleShot(true);
    connect(&m_askLater, &QTimer::timeout, this, &ConfigService::askDirectOnce);
}

void ConfigService::start()
{
    // 1) LKG из кеша — мгновенно, без сети.
    const QByteArray lkg = ConfigStore::loadConfig();
    if (!lkg.isEmpty()) {
        RemoteConfig c;
        QString err;
        if (parseConfig(lkg, c, err)) {
            // 22.09.2026: a frozen transport cannot be re-enabled by an old/offline policy cache.
            // 5.1.109 (defect of 12.11.2026 on 138: after every cold start Xray was gone until the API
            // answered): the last SIGNED xray_client=true is honoured for a bounded time since it was
            // received (ConfigCachePolicy.h::decideXrayClient; the bound comes with the same signed
            // copy). Past the bound, without a receive time or with a signed "false" it is frozen as
            // before. In-memory only: the signed payload is never rewritten. A freshly verified
            // response wins at once in both directions (applyBody).
            m_cachedXraySigned = featureFlag(c, QStringLiteral("xray_client"), false);
            m_cachedAtMs = ConfigStore::configReceivedAtMs();
            m_cachedMaxAgeMs = xrayCacheMaxAgeMs(
                numberOr(c, QLatin1String(kXrayCacheMaxAgeKey), kXrayCacheMaxAgeDefaultH));
            // The honest-Connected / network-memory mechanism is NOT covered by that trust (5.1.108):
            // a server-side node_scan=false (06.11.2026 incident) must not be overridden by a stale
            // cache that still says true - until a fresh verified response authorizes it again.
            // AVPN (iOS data watch, build 141): on iOS the tunnel-side switch of the server is frozen the
            // same way (ConfigCachePolicy.h::freezeCachedFeatures).
#ifdef Q_OS_IOS
            freezeCachedFeatures(c.features, /*ios=*/true);
#else
            freezeCachedFeatures(c.features, /*ios=*/false);
#endif
            // Upstream nodes: bounded trust of the signed cached value (UpstreamNode.h), its own bound
            // from the same copy; judged with xray_client (one-way expiry within the run).
            m_cachedUpstreamSigned = featureFlag(c, QLatin1String(kUpstreamNodesFlag), false);
            m_cachedUpstreamMaxAgeMs = upstreamCacheMaxAgeMs(
                numberOr(c, QLatin1String(kUpstreamCacheMaxAgeKey), kUpstreamCacheMaxAgeDefaultH));
            m_config = c;
            judgeCachedXray();
            emit configApplied(m_config);
        }
    }
    // 2) свежий фетч (async).
    fetchConfig();
    fetchEdges();
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    m_refreshTimer.start();
#endif
}

int ConfigService::failThreshold() const
{
    const int t = static_cast<int>(numberOr(m_config, QStringLiteral("edge_fail_threshold"), 3));
    return t < 1 ? 1 : t;
}

qint64 ConfigService::nowMs() const
{
    return m_nowMsFn ? m_nowMsFn() : QDateTime::currentMSecsSinceEpoch();
}

qint64 ConfigService::cachedConfigAgeMin() const
{
    return m_cachedAgeMs < 0 ? -1 : m_cachedAgeMs / 60000;
}

// 5.1.109: the S4.1 changes of this file act only where the client can raise Xray at all (iOS and
// macOS - NodeRotation.h::xrayClientSupported). On Android, Windows and Linux the cached copy stays
// frozen exactly as before 139, the config is asked for at the same moments, every transport failure
// of a config request votes in the edge walk and an edge switch does not ask the new edge while a
// request to the old one is in flight - as before.
// Release C (lane P1): Android and Windows get the same behaviour only while their own signed switch
// (xray_client_android / xray_client_windows, default false) is on in the config this service holds and
// the runtime is present (NodeRotation.h::xrayPlatformEnabledBy); iOS/macOS - always, as before.
static bool xrayPlatformIn(const RemoteConfig &c)
{
    return xrayPlatformEnabledBy(c.features);
}

bool ConfigService::judgeCachedXray()
{
    const qint64 now = nowMs();
    // One-way within a run (judgeCachedTrust): an expired trust is not revived by a clock change.
    const XrayClientDecision d = judgeCachedTrust(m_cachedTrust, m_cachedXraySigned, m_cachedAtMs, now,
                                                  xrayPlatformIn(m_config) ? m_cachedMaxAgeMs : 0);
    m_xrayPolicy = d.why;
    m_cachedAgeMs = (m_cachedAtMs > 0 && now >= m_cachedAtMs) ? now - m_cachedAtMs : -1;
    const QString key = QStringLiteral("xray_client");
    bool changed = featureFlag(m_config, key, !d.allowed) != d.allowed;
    m_config.features.insert(key, d.allowed);
    // Upstream nodes: the same one-way judgement with its own bound (Apple platforms only, like Xray).
    bool upstream = xrayPlatformIn(m_config)
                    && upstreamTrustedFromCache(m_cachedUpstreamSigned, m_cachedAtMs, now, m_cachedUpstreamMaxAgeMs);
    if (m_cachedUpstreamSigned && m_cachedAtMs > 0 && now - m_cachedAtMs >= m_cachedUpstreamMaxAgeMs)
        m_upstreamTrustExpired = true;
    if (m_upstreamTrustExpired)
        upstream = false;
    const QString ukey = QLatin1String(kUpstreamNodesFlag);
    changed = changed || featureFlag(m_config, ukey, !upstream) != upstream;
    m_config.features.insert(ukey, upstream);
    return changed;
}

// 5.1.109: still on the cached copy - the bounded trust in its signed xray_client=true is judged
// again (a process may live for days without an answer from the API). No timer of its own: every
// config request, the foreground refresh even when it is throttled, and every API outcome the
// facade reports come through here. The change is announced from the event loop: this is also
// entered from inside other requests' answer handlers.
void ConfigService::rejudgeCachedXray()
{
    if (!m_fresh && m_config.valid && judgeCachedXray())
        QTimer::singleShot(0, this, [this]() { emit configApplied(m_config); });
}

void ConfigService::fetchConfig()
{
    requestConfig(/*startedByApiSuccess=*/false);
}

void ConfigService::requestConfig(bool startedByApiSuccess)
{
    rejudgeCachedXray();
    if (!m_nam || m_configInFlight)
        return;
    if (m_walkPause.isActive())
        return; // R9: backing off after a full unsuccessful round; the pause timer, a network change or the
                // foreground (resumeEdgeWalk) and any HTTP answer end it
    m_configInFlight = true;
    m_lastFetchMs = nowMs();
    const quint64 seq = m_configSeq;
    const quint64 order = ++m_requestOrder;
    // Lane C: what this request can teach about the DIRECT route is decided by how it was SENT: while no tunnel of ours
    // was up, under this network generation (checked again at the answer).
    const bool directAtSend = !tunnelUp();
    const quint64 genAtSend = generationNow();
    const QString edgeAtSend = activeBaseUrl();
    QNetworkRequest req{QUrl(activeBaseUrl() + QStringLiteral("/v1/config"))};
    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    // Fast failover (device round 4): the first request of a run (or after a walk step) to a DIRECT edge that has not
    // answered yet gets kFastEdgeFirstTryMs to start answering (headers); silence = the edge is unreachable from here
    // and the walk steps at once - not after three 15 s failures. Once an edge answered, the usual rules apply.
    if (!m_pinned && m_sessionEdge.isEmpty() && !m_edgeAnswered) {
        QTimer::singleShot(m_fastEdgeMs, reply, [reply]() {
            if (reply->isRunning() && !reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).isValid()) {
                reply->setProperty("avpn_fast_edge", true);
                reply->abort();
            }
        });
    }
    connect(reply, &QNetworkReply::finished, this, [this, reply, seq, order, startedByApiSuccess, directAtSend, genAtSend, edgeAtSend]() {
        reply->deleteLater();
        const bool learnsDirect = directAtSend && genAtSend == generationNow();
        // The body and its signature are read once here: the fact below needs to know whose answer this is.
        const int answeredCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const bool is2xx = answeredCode >= 200 && answeredCode < 300;
        const QByteArray answerBody = is2xx ? reply->readAll() : QByteArray();
        const QByteArray answerSig = is2xx ? reply->rawHeader(QByteArrayLiteral("X-Tribe-Sig")) : QByteArray();
        if (reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).isValid()) {
            m_edgeAnswered = true;
            // Second consolidated review, R4: an HTTP answer is not yet OUR answer - a blocking middlebox answers
            // /v1/config with its own 403 page. The FACT becomes Reachable only on an answer that is provably the
            // API's: the signed config body. Any other answer (a block page, a captive portal, our own 5xx) proves no
            // route: the edge joins the same "did not answer as the API" set as a silent one. The edge walk's own
            // rules below are untouched (they are about leaving an edge, not about the fact).
            if (learnsDirect) {
                if (is2xx && verifyDetached(m_pubKeyHex, answerBody, answerSig))
                    setReach(ApiReach::Reachable); // a direct request, sent on this network, answered by the API
                else
                    noteEdgeNotTheApi(edgeAtSend, genAtSend);
            }
            leaveWalkPause(); // an answer: the network reaches the API, the walk's back-off is over
        }
        if (reply->property("avpn_fast_edge").toBool() && seq == m_configSeq) {
            m_configInFlight = false;
            qWarning() << "avpn config: edge" << activeBaseUrl() << "silent for" << m_fastEdgeMs
                       << "ms on its first try - the next edge now";
            emit transportFailed();
            // F7: a config request that got no answer is a config owed (as for a timeout or a 5xx): whatever ends
            // the pause that may follow - or a later API success - finds the debt in the state.
            if (!m_fresh)
                m_refetchOwed = true;
            // R9: one full round of silent edges = the network cannot reach the API now. Back off instead of
            // walking for ever; each edge still gets its quick first try inside a round.
            const int edges = edgeCandidates(ConfigStore::loadEdges(), m_bakedEdges).size();
            // Lane C: every edge silent on its quick first try = the direct control plane cannot be reached here.
            const bool allSilent = edges >= 1 && ++m_walkSilent >= edges;
            // R4 (round 9): the FACT is not a counter any stale timeout can advance - it is the set of edges that were
            // tried and stayed silent under the CURRENT generation with no tunnel up, covering every edge candidate.
            if (learnsDirect)
                noteEdgeNotTheApi(edgeAtSend, genAtSend);
            if (allSilent && edges < 2)
                m_walkSilent = 0;
            if (edges >= 2 && allSilent) {
                m_walkSilent = 0;
                ++m_walkRounds;
                const qint64 base = m_pauseBaseTest >= 0 ? m_pauseBaseTest
                    : static_cast<qint64>(numberOr(m_config, QStringLiteral("edge_round_pause_base_ms"),
                                                   static_cast<double>(kEdgeRoundPauseBaseMs)));
                const qint64 cap = m_pauseCapTest >= 0 ? m_pauseCapTest
                    : static_cast<qint64>(numberOr(m_config, QStringLiteral("edge_round_pause_cap_ms"),
                                                   static_cast<double>(kEdgeRoundPauseCapMs)));
                const qint64 pause = edgeRoundPauseMs(m_walkRounds, base, cap);
                qWarning() << "avpn config: every edge silent - round" << m_walkRounds << "over, next round in"
                           << pause << "ms";
                m_lastFetchMs = -1;
                m_walkPause.start(static_cast<int>(pause));
                return;
            }
            if (!switchToNextEdge())
                m_lastFetchMs = -1;
            return;
        }
        // 5.1.109: the active edge was switched while this request was in flight, and the new edge
        // was asked at once (switchToNextEdge). The FAILURE of this request says nothing about the
        // edge in use now and is ignored (it used to be counted against the new edge). Its ANSWER is
        // as good as any: the body is signed and does not depend on the edge that carried it - it is
        // verified and applied as 138 did (3dbe0361f dropped it: a good answer already on its way was
        // lost and the device stayed on the cached copy until the new edge answered) - unless the
        // answer of the request to the new edge, started later, is already in force (applyBody).
        if (seq != m_configSeq) {
            const int staleCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (staleCode != 0)
                emit transportOk(); // an HTTP answer: the network is alive (the white-list detector)
            if (staleCode >= 200 && staleCode < 300)
                applyBody(answerBody, answerSig, order);
            return;
        }
        m_configInFlight = false;
        // Волна-4 (P2-2, регресс 126): запрос оборвали мы сами (смена ноды/стоп гасит летящие
        // запросы), а не вход — ни отказ, ни успех; таймаут (avpn_timed_out) — честный отказ.
        if (reply->error() == QNetworkReply::OperationCanceledError && !reply->property("avpn_timed_out").toBool()) {
            // Owner test of 5.1.102 (2026-11-05): our own abort of in-flight requests on a tunnel
            // transition (AvpnEngineQml::onConnectionStateChanged) also cancels this fetch. A
            // cancelled fetch is not a fetch: the foreground refresh must not be throttled by it,
            // and while this process still runs on the LKG copy (start(): xray_client frozen or, since
            // 5.1.109, trusted for a bounded time; node_scan frozen) it is re-issued once - otherwise
            // the cached policy stays in force until the app restarts (iOS has no periodic config
            // refresh). Bounded: our aborts happen only on transitions.
            // 5.1.109: the re-issued request keeps its origin - a refetch started by an API success
            // that we aborted ourselves must not come back as a request whose failure votes.
            m_lastFetchMs = -1;
            if (!m_fresh)
                QTimer::singleShot(0, this, [this, startedByApiSuccess]() { requestConfig(startedByApiSuccess); });
            return;
        }
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        // Только транспортный сбой = проблема ЭТОГО входа → повод шагнуть на другой edge:
        // code==0 (abort/timeout из armTimeout, либо сокет не подключился) или 5xx (серверная авария).
        // Ревью 2026-07-12 (finding 2): для ДЕТЕКТОРА белых списков классификация ДРУГАЯ —
        // любой дошедший HTTP-статус (вкл. 5xx: бэк упал, но сеть жива) = transportOk;
        // транспортный фейл только code==0. Иначе обычный 5xx-инцидент бэка кормил детектор.
        if (code == 0 || code >= 500) {
            // 5.1.109 (reviews of d5d739403 and 3dbe0361f): who votes and who owes -
            // classifyConfigFailure. A refetch started by an API success and a request that outlived
            // a freeze of the process (its timer fired late - configRequestOutlivedFreeze; the stamp
            // is armTimeout's, on the system clock) count neither against the edge nor for the
            // white-list detector.
            const bool frozen = xrayPlatformIn(m_config)
                && configRequestOutlivedFreeze(reply->property("avpn_t0").toLongLong(),
                                               QDateTime::currentMSecsSinceEpoch(), kNetTimeoutMs);
            const ConfigFailure failure = classifyConfigFailure(m_fresh, startedByApiSuccess, frozen);
            if (code != 0)
                emit transportOk();
            else if (failure.voteInEdgeWalk)
                emit transportFailed();
            // Owner test 06.11: while this process still runs on the LKG copy (cached policy in force),
            // a failed fetch does not throttle the foreground refresh - the next return retries.
            if (!m_fresh)
                m_lastFetchMs = -1;
            if (failure.refetchOwed)
                m_refetchOwed = true;
            if (failure.voteInEdgeWalk)
                reportNetworkFailure();
            return;
        }
        emit transportOk();
        // Любой иной non-2xx (401/403/410/404/4xx) ДОКАЗЫВАЕТ, что edge достижим — ответ пришёл с
        // прикладного слоя. Проблема НЕ в маршруте (это авторизация/подписка/путь), уходить с
        // рабочего входа нельзя → сбрасываем стрик, тело не применяем.
        // 5.1.109: the streak is reset directly - reportNetworkSuccess() is the signal of OTHER
        // requests and may ask for the config again; the config's own answer must not do that.
        m_failStreak = 0;
        if (code < 200 || code >= 300)
            return;
        applyBody(answerBody, answerSig, order);
    });
}

// The set behind the Unreachable fact: an edge that, tried directly on this network generation, did not answer as the
// API (silent on its quick try, or answered by something else). Every current edge candidate in it = Unreachable.
void ConfigService::noteEdgeNotTheApi(const QString &edge, quint64 generation)
{
    if (m_silentGen != generation) {
        m_silentEdges.clear();
        m_silentGen = generation;
    }
    m_silentEdges.insert(edge);
    const QStringList cands = edgeCandidates(ConfigStore::loadEdges(), m_bakedEdges);
    bool covered = !cands.isEmpty();
    for (const QString &c : cands)
        covered = covered && m_silentEdges.contains(c);
    if (covered)
        setReach(ApiReach::Unreachable);
}

void ConfigService::fetchEdges()
{
    if (!m_nam)
        return;
    QNetworkRequest req{QUrl(activeBaseUrl() + QStringLiteral("/v1/edges"))};
    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code < 200 || code >= 300)
            return; // edges — вспомогательный; primary всё равно вшит
        const QByteArray body = reply->readAll();
        const QByteArray sig = reply->rawHeader(QByteArrayLiteral("X-Tribe-Sig"));
        if (!verifyDetached(m_pubKeyHex, body, sig))
            return; // не доверяем неподписанному списку зеркал
        RemoteConfig tmp;
        QString err;
        // /v1/edges — то же тело-форма {edges:[...], ttl_s}; переиспользуем парсер (edges field).
        if (!m_pinned && parseConfig(body, tmp, err) && !tmp.edges.isEmpty())
            ConfigStore::saveEdges(tmp.edges);
    });
}

void ConfigService::applyBody(const QByteArray &body, const QByteArray &sigB64, quint64 order)
{
    // 5.1.109 (review of df7f49db8): a request started later has already been applied - this answer
    // is older, whatever edge it came from and however late it lands. Without this, after an edge
    // switch the old edge's answer (xray_client=true, produced before the operator switched Xray
    // off) overwrote the new edge's "false", was stored and re-stamped, and the next cold start
    // offline trusted it.
    if (order < m_appliedOrder)
        return;
    if (!verifyDetached(m_pubKeyHex, body, sigB64))
        return; // подпись не прошла → игнор, остаёмся на кеше/дефолтах
    RemoteConfig c;
    QString err;
    if (!parseConfig(body, c, err))
        return;
    m_appliedOrder = order;
    m_config = c;
    m_fresh = true;
    // 5.1.109: the fresh signed value is in force as it is ("off" wins at once, "on" for this run);
    // the receive time is stored with the body - the next cold start trusts a cached "on" only for a
    // bounded time after it (ConfigCachePolicy.h).
    m_xrayPolicy = decideXrayClient(/*fresh=*/true, featureFlag(c, QStringLiteral("xray_client"), false), 0, 0, 0).why;
    m_cachedAgeMs = -1;
    m_refetchOwed = false;
    ConfigStore::saveConfig(body, nowMs());
    if (!m_pinned && !c.edges.isEmpty())
        ConfigStore::saveEdges(c.edges);
    emit configApplied(m_config);
}

// ВНИМАНИЕ: report* — семантика EDGE-WALK («этот вход плох», 5xx тоже повод шагнуть).
// Сигналы transportFailed/transportOk для детектора белых списков здесь НЕ эмитятся
// (ревью 2026-07-12, finding 2): у детектора иная классификация (5xx = сеть жива) —
// эмиссии стоят по местам, где известен code (fetchConfig выше; движковые фетчи зовут
// noteControlPlane* напрямую).
bool ConfigService::reportNetworkSuccess(bool directRoute)
{
    m_failStreak = 0;
    if (directRoute && m_sessionEdge.isEmpty())
        setReach(ApiReach::Reachable); // a request on the direct route was answered (not one through a tunnel)
    rejudgeCachedXray();
    // R9/F7: any API answer ends the edge walk's back-off; the config the walk was after is asked for at once.
    if (leaveWalkPause()) {
        m_refetchOwed = false;
        m_lastRefetchMs = nowMs();
        return true;
    }
    // 5.1.109 (defect of 12.11.2026 on 138): an API path works again - if this process is still on the
    // cached config and the config is owed (its own request of the usual kind got no answer), ask now
    // instead of waiting for the next return to the screen (iOS has no periodic config refresh). Rides
    // on requests the app makes anyway (bootstrap retry, subscription and account refresh). At once,
    // then never closer than the refresh throttle to the previous such refetch; its failure does not
    // vote in the edge walk and owes the next one after that spacing (ConfigCachePolicy.h).
    // iOS and macOS only (xrayPlatformIn): the other platforms keep their refresh moments unchanged.
    const qint64 now = nowMs();
    if (xrayPlatformIn(m_config) && m_nam
        && refetchConfigOnApiSuccess(m_fresh, m_configInFlight, m_refetchOwed, m_lastRefetchMs, now,
                                     kConfigRefreshThrottleMs)) {
        m_refetchOwed = false;
        m_lastRefetchMs = now;
        requestConfig(/*startedByApiSuccess=*/true);
        return true;
    }
    return false;
}

void ConfigService::refreshIfStale(qint64 maxAgeMs)
{
    rejudgeCachedXray(); // 5.1.109: the cached trust is judged also when the request below is throttled
    if (m_lastFetchMs > 0 && nowMs() - m_lastFetchMs < maxAgeMs)
        return;
    fetchConfig();
}

void ConfigService::reportNetworkFailure()
{
    rejudgeCachedXray();
    // Волна-4 (P2-2): стрик без затухания копил отказы часами (таймауты после заморозки iOS
    // 40% /v1/subscription с кодом 0) и шагал на другой вход по трём несвязанным событиям.
    const qint64 now = nowMs();
    if (m_lastFailMs > 0 && now - m_lastFailMs > 60000)
        m_failStreak = 0;
    m_lastFailMs = now;
    if (!m_sessionEdge.isEmpty())
        return; // E10: a failure on the session edge says nothing about the stored edge
    if (++m_failStreak < failThreshold())
        return;
    m_failStreak = 0;
    switchToNextEdge();
}

// R9: the pause after a full unsuccessful round is over: the next round starts at the next edge.
void ConfigService::walkPauseElapsed()
{
    if (!switchToNextEdge())
        fetchConfig();
}

// F7: the one way out of a pause (an answer to any request, a network change, the foreground). The walk exists to
// obtain a config: leaving a pause while the app is still on the cached copy sends the config request now - from the
// edge the last round ended on - so a pause never ends with "nothing owed, nothing sent". A second exit finds no
// pause and sends nothing; a request already in flight is not doubled. true = a request went out here.
bool ConfigService::leaveWalkPause()
{
    const bool paused = m_walkPause.isActive();
    m_walkSilent = 0;
    m_walkRounds = 0;
    m_walkPause.stop();
    if (!paused || m_fresh || m_configInFlight || !m_nam)
        return false;
    m_lastRefetchMs = nowMs();
    m_refetchOwed = false;
    requestConfig(/*startedByApiSuccess=*/false);
    return m_configInFlight;
}

void ConfigService::resumeEdgeWalk()
{
    leaveWalkPause(); // a new round now
}

void ConfigService::noteNetworkChanged()
{
    m_netChangeMs = nowMs();
    if (m_pinned)
        return;
    // Deferred: the network generation is bumped by a later slot of the same event.
    QTimer::singleShot(0, this, [this]() { askDirectOnce(); });
}

void ConfigService::noteTunnelDown()
{
    if (m_pinned)
        return;
    // R5 (round 9): a negative fact learned before the tunnel came up is stale now - the direct route may have
    // recovered meanwhile and an answer through the tunnel stopped the walk. Forget it and ask again (rate-bounded).
    if (m_reach == ApiReach::Unreachable)
        clearReach();
    m_silentEdges.clear();
    m_askedAny = false;
    QTimer::singleShot(0, this, [this]() { askDirectOnce(); }); // after the facade has recorded the tunnel as down
}

// Lane C: ask the direct route about the current network - but never while a tunnel of ours is up (nothing direct can
// be learned), once per network generation, not when this generation's fact is already known directly, and not closer
// than kAskSpacingMs to the previous ask. The walk starts over with the quick first try (an edge that answered on the
// old network proves nothing here); a backed-off walk ends its pause with the config request (leaveWalkPause).
// Worst flapping minute: at most 2 asks, each at most one quick try per edge.
void ConfigService::askDirectOnce()
{
    if (m_pinned || !m_nam || tunnelUp() || !m_sessionEdge.isEmpty())
        return;
    const quint64 gen = generationNow();
    if (m_askedAny && m_askedGen == gen)
        return;
    if (directApiReach() != ApiReach::Unknown)
        return;
    const qint64 now = nowMs();
    if (m_lastAskMs >= 0 && now >= m_lastAskMs && now - m_lastAskMs < kAskSpacingMs) {
        // The spacing bounds the rate, it does not cancel the ask this network is owed: one deferred ask when the
        // spacing allows (it re-checks everything above, so a tunnel, a known fact or a newer ask ends it).
        if (!m_askLater.isActive())
            m_askLater.start(int(kAskSpacingMs - (now - m_lastAskMs)));
        return;
    }
    if (m_configInFlight) {
        // A request sent before this ask is still in flight. If it was sent on the previous network its answer cannot
        // speak for this one (the stamp at send), so the ask is still owed: come back shortly and do NOT mark this
        // generation as asked (final review, F5: the ask was marked done although nothing was sent, and the fact stayed
        // Unknown on the new network). If it was sent on this network its answer sets the fact and the deferred ask ends
        // at the "known" check above.
        if (!m_askLater.isActive())
            m_askLater.start(kAskBusyRetryMs);
        return;
    }
    m_askedAny = true;
    m_askedGen = gen;
    m_lastAskMs = now;
    m_edgeAnswered = false;
    m_walkSilent = 0;
    if (!leaveWalkPause())
        fetchConfig();
}

// Lane C: the single owner of "can the direct control plane be reached on this network now". A fact observed under an
// older network generation is forgotten (Unknown), whatever it said.
ApiReach ConfigService::directApiReach() const
{
    if (m_reach == ApiReach::Unknown)
        return ApiReach::Unknown;
    if (m_generationFn && m_reachGen != m_generationFn())
        return ApiReach::Unknown;
    return m_reach;
}

void ConfigService::clearReach()
{
    const ApiReach before = directApiReach();
    m_reach = ApiReach::Unknown;
    if (before != ApiReach::Unknown)
        emit directApiReachChanged(ApiReach::Unknown);
}

void ConfigService::setReach(ApiReach r)
{
    const ApiReach before = directApiReach();
    if (r == ApiReach::Reachable)
        m_silentEdges.clear(); // a direct answer refutes every earlier silence, whichever request brought it (round 10, R5)
    m_reach = r;
    m_reachGen = m_generationFn ? m_generationFn() : 0;
    if (before != r)
        emit directApiReachChanged(r);
    // Second consolidated review, R3: a proof of the direct route is an EVENT, not only a change of the fact - a kept
    // seat release waits for exactly this, also when the fact was Reachable all along (a short API outage).
    if (r == ApiReach::Reachable)
        emit directRouteProved();
}

void ConfigService::setSessionEdge(const QString &edge)
{
    const QString before = activeBaseUrl();
    m_sessionEdge = m_pinned ? QString() : edge;
    if (activeBaseUrl() != before)
        emit activeEdgeChanged(activeBaseUrl());
}

bool ConfigService::reportSubscriptionOutcome(const QString &requestBase, bool failed)
{
    if (!m_sessionEdge.isEmpty())
        return false; // E10: the walk does not move under a session edge
    if (!m_subscriptionStreak.note(m_activeBase, requestBase, failed))
        return false;
    return switchToNextEdge();
}

bool ConfigService::switchToNextEdge()
{
    if (m_pinned)
        return false; // 5.1.108: AVPN_API_URL - the only edge, nowhere to walk
    const QStringList cands = edgeCandidates(ConfigStore::loadEdges(), m_bakedEdges);
    const QString next = nextEdge(cands, m_activeBase);
    if (next == m_activeBase)
        return false;
    m_failStreak = 0;
    m_activeBase = next; // this run only (R1a): never stored
    m_edgeAnswered = false; // its own fast first try
    emit activeEdgeChanged(next);
    // 5.1.109 (reviews of d5d739403 and 3dbe0361f): a config request still in flight went to the OLD
    // edge. Before, the in-flight guard swallowed the immediate request below, the new edge was not
    // asked until the old request ended, and its failure was then counted against the new edge. Now
    // the new edge is asked at once and the old request is left to finish: its answer is applied if
    // it comes (signed, edge-independent), only its failure is ignored (the handler in requestConfig).
    // iOS and macOS (xrayPlatformIn), where the refetch on an API success makes a request in flight at
    // this moment likely; the other platforms keep the behaviour they had.
    if (xrayPlatformIn(m_config)) {
        ++m_configSeq;
        m_configInFlight = false;
    }
    fetchConfig(); // немедленно пробуем новый вход
    return true;
}

} // namespace avpn
