// client/core/serviceEngine/ConfigService.cpp
#include "ConfigService.h"

#include "ConfigStore.h"
#include "Ed25519Verify.h"
#include "EdgeWalk.h"
#include "NetAwait.h"

#include <QDateTime>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>

namespace avpn {

ConfigService::ConfigService(QNetworkAccessManager *nam, const QString &baseUrl,
                             const QString &pubKeyHex, const QStringList &bakedEdges,
                             QObject *parent, bool pinned)
    : QObject(parent), m_nam(nam), m_pubKeyHex(pubKeyHex), m_bakedEdges(bakedEdges), m_refreshTimer(this),
      m_pinned(pinned && !baseUrl.isEmpty())
{
    // 5.1.108: a pinned control plane (AVPN_API_URL) is used as is. Before, the stored active edge of
    // an earlier run won over the env var, and the edge walk moved a dev session to the prod edges.
    m_activeBase = m_pinned ? baseUrl
                            : ConfigStore::activeEdge(baseUrl.isEmpty() && !bakedEdges.isEmpty()
                                                          ? bakedEdges.first()
                                                          : baseUrl);
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    // macOS часто работает неделями без выхода: обновления должны обнаруживаться
    // и в уже открытом приложении. После сна Qt доставит просроченный timeout.
    m_refreshTimer.setObjectName(QStringLiteral("macosConfigRefresh"));
    m_refreshTimer.setInterval(15 * 60 * 1000);
    connect(&m_refreshTimer, &QTimer::timeout, this, &ConfigService::fetchConfig);
#endif
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
            c.features.insert(QStringLiteral("node_scan"), false);
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

// 5.1.109: the two S4.1 changes of this file act only where the client can raise Xray at all (iOS and
// macOS - NodeRotation.h::xrayClientSupported). On Android, Windows and Linux the cached copy stays
// frozen exactly as before 139 and the config is asked for at the same moments as before.
#if defined(Q_OS_IOS) || defined(Q_OS_MACOS)
static constexpr bool kXrayPlatform = true;
#else
static constexpr bool kXrayPlatform = false;
#endif

bool ConfigService::judgeCachedXray()
{
    const qint64 now = nowMs();
    const XrayClientDecision d = decideXrayClient(/*fresh=*/false, m_cachedXraySigned, m_cachedAtMs, now,
                                                  kXrayPlatform ? m_cachedMaxAgeMs : 0);
    m_xrayPolicy = d.why;
    m_cachedAgeMs = (m_cachedAtMs > 0 && now >= m_cachedAtMs) ? now - m_cachedAtMs : -1;
    const QString key = QStringLiteral("xray_client");
    const bool changed = featureFlag(m_config, key, !d.allowed) != d.allowed;
    m_config.features.insert(key, d.allowed);
    return changed;
}

void ConfigService::fetchConfig()
{
    // 5.1.109: still on the cached copy - the bounded trust in its signed xray_client=true is judged
    // again before every request for a fresh one (a process may live for days without an answer from
    // the API). No timer of its own: start, a return to the screen, an edge switch, an API success
    // and the macOS refresh timer all come through here. The change is announced from the event
    // loop: this function is also entered from inside other requests' answer handlers.
    if (!m_fresh && m_config.valid && judgeCachedXray())
        QTimer::singleShot(0, this, [this]() { emit configApplied(m_config); });
    if (!m_nam || m_configInFlight)
        return;
    m_configInFlight = true;
    m_lastFetchMs = QDateTime::currentMSecsSinceEpoch();
    QNetworkRequest req{QUrl(m_activeBase + QStringLiteral("/v1/config"))};
    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        m_configInFlight = false;
        reply->deleteLater();
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
            m_lastFetchMs = -1;
            if (!m_fresh)
                QTimer::singleShot(0, this, &ConfigService::fetchConfig);
            return;
        }
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        // Только транспортный сбой = проблема ЭТОГО входа → повод шагнуть на другой edge:
        // code==0 (abort/timeout из armTimeout, либо сокет не подключился) или 5xx (серверная авария).
        // Ревью 2026-07-12 (finding 2): для ДЕТЕКТОРА белых списков классификация ДРУГАЯ —
        // любой дошедший HTTP-статус (вкл. 5xx: бэк упал, но сеть жива) = transportOk;
        // транспортный фейл только code==0. Иначе обычный 5xx-инцидент бэка кормил детектор.
        if (code == 0 || code >= 500) {
            if (code == 0)
                emit transportFailed();
            else
                emit transportOk();
            // Owner test 06.11: while this process still runs on the LKG copy (cached policy in force),
            // a failed fetch does not throttle the foreground refresh - the next return retries.
            // 5.1.109: the same mark lets the next API success of another request ask again
            // (reportNetworkSuccess, ConfigCachePolicy.h::refetchConfigOnApiSuccess).
            if (!m_fresh)
                m_lastFetchMs = -1;
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
        const QByteArray body = reply->readAll();
        const QByteArray sig = reply->rawHeader(QByteArrayLiteral("X-Tribe-Sig"));
        applyBody(body, sig);
    });
}

void ConfigService::fetchEdges()
{
    if (!m_nam)
        return;
    QNetworkRequest req{QUrl(m_activeBase + QStringLiteral("/v1/edges"))};
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

void ConfigService::applyBody(const QByteArray &body, const QByteArray &sigB64)
{
    if (!verifyDetached(m_pubKeyHex, body, sigB64))
        return; // подпись не прошла → игнор, остаёмся на кеше/дефолтах
    RemoteConfig c;
    QString err;
    if (!parseConfig(body, c, err))
        return;
    m_config = c;
    m_fresh = true;
    // 5.1.109: the fresh signed value is in force as it is ("off" wins at once, "on" for this run);
    // the receive time is stored with the body - the next cold start trusts a cached "on" only for a
    // bounded time after it (ConfigCachePolicy.h).
    m_xrayPolicy = decideXrayClient(/*fresh=*/true, featureFlag(c, QStringLiteral("xray_client"), false), 0, 0, 0).why;
    m_cachedAgeMs = -1;
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
bool ConfigService::reportNetworkSuccess()
{
    m_failStreak = 0;
    // 5.1.109 (defect of 12.11.2026 on 138): an API path works again - if this process is still on the
    // cached config because its own request failed in transport, ask now instead of waiting for the
    // next return to the screen (iOS has no periodic config refresh). Rides on requests the app makes
    // anyway (bootstrap retry, subscription and account refresh); in-flight dedup is in fetchConfig.
    // iOS and macOS only (kXrayPlatform): the other platforms keep their refresh moments unchanged.
    if (kXrayPlatform && m_nam && refetchConfigOnApiSuccess(m_fresh, m_configInFlight, m_lastFetchMs)) {
        fetchConfig();
        return true;
    }
    return false;
}

void ConfigService::refreshIfStale(qint64 maxAgeMs)
{
    if (m_lastFetchMs > 0 && QDateTime::currentMSecsSinceEpoch() - m_lastFetchMs < maxAgeMs)
        return;
    fetchConfig();
}

void ConfigService::reportNetworkFailure()
{
    // Волна-4 (P2-2): стрик без затухания копил отказы часами (таймауты после заморозки iOS
    // 40% /v1/subscription с кодом 0) и шагал на другой вход по трём несвязанным событиям.
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (m_lastFailMs > 0 && now - m_lastFailMs > 60000)
        m_failStreak = 0;
    m_lastFailMs = now;
    if (++m_failStreak < failThreshold())
        return;
    m_failStreak = 0;
    switchToNextEdge();
}

bool ConfigService::reportSubscriptionOutcome(const QString &requestBase, bool failed)
{
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
    m_activeBase = next;
    ConfigStore::setActiveEdge(next);
    emit activeEdgeChanged(next);
    fetchConfig(); // немедленно пробуем новый вход
    return true;
}

} // namespace avpn
