#include "WhitelistDetector.h"

#include <QDateTime>
#include <QDebug>
#include <QElapsedTimer>
#include <QNetworkAccessManager>
#include <QNetworkInformation>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>

namespace avpn {

namespace {

// Вкомпиленные фолбэки (§3.2 спеки) — работают офлайн/на первом запуске; боевые списки
// летят с бэка (lists.*). Пустое серверное значение НЕ стирает фолбэк (контракт TuningStore).
// Маркетплейс-tier — решающий: есть в РКН-whitelist, НЕТ в законном списке соц-значимых
// при нулевом балансе. Живой маркетплейс = точно РКН-режим, не исчерпанный тариф.
const QStringList kDefaultWhitelistDomains = {
    QStringLiteral("www.ozon.ru"), QStringLiteral("www.wildberries.ru"),
};
// Social-tier — соц-значимые: живы И при нулевом балансе, сами режим не объявляют.
const QStringList kDefaultSocialDomains = {
    QStringLiteral("www.gosuslugi.ru"), QStringLiteral("ya.ru"), QStringLiteral("vk.com"),
};
const QStringList kDefaultControlDomains = {
    QStringLiteral("api.tribevpn.com"), QStringLiteral("vpn.wellwon.hk"),
};
// Якоря: НЕ VPN-тематика, не Google/Cloudflare (точечно душатся), в РФ исторически стабильны.
const QStringList kDefaultAnchorDomains = {
    QStringLiteral("www.apple.com"), QStringLiteral("www.microsoft.com"),
};

int probeTimeoutMs()
{
    // Щедрый таймаут: медленная-но-живая сеть должна успеть ответить (анти-ложный «мёртв»).
    return qBound(2000, int(TuningStore::numberOr(QStringLiteral("whitelist_probe_timeout_ms"), 6000)),
                  15000);
}

WlFail failKindOf(QNetworkReply::NetworkError e)
{
    switch (e) {
    case QNetworkReply::HostNotFoundError:            return WlFail::Dns;
    case QNetworkReply::ConnectionRefusedError:
    case QNetworkReply::RemoteHostClosedError:        return WlFail::Tcp;
    case QNetworkReply::SslHandshakeFailedError:      return WlFail::Tls;
    case QNetworkReply::TimeoutError:
    case QNetworkReply::OperationCanceledError:       return WlFail::Timeout;
    default:                                          return WlFail::Tcp;
    }
}

} // namespace

WhitelistDetector::WhitelistDetector(QNetworkAccessManager *nam, std::function<bool()> tunnelIdle,
                                     QObject *parent)
    : QObject(parent), m_nam(nam), m_tunnelIdle(std::move(tunnelIdle))
{
    m_confirmTimer.setSingleShot(true);
    connect(&m_confirmTimer, &QTimer::timeout, this, &WhitelistDetector::maybeStartRound);

    m_exitTimer.setSingleShot(false);
    connect(&m_exitTimer, &QTimer::timeout, this, &WhitelistDetector::runExitProbe);

    m_idleRetryTimer.setSingleShot(true);
    connect(&m_idleRetryTimer, &QTimer::timeout, this, &WhitelistDetector::maybeStartRound);

    if (auto *ni = QNetworkInformation::instance()) { // backend уже загружен движком
        connect(ni, &QNetworkInformation::transportMediumChanged, this,
                [this](QNetworkInformation::TransportMedium) { onTransportChanged(); });
        connect(ni, &QNetworkInformation::reachabilityChanged, this,
                [this](QNetworkInformation::Reachability) {
                    if (m_roundInFlight)
                        abortRound(); // гигиена §3.3: сеть дёрнулась посреди раунда
                });
    }
}

bool WhitelistDetector::cellularNow() const
{
    auto *ni = QNetworkInformation::instance();
    return ni && ni->transportMedium() == QNetworkInformation::TransportMedium::Cellular;
}

void WhitelistDetector::onTransportChanged()
{
    if (m_roundInFlight)
        abortRound();
    if (!cellularNow()) {
        // Ушли с сотовой (напр. юзер послушал совет и включил Wi-Fi) — режим снимается сразу,
        // дальше штатный bootstrap сам всё проверит (kickBootstrap дёргает движок).
        m_idleRetryTimer.stop();
        m_idleRetryLeft = 0;
        const bool wasActive = m_hyst.active;
        m_hyst.feed(WlVerdict::NotApplicable, false);
        m_failStreak = 0;
        if (wasActive)
            setActive(false);
        else
            m_exitTimer.stop();
        return;
    }
    // Вошли на сотовую при недавнем подозрении — проверить сразу.
    if (m_failStreak >= 2 || m_hyst.streak > 0 || m_hyst.active)
        maybeStartRound();
}

void WhitelistDetector::noteControlPlaneFailure()
{
    ++m_failStreak;
    if (m_failStreak >= 2)
        maybeStartRound();
}

void WhitelistDetector::noteControlPlaneOk()
{
    // Любой HTTP-ответ control plane (хоть 4xx) = наша инфра достижима -> сигнатуры нет.
    m_failStreak = 0;
    if (m_hyst.active || m_hyst.streak > 0) {
        const bool wasActive = m_hyst.active;
        m_hyst.feed(WlVerdict::Normal, false);
        if (wasActive)
            setActive(false);
    }
}

void WhitelistDetector::noteConnectFailure()
{
    // Watchdog зовёт нас ДО завершения async-teardown (state ещё "connecting") — гейт
    // tunnelIdle() в maybeStartRound срежет попытку. Взводим короткий ретрай-бюджет:
    // раунд стартует, как только туннель реально осядет в disconnected (ревью, finding 1).
    m_idleRetryLeft = 5;
    maybeStartRound();
}

void WhitelistDetector::noteForeground()
{
    if (m_hyst.active)
        runExitProbe(); // немедленная проверка «а не вернулась ли сеть» при открытии app
    else if (m_failStreak >= 2 || m_hyst.streak > 0)
        maybeStartRound();
}

void WhitelistDetector::maybeStartRound()
{
    if (!TuningStore::flag(QStringLiteral("whitelist_detector"), true))
        return; // kill-switch с бэка, рантайм
    if (m_roundInFlight || !m_nam)
        return;
    if (!cellularNow() || !m_tunnelIdle || !m_tunnelIdle()) {
        // §3.1/§3.3: только сотовая + полностью опущенный туннель. Триггер от watchdog приходит
        // во время async-teardown — дотянуть старт коротким ретраем (кап m_idleRetryLeft).
        if (cellularNow() && m_idleRetryLeft > 0) {
            --m_idleRetryLeft;
            m_idleRetryTimer.start(2000);
        }
        return;
    }
    m_idleRetryLeft = 0;
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const int minGap = qBound(5000,
        int(TuningStore::numberOr(QStringLiteral("whitelist_round_min_gap_ms"), 20000)), 300000);
    // Confirm-раунды (стрик уже набирается) ходят чаще — по confirm_gap, не по общему дебаунсу.
    const int confirmGap = qBound(3000,
        int(TuningStore::numberOr(QStringLiteral("whitelist_confirm_gap_ms"), 8000)), 60000);
    const int gap = (m_hyst.streak > 0) ? confirmGap : minGap;
    if (now - m_lastRoundStartMs < gap)
        return;
    startRound();
}

void WhitelistDetector::startRound()
{
    m_roundInFlight = true;
    m_roundCellular = true; // снапшот: старт возможен только на Cellular (гейт выше)
    m_lastRoundStartMs = QDateTime::currentMSecsSinceEpoch();
    m_samples.clear();
    m_pending = 0;
    ++m_gen;

    const int t = probeTimeoutMs();
    const auto wl  = TuningStore::listOr(QStringLiteral("whitelist_probe_domains"), kDefaultWhitelistDomains);
    const auto soc = TuningStore::listOr(QStringLiteral("whitelist_social_domains"), kDefaultSocialDomains);
    const auto ctl = TuningStore::listOr(QStringLiteral("whitelist_control_domains"), kDefaultControlDomains);
    const auto anc = TuningStore::listOr(QStringLiteral("whitelist_anchor_domains"), kDefaultAnchorDomains);
    for (const auto &h : ctl) probeHost(h, /*isControl*/ true,  /*isAnchor*/ false, /*isSocial*/ false, t);
    for (const auto &h : anc) probeHost(h, /*isControl*/ true,  /*isAnchor*/ true,  /*isSocial*/ false, t);
    for (const auto &h : wl)  probeHost(h, /*isControl*/ false, /*isAnchor*/ false, /*isSocial*/ false, t);
    for (const auto &h : soc) probeHost(h, /*isControl*/ false, /*isAnchor*/ false, /*isSocial*/ true,  t);
    if (m_pending == 0)
        finishRound(); // пустые списки — вырожденный случай, не виснем
}

void WhitelistDetector::probeHost(const QString &host, bool isControl, bool isAnchor, bool isSocial,
                                  int timeoutMs)
{
    QNetworkRequest req(QUrl(QStringLiteral("https://") + host + QStringLiteral("/")));
    // Ответ ЛЮБОГО статуса = хост жив; редирект следовать не нужно (и опасно — чужой хост).
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    req.setTransferTimeout(timeoutMs);
    ++m_pending;
    const int gen = m_gen;
    auto *timer = new QElapsedTimer();
    timer->start();
    QNetworkReply *rep = m_nam->head(req);
    connect(rep, &QNetworkReply::finished, this,
            [this, rep, gen, timer, isControl, isAnchor, isSocial]() {
        const int rtt = int(timer->elapsed());
        delete timer;
        rep->deleteLater();
        if (gen != m_gen)
            return; // раунд отброшен (abortRound) — колбэк устарел
        WlSample s;
        s.isControl = isControl;
        s.isAnchor = isAnchor;
        s.isSocial = isSocial;
        s.rttMs = rtt;
        // Дошёл ЛЮБОЙ HTTP-статус -> handshake состоялся -> жив (даже если error() != NoError).
        const bool gotHttp = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).isValid();
        s.ok = (rep->error() == QNetworkReply::NoError) || gotHttp;
        if (!s.ok)
            s.fail = failKindOf(rep->error());
        m_samples.append(s);
        if (--m_pending <= 0)
            finishRound();
    });
}

void WhitelistDetector::abortRound()
{
    if (!m_roundInFlight)
        return;
    ++m_gen; // все отложенные колбэки станут no-op
    m_roundInFlight = false;
    m_pending = 0;
    m_samples.clear();
    if (m_forcedRound) { // D-3: Доктор ждёт ответ — отдать честный Inconclusive, не молчать
        m_forcedRound = false;
        auto cb = std::move(m_forcedCb);
        m_forcedCb = nullptr;
        if (cb) cb(WlVerdict::Inconclusive, false);
    }
}

// D-3 п.17: форс-прогон для Доктора. Мимо дебаунса, но предусловия валидности те же.
bool WhitelistDetector::runRoundNow(std::function<void(WlVerdict, bool)> cb)
{
    if (!m_nam || m_roundInFlight)
        return false;
    if (!TuningStore::flag(QStringLiteral("whitelist_detector"), true))
        return false; // kill-switch распространяется и на форс-прогон
    if (!cellularNow() || !m_tunnelIdle || !m_tunnelIdle())
        return false; // на Wi-Fi/при поднятом туннеле дифф-пробы не валидны
    m_forcedRound = true;
    m_forcedCb = std::move(cb);
    startRound();
    return true;
}

void WhitelistDetector::finishRound()
{
    m_roundInFlight = false;
    const WlVerdict v = decideWhitelistRound(m_samples, m_roundCellular && cellularNow());
    const bool marginal = whitelistMarginalNetwork(m_samples);
    if (m_forcedRound) { // D-3: диагностический раунд Доктора — вердикт в колбэк, гистерезис не трогаем
        m_forcedRound = false;
        auto cb = std::move(m_forcedCb);
        m_forcedCb = nullptr;
        qInfo().noquote() << QStringLiteral("avpn: whitelist FORCED round verdict=%1 marginal=%2")
                                 .arg(int(v)).arg(marginal);
        if (cb) cb(v, marginal);
        return;
    }
    const bool wasActive = m_hyst.active;
    const bool nowActive = m_hyst.feed(v, marginal);
    qInfo().noquote() << QStringLiteral("avpn: whitelist round verdict=%1 marginal=%2 streak=%3 active=%4")
                             .arg(int(v)).arg(marginal).arg(m_hyst.streak).arg(nowActive);
    if (nowActive != wasActive)
        setActive(nowActive);
    // Стрик набирается — назначить подтверждающий раунд через confirm_gap.
    if (!nowActive && v == WlVerdict::Candidate) {
        const int gap = qBound(3000,
            int(TuningStore::numberOr(QStringLiteral("whitelist_confirm_gap_ms"), 8000)), 60000);
        m_confirmTimer.start(gap);
    }
}

void WhitelistDetector::setActive(bool on)
{
    if (on) {
        const int exitMs = qBound(15000,
            int(TuningStore::numberOr(QStringLiteral("whitelist_exit_probe_ms"), 45000)), 600000);
        m_exitTimer.start(exitMs);
    } else {
        m_exitTimer.stop();
    }
    emit activeChanged(on);
}

void WhitelistDetector::runExitProbe()
{
    // Дешёвый выход: один control-хост (ротация инфра+якоря). Успех -> Normal -> режим снят.
    if (!m_hyst.active || m_roundInFlight || !m_nam)
        return;
    QStringList all = TuningStore::listOr(QStringLiteral("whitelist_control_domains"), kDefaultControlDomains)
                    + TuningStore::listOr(QStringLiteral("whitelist_anchor_domains"), kDefaultAnchorDomains);
    if (all.isEmpty())
        return;
    const QString host = all.at(m_exitRotation++ % all.size());
    QNetworkRequest req(QUrl(QStringLiteral("https://") + host + QStringLiteral("/")));
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    req.setTransferTimeout(probeTimeoutMs());
    const int gen = m_gen;
    QNetworkReply *rep = m_nam->head(req);
    connect(rep, &QNetworkReply::finished, this, [this, rep, gen]() {
        rep->deleteLater();
        if (gen != m_gen || !m_hyst.active)
            return;
        const bool alive = (rep->error() == QNetworkReply::NoError)
                        || rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).isValid();
        if (alive) {
            m_hyst.feed(WlVerdict::Normal, false);
            m_failStreak = 0;
            setActive(false);
        }
    });
}

} // namespace avpn
