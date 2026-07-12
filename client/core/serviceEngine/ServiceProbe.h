// AVPN serviceEngine — проба «работает ли конкретный сервис ЧЕРЕЗ эту ноду прямо сейчас». [IN-FORK / QtNetwork]
//
// Зачем: в РФ Telegram/YouTube чаще НЕ блокируют, а ДУШАТ по SNI/IP — reachability одного URL = ложно-зелёный,
// а одиночный goodput-сэмпл = флап. Замер обязан идти С УСТРОЙСТВА через туннель (доступность =
// f(юзер,сеть,регион,нода,время); бэкенд её не знает — см. memory tribe-real-signal-quality).
//
// v2 (2026-07-12, анти-флап; решения — ChipLogic.h, ресёрч OONI ts-020/ts-019 + sing-box urltest):
//   • Mtproto (Telegram): login-free handshake к seed-DC-IP — TCP→intermediate-тег→req_pq_multi→resPQ
//     (MtprotoProbe). resPQ с нашим nonce ⇒ DC реально говорит по MTProto через туннель (сильнее TCP-connect).
//   • Goodput (YouTube/Instagram) = ДВА СЛОЯ:
//     1) reachability-КВОРУМ: два лёгких голоса разных контуров (web/API-tier + CDN-tier; вкомпилены в
//        ServiceProbeTargets.h, server-driven через lists.chip_reach_urls_<key>). «Заблокировано» — только
//        когда упали ОБА (жёстко или тихим дропом); один контур RST при живом втором ⇒ потолок slow.
//     2) КАЧЕСТВО только уточняет works|slow при доказанной reachability: YouTube — InnerTube `player`
//        (YoutubeSource) → ranged-GET по SNI *.googlevideo.com (реально-душимый путь) и kbit/s
//        (GoodputProbe); Instagram — TTFB голосов. Провал качества (протухший InnerTube/403) больше
//        НЕ красит чип серым/красным — reachability уже решила.
//   • Https: TLS-reachability с реальным SNI (для серверных целей без пары голосов).
// Гонки смены ноды: invalidate() поднимает поколение — результаты старой серии молча выбрасываются
// (finish gen-гейт), продолжения цепочек (следующий seed/видео) не стартуют.
//
// АСИНХРОННО (анти-фриз §tribe-engine-net-async): сокеты/таймеры event-driven, БЕЗ nested QEventLoop.
// Гистерезис показа, каденс (on-connect + self-heal + тап) и freshness — на стороне AvpnEngineQml.
#pragma once

#include "ChipLogic.h"
#include "GoodputProbe.h"

#include <QHostAddress>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>

#include <functional>

class QNetworkAccessManager;

namespace avpn {

// Статус сервиса для чипа. blocked: путь не отвечает корректно (заблокирован/задушен в ноль).
// slow: ответил, но медленно (вероятный троттлинг). works: ответил быстро/на нормальной скорости.
// unknown: не смогли ЧЕСТНО измерить (напр. резолв byte-source сломался, но путь достижим) — не врём зелёным.
enum class ServiceState { Unknown = -1, Blocked = 0, Slow = 1, Works = 2 };

struct ServiceProbeConfig {
    // Goodput: РЕАЛЬНЫЙ замер kbit/s на душимом пути (YouTube/Instagram). Mtproto: Telegram-handshake.
    // Https: TLS-reachability (устаревшее для соцсетей — оставлено как деградация).
    enum Kind { Mtproto, Https, Goodput };
    QString          key;            // "telegram","youtube","instagram",…
    Kind             kind = Https;
    QString          host;           // Mtproto: ПЕРВЫЙ seed DC IP; Https: SNI/GET-хост; Goodput: fallback-хост
                                     // reachability на душимом CDN (напр. redirector.googlevideo.com / static.cdninstagram.com).
    int              port = 443;
    int              slowMs = 1500;  // Https: RTT/TTFB выше ⇒ Slow. Goodput не использует (там пороги kbit/s).
    QStringList      fallbackHosts;  // Mtproto: запасные seed DC IP (пробуем по очереди; первый resPQ → works).
                                     // Зачем: один IP мог смениться/лечь → ложный «заблок». DC-IP не статичны
                                     // (core.telegram.org/api/datacenter); правильный рефреш — help.getConfig (TODO).
    qint64           sampleBytes = 131072;  // Goodput: сколько байт качаем для замера (128 КБ — хватает и дёшево).
    GoodputThresholds goodput;              // Goodput: пороги works/slow/blocked (kbit/s).
    QStringList      reachUrls;             // Goodput v2: 2 лёгких reachability-голоса разных контуров
                                            // (web/API-tier + CDN-tier); server-driven через
                                            // lists.chip_reach_urls_<key>, вкомпиленное — фолбэк.
                                            // Пусто ⇒ одиночная деградация goodputFallback (host).
};

class ServiceProbe : public QObject {
    Q_OBJECT
public:
    explicit ServiceProbe(QNetworkAccessManager *nam, QObject *parent = nullptr);

    void setServices(const QList<ServiceProbeConfig> &cfgs) { m_cfgs = cfgs; }
    QList<ServiceProbeConfig> services() const { return m_cfgs; }

    // Запустить пробу всех сервисов (идемпотентно, пока серия в полёте). Результат — сигнал result()
    // на каждый сервис + allDone() в конце.
    void probeAll(int timeoutMs = 6000);
    // Повторная проба одного сервиса по key (авто-ретрай Unknown / подтверждение ухудшения гистерезиса).
    void probeOne(const QString &key, int timeoutMs = 6000);
    bool inFlight() const { return m_remaining > 0; }
    // Смена ноды/обрыв: поднять поколение — результаты in-flight серии молча выбрасываются
    // (гонка «вердикт старой ноды в чипе новой» — девайс-баг 2026-07-12), продолжения цепочек не стартуют.
    void invalidate() { ++m_gen; m_remaining = 0; }

signals:
    void result(const QString &key, int state /*ServiceState*/, int rttMs);
    void allDone();

private:
    void startOne(const ServiceProbeConfig &c, int timeoutMs, int gen);
    void probeMtproto(const ServiceProbeConfig &c, int timeoutMs, int gen);
    // Один seed-DC из списка: успех → finish(works/slow); провал → следующий seed; все провалились → finish(blocked).
    void attemptMtprotoHost(int gen, const QString &key, const QStringList &hosts, int idx, int port,
                            int perHostMs, int slowMs);
    void probeHttps(const ServiceProbeConfig &c, int timeoutMs, int gen);

    // Goodput v2: слой 1 — reachability-кворум двух голосов (ChipLogic.h); слой 2 — качество.
    void probeGoodput(const ServiceProbeConfig &c, int gen);
    void probeReachPair(const ServiceProbeConfig &c, const QStringList &urls, int gen);
    // Один лёгкий reachability-голос: GET url, TTFB; done(outcome, rttMs) ровно один раз.
    void runReachVoice(const QString &url, int timeoutMs, std::function<void(VoiceOutcome, int)> done);
    // Качество YouTube при доказанной reachability: InnerTube → ranged-GET googlevideo → works|slow.
    // Любой провал цепочки ⇒ works с потолком cap (reachability уже решила — серым/красным не красим).
    void qualityYoutube(const ServiceProbeConfig &c, int cap, int quorumRtt,
                        const QStringList &videoIds, int idx, int gen);
    // Скачать N байт по готовому URL и померить kbit/s; вердикт = qMin(cap, refineReachable(classify)).
    void measureGoodput(const ServiceProbeConfig &c, int cap, int quorumRtt, const QString &url,
                        bool rangeAsQuery, int gen);
    // Деградация для целей БЕЗ пары голосов (серверный goodput неизвестного сервиса): TLS-достижимость
    // host. reachable ⇒ Unknown (честно «не измерили»), reset/timeout ⇒ Blocked.
    void goodputFallback(const ServiceProbeConfig &c, int gen);

    void finish(int gen, const QString &key, ServiceState st, int rttMs);

    QNetworkAccessManager    *m_nam = nullptr;
    QList<ServiceProbeConfig> m_cfgs;
    int                       m_remaining = 0;
    int                       m_gen = 0; // поколение серии (гейт finish/цепочек после invalidate)
};

} // namespace avpn
