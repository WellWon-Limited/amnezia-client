// AVPN serviceEngine — проба «работает ли конкретный сервис ЧЕРЕЗ эту ноду прямо сейчас». [IN-FORK / QtNetwork]
//
// Зачем: в РФ Telegram/YouTube чаще НЕ блокируют, а ДУШАТ по SNI/IP — reachability («200 OK») = ложно-зелёный.
// Замер обязан идти С УСТРОЙСТВА через туннель (доступность = f(юзер,сеть,регион,нода,время); бэкенд её не
// знает — см. memory tribe-real-signal-quality). Два вида проб:
//   • Mtproto (Telegram): login-free handshake к seed-DC-IP — TCP→intermediate-тег→req_pq_multi→resPQ
//     (MtprotoProbe). resPQ с нашим nonce ⇒ DC реально говорит по MTProto через туннель (сильнее TCP-connect).
//   • Https (YouTube/прочие): TLS-complete с РЕАЛЬНЫМ SNI + TTFB. NB: точный детект троттлинга YouTube
//     требует SNI *.googlevideo.com и резолва подписанного videoplayback-URL (yt-dlp/n-cipher) — это
//     раннер пока НЕ делает; https-проба к www.youtube.com = грубая reachability, помечена TODO.
//
// АСИНХРОННО (анти-фриз §tribe-engine-net-async): сокеты/таймеры event-driven, БЕЗ nested QEventLoop.
// Кэш результата per-нода и каденс (on-connect + по тапу, НЕ поллинг) — на стороне вызывающего (AvpnEngineQml).
#pragma once

#include "GoodputProbe.h"

#include <QHostAddress>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>

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
    bool inFlight() const { return m_remaining > 0; }

signals:
    void result(const QString &key, int state /*ServiceState*/, int rttMs);
    void allDone();

private:
    void probeMtproto(const ServiceProbeConfig &c, int timeoutMs);
    // Один seed-DC из списка: успех → finish(works/slow); провал → следующий seed; все провалились → finish(blocked).
    void attemptMtprotoHost(const QString &key, const QStringList &hosts, int idx, int port,
                            int perHostMs, int slowMs);
    void probeHttps(const ServiceProbeConfig &c, int timeoutMs);

    // Goodput: качаем sampleBytes с реального byte-source на душимом CDN и классифицируем kbit/s.
    void probeGoodput(const ServiceProbeConfig &c);
    void resolveYoutube(const ServiceProbeConfig &c, const QStringList &videoIds, int idx);
    void resolveInstagram(const ServiceProbeConfig &c);
    // Скачать N байт по готовому URL и померить скорость → finish(works/slow/blocked). rttMs слот = kbit/s.
    void measureGoodput(const ServiceProbeConfig &c, const QString &url, bool rangeAsQuery);
    // Fail-safe: byte-source не резолвится → проверить хотя бы TLS-достижимость CDN. reachable ⇒ Unknown
    // (честно «не смогли измерить»), reset/timeout ⇒ Blocked. Никогда не выдаём ложный works.
    void goodputFallback(const ServiceProbeConfig &c);

    void finish(const QString &key, ServiceState st, int rttMs);

    QNetworkAccessManager    *m_nam = nullptr;
    QList<ServiceProbeConfig> m_cfgs;
    int                       m_remaining = 0;
};

} // namespace avpn
