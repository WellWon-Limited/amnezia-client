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

#include <QHostAddress>
#include <QList>
#include <QObject>
#include <QString>

class QNetworkAccessManager;

namespace avpn {

// Статус сервиса для чипа. blocked: путь не отвечает корректно (заблокирован/задушен в ноль).
// slow: ответил, но медленно (вероятный троттлинг). works: ответил быстро.
enum class ServiceState { Unknown = -1, Blocked = 0, Slow = 1, Works = 2 };

struct ServiceProbeConfig {
    enum Kind { Mtproto, Https };
    QString key;       // "telegram","youtube","instagram",…
    Kind    kind = Https;
    QString host;      // Mtproto: seed DC IP; Https: хост для SNI/GET (реальный SNI обязателен)
    int     port = 443;
    int     slowMs = 1500; // RTT/TTFB выше ⇒ Slow (троттлинг/далёкий путь)
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
    void probeHttps(const ServiceProbeConfig &c, int timeoutMs);
    void finish(const QString &key, ServiceState st, int rttMs);

    QNetworkAccessManager    *m_nam = nullptr;
    QList<ServiceProbeConfig> m_cfgs;
    int                       m_remaining = 0;
};

} // namespace avpn
