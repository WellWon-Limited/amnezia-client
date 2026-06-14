// AVPN serviceEngine — app-layer RTT-проба ЧЕРЕЗ туннель (реальный «пинг» для палочек). [IN-FORK / QtNetwork]
//
// AWG = UDP-only ⇒ ICMP/TCP-пинг до эндпоинта пуст. Реальную латентность даёт крошечный HTTPS-запрос
// к generate_204 (0 байт) через поднятый full-tunnel: меряем TTFB (заголовки получены) = RTT пути VPN.
// Поток RTT → SignalQuality (EWMA+гистерезис) → 0..5 баров. Источник: research (Tailscale-модель,
// captive-portal generate_204), см. memory tribe-real-signal-quality.
//
// АСИНХРОННО (анти-фриз §tribe-engine-net-async): НЕТ вложенного QEventLoop на GUI-потоке — measure()
// лишь запускает запрос, результат прилетает сигналом result(rttMs, reachable). Несколько эндпоинтов:
// пробуем по порядку (свой /v1/ping → фолбэк generate_204), первый успешный 2xx/204 даёт RTT.
#pragma once

#include <QElapsedTimer>
#include <QObject>
#include <QPointer>
#include <QStringList>

class QNetworkAccessManager;
class QNetworkReply;
class QTimer;

namespace avpn {

class QualityProbe : public QObject {
    Q_OBJECT
public:
    explicit QualityProbe(QNetworkAccessManager *nam, QObject *parent = nullptr);

    // Список URL по приоритету (свой бэкенд-пинг, затем публичный generate_204-фолбэк).
    void setEndpoints(const QStringList &urls) { m_endpoints = urls; }
    QStringList endpoints() const { return m_endpoints; }

    // Запустить один async-замер. Игнорируется, если предыдущий ещё в полёте.
    void measure(int timeoutMs = 4000);
    bool inFlight() const { return m_inFlight; }

signals:
    // rttMs ≥ 0 и reachable=true при успехе; rttMs=-1, reachable=false если все эндпоинты не ответили.
    void result(int rttMs, bool reachable);

private:
    void tryEndpoint(int idx);
    void finishOk(int rttMs);
    void finishFail();

    QNetworkAccessManager *m_nam = nullptr;
    QStringList            m_endpoints;
    QPointer<QNetworkReply> m_reply;
    QTimer                *m_timeout = nullptr;
    QElapsedTimer          m_clock;
    int                    m_curIdx = 0;
    int                    m_timeoutMs = 4000;
    bool                   m_inFlight = false;
    qint64                 m_bust = 0; // cache-buster счётчик (вместо запрещённого Math.random — монотонный)
};

} // namespace avpn
