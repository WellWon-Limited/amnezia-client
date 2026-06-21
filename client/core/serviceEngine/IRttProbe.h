// AVPN serviceEngine — граница ПРЯМОГО RTT-замера до нод (off-tunnel), для «выбора по скорости».
// Движок один, платформо-зависим только этот интерфейс (как ITunnelControl). Реализации:
//   • нативный ICMP-пинг per-platform (iOS/macOS: SOCK_DGRAM/IPPROTO_ICMP unprivileged; Android/Win — шим),
//   • либо кроссплатформенный UDP-зонд (QUdpSocket) — если когда-то появится эхо на ноде.
// Семантика: probeAll параллельно меряет ВСЕ цели; onSample(nodeId,rttMs) по каждой готовой
// (rttMs<0 = нет ответа), onDone() — когда все завершились/истёк таймаут. Колбэки — на главном потоке.
// ВАЖНО (физика): честный ПРЯМОЙ RTT берётся, когда туннель опущен; при поднятом full-tunnel пакет к
// чужой ноде идёт через туннель → результат смазан. Кадэнс/когда звать — забота движка, не интерфейса.
#pragma once

#include <QList>
#include <QString>
#include <functional>

namespace avpn {

struct RttTarget {
    QString nodeId;
    QString host;     // IP или хост эндпоинта ноды
    int     port = 0; // порт AWG (для UDP-зонда; ICMP игнорирует)
};

class IRttProbe {
public:
    virtual ~IRttProbe() = default;

    using SampleCb = std::function<void(const QString &nodeId, int rttMs)>;
    using DoneCb   = std::function<void()>;

    // Параллельный замер RTT до всех целей. timeoutMs — общий бюджет на цель.
    virtual void probeAll(const QList<RttTarget> &targets, int timeoutMs,
                          SampleCb onSample, DoneCb onDone) = 0;

    // Прервать текущий замер (шторка закрылась / переключились в connected). Идемпотентно.
    virtual void cancel() = 0;
};

} // namespace avpn
