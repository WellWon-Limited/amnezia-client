// AVPN serviceEngine — снимок состояния для диагностической панели (5 тапов по логотипу). [СКАФФОЛД]
#pragma once

#include "dto/Subscription.h"
#include <QString>
#include <QList>

namespace avpn {

struct NodeDebugRow {
    QString nodeId;
    QString region;
    QString name;            // AVPN: имя сервера (опц.)
    QString countryCode;     // AVPN: ISO-3166 alpha-2 → флаг-эмодзи в UI; пусто = нет флага
    QString endpoint;        // AVPN: "host:port" — для показа реального сервера в UI (карточка/Серверы)
    double  scoreMs = 0.0;
    bool    healthy = true;
    QString reason;          // почему так ранжирована / последний вердикт пробы
};

struct DebugSnapshot {
    QString state;                       // фаза машины состояний
    QString currentNodeId;
    qint64  latestHandshakeAgeSec = -1;
    qint64  rxBytes = 0, txBytes = 0;
    QString subStatus;                   // active/degraded
    bool    lkgStale = false;
    qint64  trafficUsed = 0, trafficLimit = 0;
    QString expiresAt;                   // AVPN: ISO-8601 из Subscription; "" = бессрочно (для daysLeft)
    QList<NodeDebugRow> pool;
    QStringList switchLog;               // «switch A→B: причина»
    // Секреты (токен/приватный ключ) сюда НЕ кладём — маскировка на уровне UI (план §7).
};

} // namespace avpn
