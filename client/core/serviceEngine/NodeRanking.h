// AVPN serviceEngine — ранжирование нод для шторки выбора (CLIENT: «выбор по скорости»). [чистая логика]
//
// Кроссплатформенно (только Qt-типы) — общий код для iOS/Android/macOS/Windows. Источник RTT (нативный
// пинг/проба) сюда НЕ входит: этот файл лишь превращает измеренные RTT в порядок строк и уровень палочек.
//   • Порядок в шторке: быстрые ВНИЗУ (ближе к пальцу), медленные выше, НЕИЗМЕРЕННЫЕ — сверху
//     (ещё не знаем скорость, пусть свежеизмеренные быстрые «тонут» вниз). Стабильно (равные не дёргаются).
//   • Палочки: переиспользуем щедрую VPN-шкалу SignalQuality::barsForRtt (единый порог во всём движке).
#pragma once

#include "SignalQuality.h"

#include <QList>
#include <QString>
#include <algorithm>

namespace avpn {

struct RankRow {
    QString nodeId;
    int     rttMs = -1; // -1 = неизмерено/недостижимо
};

// Сортировка для шторки: неизмеренные (rtt<0) — сверху; затем по убыванию rtt ⇒ самый быстрый внизу.
// stable_sort: равные rtt и группа неизмеренных сохраняют исходный порядок (нет дребезга списка).
inline QList<RankRow> rankFastestAtBottom(QList<RankRow> rows)
{
    std::stable_sort(rows.begin(), rows.end(), [](const RankRow &a, const RankRow &b) {
        const bool au = a.rttMs < 0;
        const bool bu = b.rttMs < 0;
        if (au != bu)
            return au;          // неизмеренные — выше (top)
        if (au && bu)
            return false;       // обе неизмерены — порядок не меняем
        return a.rttMs > b.rttMs; // больший rtt выше, меньший (быстрее) — ниже (bottom)
    });
    return rows;
}

// Уровень палочек 0..5 для измеренного RTT (единая шкала движка).
inline int barsForNode(int rttMs) { return SignalQuality::barsForRtt(rttMs); }

// Для авто-выбора «Авто (быстрейший)»: nodeId с МИНИМАЛЬНЫМ измеренным rtt (>=0). Пусто (""),
// если ни одна нода не измерена → движок откатывается на pickByWeight (backend-weight). Ничья rtt —
// стабильно первый по исходному порядку (детерминированно).
inline QString fastestMeasuredNodeId(const QList<RankRow> &rows)
{
    QString best;
    int bestRtt = -1;
    for (const RankRow &r : rows) {
        if (r.rttMs < 0)
            continue;
        if (bestRtt < 0 || r.rttMs < bestRtt) {
            bestRtt = r.rttMs;
            best = r.nodeId;
        }
    }
    return best;
}

} // namespace avpn
