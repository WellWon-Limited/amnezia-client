// AVPN serviceEngine — ранжирование нод для шторки выбора (CLIENT: «выбор по скорости»). [чистая логика]
//
// Кроссплатформенно (только Qt-типы) — общий код для iOS/Android/macOS/Windows. Источник RTT (нативный
// пинг/проба) сюда НЕ входит: этот файл лишь превращает измеренные RTT в порядок строк и уровень палочек.
//   • Порядок в шторке: быстрые ВНИЗУ (ближе к пальцу), медленные выше, НЕИЗМЕРЕННЫЕ — сверху
//     (ещё не знаем скорость, пусть свежеизмеренные быстрые «тонут» вниз). Стабильно (равные не дёргаются).
//   • Палочки: переиспользуем щедрую VPN-шкалу SignalQuality::barsForRtt (единый порог во всём движке).
#pragma once

#include "SignalQuality.h"

#include <QHash>
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

// Server picker / Connect card: what a row SHOWS (owner test of 5.1.102, 2026-11-05). An Xray
// listener shares its exit host (location = host_id) with an AWG node, but its off-tunnel ICMP RTT
// is measured to the RU entry that relays every listener (~14 ms everywhere), and its label may
// come empty. A row therefore shows its exit, never the entry and never the raw region code:
//  - rttMs: an Xray row takes the measured RTT of a non-Xray sibling on the same location;
//    no measured sibling -> -1 ("—"). Other rows keep their own RTT;
//  - name: its own label, else the label of a sibling on the same location (non-Xray first),
//    else fallbackName (the localized country name, filled by the caller).
// Display only: selection keeps the engine's own measurements.
struct PickerRow {
    QString location;     // NodeRotation.h::locationKeyOf ("" = no grouping)
    QString proto;        // "" = awg
    QString name;         // label from the subscription (may be empty)
    QString fallbackName; // localized country name
    int     rttMs = -1;   // measured off-tunnel RTT, -1 = none
};

inline QList<PickerRow> pickerDisplay(QList<PickerRow> rows)
{
    const auto isXray = [](const PickerRow &r) { return r.proto == QLatin1String("xray"); };
    QHash<QString, int> exitRtt;        // location -> min measured RTT of a non-Xray row
    QHash<QString, QString> label;      // location -> label of a non-Xray row
    QHash<QString, QString> anyLabel;   // location -> label of any row
    for (const PickerRow &r : rows) {
        if (r.location.isEmpty())
            continue;
        if (!isXray(r) && r.rttMs >= 0 && (!exitRtt.contains(r.location) || r.rttMs < exitRtt.value(r.location)))
            exitRtt.insert(r.location, r.rttMs);
        if (r.name.isEmpty())
            continue;
        if (!isXray(r) && !label.contains(r.location))
            label.insert(r.location, r.name);
        if (!anyLabel.contains(r.location))
            anyLabel.insert(r.location, r.name);
    }
    for (PickerRow &r : rows) {
        if (isXray(r))
            r.rttMs = r.location.isEmpty() ? -1 : exitRtt.value(r.location, -1);
        if (r.name.isEmpty())
            r.name = label.value(r.location, anyLabel.value(r.location));
        if (r.name.isEmpty())
            r.name = r.fallbackName;
    }
    return rows;
}

} // namespace avpn
