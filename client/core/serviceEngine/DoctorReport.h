#pragma once
// AVPN (Доктор v1, 2026-07-17): чистая логика диагностики — вердикты стадий, сборка
// JSON-отчёта и человеческое резюме. БЕЗ I/O и Qt-сети: всё тестируется юнитом
// (tests/doctor_report_check.cpp). Оркестрация (фазы/таймеры/пробы) — в AvpnEngineQml.
// Спека: tribe-front docs/superpowers/specs/2026-07-17-doctor-v1-design.md.

#include <QJsonArray>
#include <QJsonObject>
#include <QString>
#include <QStringList>

namespace doctor {

// Статус стадии для UI и отчёта.
enum StageStatus { Skip = -1, Ok = 0, Warn = 1, Bad = 2 };

struct StageResult {
    QString id;              // connection|servers|operator|whitelist|speed
    int status = Ok;         // StageStatus
    QString note;            // короткая человеческая строка для UI
    QJsonObject data;        // сырые факты стадии (в отчёт)
};

// numbers.diag_stage_timeout_ms: кламп 5с..60с (сторож фазы; стадия дольше — гасится
// с честным status=Skip, диагностика продолжается).
inline int clampStageTimeoutMs(double v)
{
    if (v != v || v <= 0)      // NaN/нет ключа
        return 25000;
    if (v < 5000)  return 5000;
    if (v > 60000) return 60000;
    return int(v);
}

// Стадия 1: подключение. rx/tx-дельты за окно наблюдения ловят «зелёный, но мёртвый»
// (сигнатура S4-blackhole/протухшего NAT: handshake старый И приёма нет при исходящем).
inline StageResult connectionStage(const QString &state, qint64 handshakeAgeSec,
                                   qint64 rxDelta, qint64 txDelta)
{
    StageResult r; r.id = QStringLiteral("connection");
    r.data.insert(QStringLiteral("state"), state);
    r.data.insert(QStringLiteral("handshake_age_sec"), double(handshakeAgeSec));
    r.data.insert(QStringLiteral("rx_delta"), double(rxDelta));
    r.data.insert(QStringLiteral("tx_delta"), double(txDelta));
    if (state != QLatin1String("connected")) {
        r.status = Skip;
        r.note = QStringLiteral("VPN выключен — проверяю сеть напрямую");
        return r;
    }
    const bool staleHs = handshakeAgeSec >= 180;   // WG: сессия старше 3 мин без ре-handshake
    const bool deadRx  = txDelta > 0 && rxDelta <= 0;
    if (staleHs && deadRx) {
        r.status = Bad;
        r.note = QStringLiteral("Подключено, но данные не проходят");
    } else if (staleHs || deadRx) {
        r.status = Warn;
        r.note = QStringLiteral("Подключение нестабильно");
    } else {
        r.note = QStringLiteral("Туннель живой");
    }
    return r;
}

// Стадия 2: серверы. bestRttMs<0 = ни одного замера (все недостижимы off-tunnel — обычно
// оператор режет ICMP или сети нет; сам по себе НЕ приговор, поэтому Warn, не Bad).
inline StageResult serversStage(int aliveCount, int measuredCount, int bestRttMs,
                                bool fromCache)
{
    StageResult r; r.id = QStringLiteral("servers");
    r.data.insert(QStringLiteral("alive"), aliveCount);
    r.data.insert(QStringLiteral("measured"), measuredCount);
    r.data.insert(QStringLiteral("best_rtt_ms"), bestRttMs);
    r.data.insert(QStringLiteral("from_cache"), fromCache);
    if (aliveCount <= 0) {
        r.status = Bad;
        r.note = QStringLiteral("Нет доступных серверов в пуле");
    } else if (measuredCount <= 0 || bestRttMs < 0) {
        r.status = Warn;
        r.note = QStringLiteral("Серверы не отвечают на прямой замер");
    } else {
        r.note = QStringLiteral("Лучший сервер: ~%1 мс").arg(bestRttMs);
        if (bestRttMs >= 300) r.status = Warn;
    }
    return r;
}

// Стадия 3: оператор. Кворум reach-проб (generate_204) через текущий путь + факт DNS.
inline StageResult operatorStage(const QString &netType, int reachOk, int reachTotal,
                                 bool dnsOk, const QString &egressLoc)
{
    StageResult r; r.id = QStringLiteral("operator");
    r.data.insert(QStringLiteral("net_type"), netType);
    r.data.insert(QStringLiteral("reach_ok"), reachOk);
    r.data.insert(QStringLiteral("reach_total"), reachTotal);
    r.data.insert(QStringLiteral("dns_ok"), dnsOk);
    if (!egressLoc.isEmpty())
        r.data.insert(QStringLiteral("egress_loc"), egressLoc); // страна/colo, БЕЗ IP
    if (reachTotal > 0 && reachOk <= 0) {
        r.status = Bad;
        r.note = dnsOk ? QStringLiteral("Оператор блокирует доступ")
                       : QStringLiteral("Сеть недоступна (DNS и пробы молчат)");
    } else if (!dnsOk || (reachTotal > 0 && reachOk < reachTotal)) {
        r.status = Warn;
        r.note = QStringLiteral("Сеть работает с ограничениями");
    } else {
        r.note = egressLoc.isEmpty() ? QStringLiteral("Сеть оператора в порядке")
                                     : QStringLiteral("Выход в сеть: %1").arg(egressLoc);
    }
    return r;
}

// Стадия 4: белые списки. applicable=false (Wi-Fi/ethernet) → Skip: детект работает
// только на сотовой (инварианты WhitelistDetector не трогаем).
inline StageResult whitelistStage(bool applicable, bool active, int episodes)
{
    StageResult r; r.id = QStringLiteral("whitelist");
    r.data.insert(QStringLiteral("applicable"), applicable);
    r.data.insert(QStringLiteral("active"), active);
    r.data.insert(QStringLiteral("episodes"), episodes);
    if (!applicable) {
        r.status = Skip;
        r.note = QStringLiteral("Не сотовая сеть — не применимо");
    } else if (active) {
        r.status = Bad;
        r.note = QStringLiteral("Похоже на режим «белых списков» у оператора");
    } else {
        r.note = QStringLiteral("Признаков «белых списков» нет");
    }
    return r;
}

// Стадия 5: скорость. Пороги согласованы с BenchAnalysis (kLowGoodputMbit=5,
// bufferbloat = loaded/idle > 2.5 при idle>0).
inline StageResult speedStage(double downMbit, int idleRttMs, int loadedRttMs)
{
    StageResult r; r.id = QStringLiteral("speed");
    r.data.insert(QStringLiteral("down_mbit"), downMbit);
    r.data.insert(QStringLiteral("idle_rtt_ms"), idleRttMs);
    r.data.insert(QStringLiteral("loaded_rtt_ms"), loadedRttMs);
    if (downMbit < 0) {         // стадия не мерялась (обрыв/таймаут)
        r.status = Skip;
        r.note = QStringLiteral("Замер скорости не выполнен");
        return r;
    }
    const bool slow = downMbit < 5.0;
    const bool bloat = idleRttMs > 0 && loadedRttMs > 0
                       && double(loadedRttMs) / double(idleRttMs) > 2.5;
    if (slow && bloat) {
        r.status = Bad;
        r.note = QStringLiteral("Скорость низкая, задержка под нагрузкой растёт");
    } else if (slow) {
        r.status = Warn;
        r.note = QStringLiteral("Скорость ниже комфортной (%1 Мбит/с)")
                     .arg(QString::number(downMbit, 'f', 1));
    } else if (bloat) {
        r.status = Warn;
        r.note = QStringLiteral("Канал «пухнет» под нагрузкой (%1 Мбит/с)")
                     .arg(QString::number(downMbit, 'f', 1));
    } else {
        r.note = QStringLiteral("Скорость в порядке: %1 Мбит/с")
                     .arg(QString::number(downMbit, 'f', 1));
    }
    return r;
}

// Главная человеческая строка для финала попапа: первая стадия с худшим статусом.
inline QString humanSummary(const QList<StageResult> &stages)
{
    const StageResult *worst = nullptr;
    for (const auto &s : stages) {
        if (s.status == Skip) continue;
        if (!worst || s.status > worst->status) worst = &s;
    }
    if (!worst)
        return QStringLiteral("Диагностика выполнена");
    if (worst->status == Ok)
        return QStringLiteral("Проблем не найдено — всё работает штатно");
    return worst->note;
}

// Итоговый JSON-отчёт (уходит в /v1/bench/report и в секцию diag.log).
// PII нет by construction: стадии кладут только loc/colo и агрегаты.
inline QJsonObject buildReport(const QList<StageResult> &stages,
                               const QJsonObject &extra)
{
    QJsonObject o;
    o.insert(QStringLiteral("type"), QStringLiteral("doctor"));
    o.insert(QStringLiteral("schema"), 1);
    QJsonArray arr;
    for (const auto &s : stages) {
        QJsonObject so = s.data;
        so.insert(QStringLiteral("id"), s.id);
        so.insert(QStringLiteral("status"), s.status);
        so.insert(QStringLiteral("note"), s.note);
        arr.append(so);
    }
    o.insert(QStringLiteral("stages"), arr);
    o.insert(QStringLiteral("summary"), humanSummary(stages));
    if (!extra.isEmpty())
        o.insert(QStringLiteral("extra"), extra);
    return o;
}

} // namespace doctor
