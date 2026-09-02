// AVPN (live-node picker): чистая логика ротации «Сменить сервер» (nextLiveNodeId) + общие хелперы
// живости/RU-ноды/протокола/локации. Вынесено из ServiceEngine.cpp по паттерну NodeRanking.h —
// тестируется автономно (tests/node_rotation_check.cpp, tests/transport_pick_check.cpp, только
// QtCore), ServiceEngine делегирует сюда.
#pragma once

#include "TuningStore.h" // AVPN awg31-xray-v1: kill-switch'и xray_client / transport_auto_pick
#include "dto/Subscription.h"

#include <QHash>
#include <QList>
#include <QString>
#include <QStringList>

#include <algorithm>

namespace avpn {

// Агрегат backend-health узла в [0..1]. Пустой health = 1.0 (живой) — бэкенд провижинит узлы
// /v1/subscription уже живыми, отсутствие телеметрии не значит «мёртв». Среднее по всем target'ам.
inline double healthAggregate(const SubscriptionNode &n)
{
    if (n.health.isEmpty())
        return 1.0;
    double sum = 0.0;
    for (auto it = n.health.constBegin(); it != n.health.constEnd(); ++it)
        sum += it.value();
    return sum / static_cast<double>(n.health.size());
}

// RU-нода (countryCode==RU) обслуживает ТОЛЬКО РФ-сайты (full-tunnel через РФ) — в общем VPN на ней
// не работает ничего. Исключается из ЛЮБОГО авто-выбора (pick*/Selector/ротация); достижима только
// ручным pin из шторки (сценарий «за границей зайти на РФ-сайт»). CONNECT-INVARIANTS §14.3.
inline bool isRuNode(const SubscriptionNode &n)
{
    return n.countryCode.compare(QStringLiteral("RU"), Qt::CaseInsensitive) == 0;
}

// AVPN awg31-xray-v1 (спека 2026-09-01 §2.3): ручной режим транспорта «Авто / Amnezia / Xray».
// Локальная настройка (QSettings avpn/transportMode, фасад) — kill-switch не нужен.
enum class TransportMode { Auto, Awg, Xray };

inline QString transportModeToString(TransportMode m)
{
    switch (m) {
    case TransportMode::Awg:  return QStringLiteral("awg");
    case TransportMode::Xray: return QStringLiteral("xray");
    case TransportMode::Auto: break;
    }
    return QStringLiteral("auto");
}

// Незнакомое/пустое значение → Auto (стейл-ключ настроек не ломает выбор).
inline TransportMode transportModeFromString(const QString &s)
{
    const QString v = s.trimmed().toLower();
    if (v == QLatin1String("awg") || v == QLatin1String("amnezia"))
        return TransportMode::Awg;
    if (v == QLatin1String("xray"))
        return TransportMode::Xray;
    return TransportMode::Auto;
}

// Нормализованный proto ноды: пусто (легаси-тело без поля) = awg.
inline QString protoOf(const SubscriptionNode &n)
{
    return n.proto.isEmpty() ? QStringLiteral("awg") : n.proto;
}

inline bool isXrayProto(const QString &proto)
{
    return proto == QLatin1String("xray");
}

// AVPN awg31-xray-v1: умеет ли ЭТОТ клиент поднимать xray-туннель. Две опоры:
//  • платформенный гейт — в этой волне xray доводится на macOS (root-демон Xray::startXray +
//    tun2socks, статистика через IPC xrayRuntimeStatus) и iOS (NE PacketTunnelProvider+Xray,
//    статистика bytesChanged). Android/Windows — следующая волна: движки упакованы, но rx/tx на
//    xray-пути там нет (HealthLoop слеп), поэтому клиент xray не выбирает; сервер им xray и так
//    не выдаёт (per-platform min_app_version на листенере, спека §2.2);
//  • kill-switch features.xray_client (default ВКЛ) — бэк гасит xray на клиентах без релиза.
inline bool xrayClientSupported()
{
#if defined(Q_OS_MACOS) || defined(Q_OS_IOS)
    return TuningStore::flag(QStringLiteral("xray_client"), true);
#else
    return false;
#endif
}

// Форвард-совместимость по протоколу (Task 10, backend-first-3; расширено волной awg31-xray-v1):
// клиентский Tribe-слой умеет awg и (macOS/iOS, kill-switch xray_client) xray; бэкенд может
// добавлять в пул ноды будущих протоколов (vless, ...). Такая нода ОСТАЁТСЯ в пуле (диагностика/
// эскалация), но непригодна для коннекта в принципе — исключается из ЛЮБОГО выбора (auto,
// failover, ротация, ручной pin) БЕЗ manual_only-фолбэка «оставить как есть»: если поддерживаемых
// нод нет, выбор честно пуст (штатная ветка «нет нод»). Пустой proto = легаси-тело без поля = awg.
// Строковая перегрузка — для мест, где нода уже сконвертирована из SubscriptionNode
// (QVariantMap-пул фасада: очередь админ-свипа, Доктор, nodePool() для QML).
inline bool isSupportedProto(const QString &proto)
{
    if (proto.isEmpty() || proto == QLatin1String("awg"))
        return true;
    if (isXrayProto(proto))
        return xrayClientSupported();
    return false;
}

// xray-нода пригодна только с валидными xray_params (парсер их гарантирует; страховка для DTO,
// собранных мимо парсера / стейл-LKG).
inline bool isSupportedProtoNode(const SubscriptionNode &n)
{
    if (!isSupportedProto(n.proto))
        return false;
    if (isXrayProto(n.proto) && !n.xray.has_value())
        return false;
    return true;
}

// AVPN awg31-xray-v1: пригодна ли нода для АВТО-путей (первый коннект, failover, «Сменить сервер»).
// Kill-switch features.transport_auto_pick=false = «до этой волны»: автоматика берёт только awg,
// xray достижим лишь ручным режимом/pin. Так серверный рубильник не оставляет автомат без защиты
// от TCP-пинга (Selector::pick достукивается до xray:443, но не до awg UDP).
inline bool isAutoEligibleNode(const SubscriptionNode &n)
{
    if (!isSupportedProtoNode(n))
        return false;
    if (isXrayProto(n.proto) && !TuningStore::flag(QStringLiteral("transport_auto_pick"), true))
        return false;
    return true;
}

// Ручной режим транспорта: hard-filter по proto. Auto пропускает всё.
inline bool transportAllowed(const SubscriptionNode &n, TransportMode mode)
{
    switch (mode) {
    case TransportMode::Auto: return true;
    case TransportMode::Awg:  return !isXrayProto(n.proto) && isSupportedProto(n.proto);
    case TransportMode::Xray: return isXrayProto(n.proto);
    }
    return true;
}

// «Только ручной pin» — честный флаг контракта nodes[].manual_only (openapi 0.6.1,
// MANUAL-ONLY-POOL-HANDOFF): такие ноды НИКОГДА не выбираются автоматикой (первый коннект,
// failover, «Сменить сервер») — только явный тап. RU-проверка остаётся страховкой для тел
// без поля (LKG-кеш старого формата) и потому, что RU manual по определению (§14.3).
inline bool isManualOnlyNode(const SubscriptionNode &n)
{
    return n.manualOnly || isRuNode(n);
}

// AVPN awg31-xray-v1 (§2.3): ЛОКАЦИЯ = группа листенеров одного хоста (host_id). Фолбэк для тел
// без host_id (старый бэк/LKG): country_code+region; совсем без страны — сама нода. Pin, выбор
// транспорта и ротация «Сменить сервер» работают по локациям, не по узлам.
inline QString locationKeyOf(const SubscriptionNode &n)
{
    if (n.hostId > 0)
        return QStringLiteral("h:") + QString::number(n.hostId);
    if (!n.countryCode.isEmpty())
        return QStringLiteral("cr:") + n.countryCode.toUpper() + QLatin1Char('/') + n.region.toLower();
    return QStringLiteral("n:") + n.nodeId;
}

// Представитель локации для кольца ротации (чистый порядок без истории/RTT — реальный транспорт
// выбирает connect() по pin-локации): transport_rank↑, weight↓, nodeId↑.
inline const SubscriptionNode *locationRepresentative(const QList<const SubscriptionNode *> &loc)
{
    const SubscriptionNode *best = nullptr;
    for (const SubscriptionNode *n : loc) {
        if (!best) { best = n; continue; }
        if (n->transportRank != best->transportRank) {
            if (n->transportRank < best->transportRank) best = n;
            continue;
        }
        if (n->weight != best->weight) {
            if (n->weight > best->weight) best = n;
            continue;
        }
        if (n->nodeId < best->nodeId)
            best = n;
    }
    return best;
}

// Следующая живая ЛОКАЦИЯ после текущей — round-robin для кнопки «Сменить сервер» (rotateNext).
// Возвращает nodeId представителя локации; фактический транспорт внутри неё выберет connect()
// (pin по локации + transport_rank + история). manual_only-ноды (вкл. RU) в кольцо НЕ входят
// (§14.3: только ручной pin); с запиненной manual ротация уводит на лучшую обычную. Ручной режим
// транспорта (mode) фильтрует кандидатов. Сортировка стабильная: weight desc → health desc →
// nodeId (по представителю). Пусто = ротировать некуда.
inline QString nextLiveNodeId(const QList<SubscriptionNode> &nodes, const QString &currentNodeId,
                              TransportMode mode = TransportMode::Auto)
{
    // Группировка по локации с сохранением порядка появления.
    QStringList order;
    QHash<QString, QList<const SubscriptionNode *>> byLoc;
    QString currentLoc;
    for (const SubscriptionNode &n : nodes) {
        if (n.nodeId == currentNodeId)
            currentLoc = locationKeyOf(n);
        if (!isAutoEligibleNode(n) || !transportAllowed(n, mode) || isManualOnlyNode(n)
            || healthAggregate(n) <= 0.0)
            continue;
        const QString key = locationKeyOf(n);
        if (!byLoc.contains(key))
            order << key;
        byLoc[key].append(&n);
    }
    if (order.isEmpty())
        return QString();
    QList<const SubscriptionNode *> reps;
    for (const QString &key : order)
        reps.append(locationRepresentative(byLoc.value(key)));
    std::sort(reps.begin(), reps.end(), [](const SubscriptionNode *a, const SubscriptionNode *b) {
        if (a->weight != b->weight)
            return a->weight > b->weight;
        const double ha = healthAggregate(*a), hb = healthAggregate(*b);
        if (ha != hb)
            return ha > hb;
        return a->nodeId < b->nodeId;
    });
    int cur = -1;
    for (int i = 0; i < reps.size(); ++i)
        if (locationKeyOf(*reps.at(i)) == currentLoc && !currentLoc.isEmpty()) { cur = i; break; }
    // Текущая локация в кольце и одна → ротировать некуда; текущая ВНЕ кольца (RU-pin/новый
    // коннект/чужой транспорт) — единственной локации достаточно (уходим на неё).
    if (cur >= 0 && reps.size() < 2)
        return QString();
    const int next = (cur < 0) ? 0 : (cur + 1) % reps.size();
    return reps.at(next)->nodeId;
}

} // namespace avpn
