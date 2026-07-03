// AVPN (Tribe split-DNS, 2026-07-03): per-domain резолверы macOS через /etc/resolver/<suffix>.
// Зачем: «Доступ к сайтам РФ» требует РОССИЙСКИЙ резолвер для RU-доменов (Госуслуги/Кинопоиск палят
// «нероссийский DNS»), но Яндекс-DNS-на-всё портит гео зарубежных сервисов (WhatsApp-инфра +75% RTT —
// измерено). Решение: глобальный DNS туннеля = бэкендовский (1.1.1.1, гео=egress), а RU-суффиксы
// mDNSResponder направляет на Яндекс через штатный механизм /etc/resolver/* (запрос уходит с
// устройства мимо туннеля — RU-CIDR исключены маршрутно; Яндекс-DNS отвечает только residential-IP).
// Пишет ТОЛЬКО root-демон (Tribe-service). Файлы помечены маркером — clear() убирает только наши
// (вкл. сирот после краша: вызывается на старте демона и на deactivate). apply = реконсиляция.
#pragma once

#include <QString>
#include <QStringList>

namespace SplitDnsResolverFiles {

// Записать /etc/resolver/<suffix> → nameserver server (+server2, если задан). Сначала clear().
bool apply(const QStringList &suffixes, const QString &server, const QString &server2 = QString());

// Удалить все НАШИ файлы из /etc/resolver (по маркеру в первой строке). Идемпотентно.
void clear();

} // namespace SplitDnsResolverFiles
