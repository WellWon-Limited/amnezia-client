// AVPN: стамп входов сева АнтиВПН (applyRuBypassSplit) — «пересевать или пропустить».
//
// Корень тормозов коннекта (девайс-баг 2026-07-10, билд 74): сев на КАЖДОМ guardedStart/
// реконнекте строил QMap на ~10801 CIDR (серверный ru-список), гонял carve-out по всем ключам
// и писал весь набор в QSettings/plist на GUI-потоке — при том, что входы сева между
// реконнектами не меняются (список обновляется раз в 6 часов, тумблеры — руками). Стамп
// канонизирует ВСЕ входы, от которых зависит содержимое sites: тумблеры masterOn/liAutoOn,
// источник списка (валидный серверный снапшот vs вкомпиленный фолбэк + его version) и набор
// carve-IP control plane. Совпал с прошлым севом → содержимое идентично → сев пропускается.
//
// Валидный снапшот определяет содержимое групп однозначно через version (анти-downgrade в
// BypassListService гарантирует монотонность); невалидный = вкомпиленный фолбэк, version
// не участвует. Порядок carve-IP не важен (async-резолв наполняет m_apiHostIps недетерминированно).
// Чистая inline-функция (только QtCore) — тестируется автономно: tests/build_bypass_seed.sh.
#pragma once

#include <QString>
#include <QStringList>

namespace avpn {

inline QString bypassSeedStamp(bool masterOn, bool liAutoOn, bool remoteValid, int remoteVersion,
                               QStringList carveIps)
{
    carveIps.sort();
    return QStringLiteral("m%1|l%2|r%3|v%4|c%5")
            .arg(masterOn ? 1 : 0)
            .arg(liAutoOn ? 1 : 0)
            .arg(remoteValid ? 1 : 0)
            .arg(remoteValid ? remoteVersion : -1)
            .arg(carveIps.join(QLatin1Char(',')));
}

} // namespace avpn
