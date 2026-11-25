#pragma once
// AVPN (macOS desktop): авто-установка root-демона Tribe-service из ВШИТОГО в app .pkg —
// чтобы пользователю НИКОГДА не нужен был терминал. Ставится через `installer -pkg`
// с системным промптом администратора (как auto-update в Amnezia, см. mac_installer.sh).
// Реализация — MacServiceInstaller.mm (компилируется только под macOS-desktop, НЕ NE/iOS).
#include <QString>
#include <QStringList>

namespace avpn {

// The service's own amneziawg-go of the LIVE tunnel (wireguardutilsmacos.cpp: `<dir>/amneziawg-go -f utun`), as one
// line of `pgrep -fl <path>` ("PID argv0 args..."). The Scanner's AmneziaWG mini-probe runs the same binary as
// `amneziawg-go probe ...` (service/server/tribe_scan.cpp): it is not our tunnel, so it never hides another VPN
// from the warning before connecting. Pure (tests/build_mac_service_match.sh).
inline bool macOwnTunnelProcessLine(const QString &pgrepLine, const QString &binaryPath)
{
    const QStringList t = pgrepLine.trimmed().split(QLatin1Char(' '), Qt::SkipEmptyParts);
    if (t.size() < 2 || t.at(1) != binaryPath)
        return false;
    bool pid = false;
    t.at(0).toLongLong(&pid);
    if (!pid)
        return false;
    return t.size() == 2 || t.at(2) != QLatin1String("probe");
}
inline bool macOwnTunnelRunning(const QString &pgrepOutput, const QString &binaryPath)
{
    for (const QString &line : pgrepOutput.split(QLatin1Char('\n')))
        if (macOwnTunnelProcessLine(line, binaryPath))
            return true;
    return false;
}

// Демон установлен? (существует /Library/LaunchDaemons/Tribe-service.plist)
bool macServiceInstalled();

// Демон реально запущен? (живой процесс Tribe-service)
bool macServiceRunning();

// Установленный демон УСТАРЕЛ относительно вшитого в app? Сверяет маркер версии (хэш бинарей):
// ресурс app `tribe-svc.version` vs `/Library/PrivilegedHelperTools/TribeVPN/VERSION`. true, если
// отличаются или установленного маркера нет (демон от старой сборки без версии). Мгновенно (крошечные
// файлы). Нужно, чтобы апдейт логики демона (split-DNS и т.п.) сам доезжал через обновление .app.
bool macServiceOutdated();

// Установка — ДВЕ фазы (beachball-фикс 2026-07-21: раньше всё было одним блокирующим вызовом на
// GUI-потоке — на время ввода пароля + распаковки tarball окно «висело» с радужным курсором).
//
// Фаза 1 — ТОЛЬКО главный поток: пояснительный диалог «установим службу, потребуется пароль».
// display dialog качает события в своём модальном цикле — окно живое. false = пользователь отменил.
// required (round mac-E2): the running service cannot work with this app (its IPC contract differs) - the same
// dialog, worded as required; a decline answers the honest line in errOut.
bool macInstallServiceConfirm(QString *errOut, bool required = false);
// Фаза 2 — МОЖНО (и нужно) с ФОНОВОГО потока: привилегированный запуск вшитого установщика
// (NSAppleScript `do shell script … with administrator privileges`; системный промпт пароля рисует
// SecurityAgent — отдельный процесс, поток вызова ему не важен, атрибуция остаётся «Tribe VPN»).
// БЛОКИРУЕТ поток вызова на пароль + распаковку + bootstrap демона — потому и фоновый.
bool macInstallServiceRun(QString *errOut);

// Обнаружен ли ДРУГОЙ активный VPN (чужой full-tunnel/демон), который будет конфликтовать с нашим
// демоном по маршруту? Возвращает имя («Amnezia VPN» / «другой VPN») или пустую строку. Не считает
// наш собственный поднятый туннель за чужой. Вызывать ДО старта коннекта.
QString macForeignVpnName();

// 5.1.108: the installed service carries the Xray runtime - tun2socks next to Tribe-service
// (/Library/PrivilegedHelperTools/TribeVPN/tun2socks, executable). Services up to 5.1.107 never shipped
// it: without it the Xray path cannot start, so the client treats Xray as unsupported (NodeRotation.h).
bool macXrayRuntimePresent();

// Upstream nodes: the cut geo pair (geoip.dat + geosite.dat, recipes/tribe-xray-geo) sits next to the
// installed service and matches, byte for byte, the hashes this app build carries (resource
// tribe-svc-geo.sha256, written by deploy/tribe/make-svc-payload.sh). false when the resource is
// missing (a build without the pair), a file is missing, or a hash differs. Reads both files
// (~380 KB): call at the same points as macXrayRuntimePresent, not per tick. Pure part with an
// injectable directory: MacUpstreamGeo.h (avpn::upstreamGeoPresentAt).
bool macUpstreamGeoPresent();

}
