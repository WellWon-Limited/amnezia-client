#pragma once
// AVPN (macOS desktop): авто-установка root-демона Tribe-service из ВШИТОГО в app .pkg —
// чтобы пользователю НИКОГДА не нужен был терминал. Ставится через `installer -pkg`
// с системным промптом администратора (как auto-update в Amnezia, см. mac_installer.sh).
// Реализация — MacServiceInstaller.mm (компилируется только под macOS-desktop, НЕ NE/iOS).
#include <QString>

namespace avpn {

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
bool macInstallServiceConfirm(QString *errOut);
// Фаза 2 — МОЖНО (и нужно) с ФОНОВОГО потока: привилегированный запуск вшитого установщика
// (NSAppleScript `do shell script … with administrator privileges`; системный промпт пароля рисует
// SecurityAgent — отдельный процесс, поток вызова ему не важен, атрибуция остаётся «Tribe VPN»).
// БЛОКИРУЕТ поток вызова на пароль + распаковку + bootstrap демона — потому и фоновый.
bool macInstallServiceRun(QString *errOut);

// Обнаружен ли ДРУГОЙ активный VPN (чужой full-tunnel/демон), который будет конфликтовать с нашим
// демоном по маршруту? Возвращает имя («Amnezia VPN» / «другой VPN») или пустую строку. Не считает
// наш собственный поднятый туннель за чужой. Вызывать ДО старта коннекта.
QString macForeignVpnName();

}
