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

// Поставить вшитый Tribe-service.pkg через osascript с админ-промптом (БЛОКИРУЮЩЕ — installer
// синхронно выполняет postinstall, который bootstrap'ит демон). true = installer вышел с 0.
// errOut — текст для UI при отмене/ошибке.
bool macInstallService(QString *errOut);

// Обнаружен ли ДРУГОЙ активный VPN (чужой full-tunnel/демон), который будет конфликтовать с нашим
// демоном по маршруту? Возвращает имя («Amnezia VPN» / «другой VPN») или пустую строку. Не считает
// наш собственный поднятый туннель за чужой. Вызывать ДО старта коннекта.
QString macForeignVpnName();

}
