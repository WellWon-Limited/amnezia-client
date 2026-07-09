// AVPN (объявления P-ANN, macOS): бейдж непрочитанных уведомлений на иконке дока.
// macOS-путь не получает aps.badge (пуша на десктопе нет) — число питается локальным
// AvpnPushBridge::unreadCount (поллинг /v1/notifications + локальная история пушей).
// Регистрация — AvpnDockBadge_install() из конструктора AvpnEngineQml (#ifdef Q_OS_MACOS).

#import <AppKit/AppKit.h>

#include "core/serviceEngine/AvpnPushBridge.h"

namespace {

void avpnDockBadgeSetter(int count)
{
    // Бридж живёт в Qt-главном потоке; AppKit требует main thread — dispatch на всякий случай
    // (queued-сигналы бриджа уже в main, но регистрация/первый вызов может прийти раньше).
    dispatch_async(dispatch_get_main_queue(), ^{
        NSDockTile *tile = [NSApp dockTile];
        tile.badgeLabel = (count > 0) ? [NSString stringWithFormat:@"%d", count] : nil;
    });
}

} // namespace

extern "C" void AvpnDockBadge_install()
{
    avpn::AvpnPushBridge::instance()->setBadgeSetter(&avpnDockBadgeSetter);
}
