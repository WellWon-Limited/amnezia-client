// AVPN (разбор 2026-09-23): фоновое время iOS для перезапуска туннеля, начатого самим приложением.
//
// Зачем: перезапуск идёт «стоп → ждём Disconnected → старт»; свёрнутое приложение iOS замораживает
// через секунды, и старт уходил только при следующем открытии — VPN выключен (журнал iPhone
// владельца, 10:05:54 и 13:37:07.9). Решение о удержании — чистое (serviceEngine/RestartGuard.h),
// здесь только UIApplication background task. Только приложение (UIKit), не NE.
// Вызывать с главного потока (GUI-поток Qt на iOS).
//
// AVPN (iOS data watch, build 141): the one task is owned by reason (BackgroundHoldBook.h): the restart
// guard (begin/end below, unchanged for its caller) and the On-Demand arming after leaving the screen
// (acquire/release with BgReason::OnDemandArm). Ending one reason does not end the task another holds;
// iOS ending the task ends it for all, each owner's callback runs.
#pragma once

#include <functional>

#include "BackgroundHoldBook.h"

// Начать удержание (идемпотентно). onExpired — на главном потоке, когда iOS исчерпала время:
// задача к этому моменту уже завершена. false — iOS отказала (времени нет), удержания нет.
// AVPN (141): = AvpnBackgroundGuard_acquire(BgReason::TunnelRestart, onExpired).
bool AvpnBackgroundGuard_begin(std::function<void()> onExpired);

// Завершить удержание (идемпотентно).
// AVPN (141): = AvpnBackgroundGuard_release(BgReason::TunnelRestart).
void AvpnBackgroundGuard_end();

// Hold / let go of background time for one reason (idempotent per reason). Same contract as begin/end.
bool AvpnBackgroundGuard_acquire(avpn_ios::BgReason reason, std::function<void()> onExpired);
void AvpnBackgroundGuard_release(avpn_ios::BgReason reason);
