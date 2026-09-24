// AVPN (журнал тестирования, Tribe-Backend docs/specs/2026-09-23-tester-journal-design.md):
// iOS-часть TribeJournal — App Group (где лежат ne.log/app.log туннеля и Swift-части приложения),
// флаг файлового лога NE (тот же ключ IsLoggingEnabled, что Log.swift) и фоновое время на досылку
// при уходе в фон. Только приложение (UIKit), не NE. Вызывать с главного потока.
#pragma once

#include <QString>
#include <functional>

// Каталог App Group ("" — недоступна).
QString TribeJournalIos_appGroupDir();

// Писать ли NE/Swift-части в ne.log/app.log (UserDefaults App Group, ключ IsLoggingEnabled).
void TribeJournalIos_setNativeLogging(bool on);

// Сборка из TestFlight (квитанция sandboxReceipt).
bool TribeJournalIos_isTestFlight();

// Фоновое время на досылку (идемпотентно). onExpired — на главном потоке, задача уже завершена.
bool TribeJournalIos_beginBackground(std::function<void()> onExpired);
void TribeJournalIos_endBackground();
