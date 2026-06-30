// AVPN — авто-сбор диагностики вылетов/зависаний (Apple MetricKit, iOS 14+).
//
// Зачем: до этого краши тестеров приходилось снимать с устройства по проводу (idevicecrashreport)
// и символизировать вручную. MetricKit — sandbox-нативный, без сторонних SDK: iOS на СЛЕДУЮЩЕМ
// запуске после вылета отдаёт приложению MXDiagnosticPayload (crash/hang/cpu-exception, со стеком,
// сигналом, terminationReason, UUID образа и build). Мы шлём payload как есть на бэк
// (POST /v1/diag/crash) — там лог + символизация по dSYM. Рунбук: Tribe-Backend documents/CRASHLOGS.md.
//
// Полностью изолировано: один файл, NSURLSession (без Qt/движка) → не влияет на путь коннекта.
// Overlay: апстрим не трогаем. Вызывается один раз из QtAppDelegate didFinishLaunching.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Подписаться на MXMetricManager (идемпотентно, dispatch_once). No-op на iOS < 14 и на macOS.
void AvpnDiagnostics_install(void);

#ifdef __cplusplus
}
#endif
