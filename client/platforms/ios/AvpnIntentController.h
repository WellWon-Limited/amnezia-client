// AVPN (Task E) — iOS-консьюмер «намерений» App Intent авто-паузы (Task 8) из App Group.
//
// Фоновый App Intent (AvpnAppIntents.swift) пишет флаги в App Group UserDefaults
// (suite "group.hk.wellwon.zanaves": AvpnIntent/pauseRequested, AvpnIntent/resumeRequested,
// AvpnIntent/lastActionAt) и сам опускает/поднимает туннель. Прямой вызов Q_INVOKABLE движка из
// фона невозможен, поэтому при следующем выходе в foreground QtAppDelegate.mm зовёт C-функцию
// Avpn_consumeIntentFlags() — она читает эти флаги (NSUserDefaults App Group), эмитит через
// AvpnIntentBridge pauseRequested()/resumeRequested() и СБРАСЫВАЕТ флаги (чтобы не повторять).
//
// Объявлен в общем заголовке моста (AvpnIntentBridge.h: extern "C" void Avpn_consumeIntentFlags()).
// Реализация — только на iOS (этот .mm). На desktop/Android — no-op в AvpnIntentBridge.cpp.
//
// Overlay: апстрим не трогаем; вся логика — в этом AVPN-файле.
#pragma once

// Реализацию см. AvpnIntentController.mm; C-вход — Avpn_consumeIntentFlags() из AvpnIntentBridge.h.
