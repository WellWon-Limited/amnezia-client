// AVPN (Task 9, FCM-волна 2026-07-13) — Android FCM ⇄ avpn::AvpnPushBridge.
// Регистрация JNI-статиков AvpnFcmService.kt + старт Kotlin-половины (запрос токена).
// Зовётся ОДИН раз из AndroidController::initialize() (метка // AVPN там).
#pragma once

namespace avpn {

// Регистрирует natives на классе org/amnezia/vpn/AvpnFcmService, ставит
// authorizationRequester моста (рантайм-запрос POST_NOTIFICATIONS) и зовёт
// AvpnFcmService.start() (флаш отложенного + запрос текущего FCM-токена).
bool registerFcmNatives();

} // namespace avpn
