// AVPN (Task 9) — iOS APNs контроллер. Запрашивает разрешение на уведомления, регистрирует
// устройство в APNs, кладёт device token + APNs-окружение (sandbox/production) в AvpnPushBridge
// (откуда движок шлёт его авторизованно на POST /v1/devices/push-token), сбрасывает бейдж иконки
// и прокидывает входящие пуши в мост (→ QML-центр уведомлений).
//
// Делегатные коллбэки APNs (didRegisterForRemoteNotificationsWithDeviceToken и т.п.) живут в
// QtAppDelegate.mm (категория на QIOSApplicationDelegate) и зовут эти C-функции.
//
// Overlay: апстрим не трогаем; вся логика — в этом AVPN-файле.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Запросить разрешение на уведомления (UNUserNotificationCenter) и, если выдано, вызвать
// registerForRemoteNotifications. Безопасно звать повторно. Регистрируется как m_authRequester
// в AvpnPushBridge, чтобы QML/движок мог инициировать запрос (после первого коннекта — контекстный UX).
void AvpnPush_requestAuthorization(void);

// «Тихая» регистрация на КАЖДОМ запуске: если разрешение УЖЕ выдано — зовёт
// registerForRemoteNotifications (обновляет device token, токен периодически ротируется), БЕЗ промпта.
// Если разрешение ещё не запрашивали / отклонено — ничего не делает (промпт будет после 1-го коннекта).
void AvpnPush_registerIfAuthorized(void);

// Коллбэк из QtAppDelegate: APNs выдал device token (NSData → hex). Шлёт его на бэк + в мост.
void AvpnPush_onDeviceToken(const unsigned char *bytes, unsigned long length);

// Коллбэк из QtAppDelegate: APNs не смог зарегистрировать (нет сети / симулятор / нет права).
void AvpnPush_onRegisterFailed(const char *reason);

// Коллбэк из QtAppDelegate: пришёл remote push (foreground/background). userInfoJson — payload
// сериализованный в JSON-строку (UTF-8). Разбираем aps.alert.{title,body} → мост.
void AvpnPush_onRemoteNotification(const char *userInfoJson);

#ifdef __cplusplus
}
#endif
