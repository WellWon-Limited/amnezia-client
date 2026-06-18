// AVPN (Task 9) — мост пуш-уведомлений (APNs/FCM) → QML.
//
// Кросс-платформенный QObject-фасад: его регистрируют как context property "AvpnPush" и читают
// из QML (колокол в шапке Connect + центр уведомлений #3). Натив-слой (iOS: QtAppDelegate.mm /
// AvpnPushController.mm; Android: FCMService) дёргает СТАТИЧЕСКИЙ instance() из любого потока и
// зовёт setDeviceToken()/incrementUnread()/onRemoteNotification() — те маршалятся в Qt-поток через
// QMetaObject::invokeMethod(Qt::QueuedConnection), чтобы NOTIFY-сигналы прилетели в QML безопасно.
//
// Overlay: апстрим не трогаем. На desktop/Android без пушей это просто пустой счётчик (no-op).
#pragma once

#include <QObject>
#include <QString>
#include <QVariantList>
#include <QVariantMap>

namespace avpn {

class AvpnPushBridge : public QObject {
    Q_OBJECT
    // Непрочитанные пуши — бейдж на колоколе (PageConnectAvpn.unreadCount).
    Q_PROPERTY(int unreadCount READ unreadCount NOTIFY changed)
    // APNs/FCM device token (для дебага/настроек; отправляется на бэк нативным слоем).
    Q_PROPERTY(QString deviceToken READ deviceToken NOTIFY changed)
    // Платформа токена: "ios" | "android" | "" (нет).
    Q_PROPERTY(QString platform READ platform NOTIFY changed)
    // Статус разрешения на пуши: "unknown" | "granted" | "denied".
    Q_PROPERTY(QString authStatus READ authStatus NOTIFY changed)
    // Последние входящие уведомления (для центра уведомлений #3): [{title, body, time, read}].
    Q_PROPERTY(QVariantList items READ items NOTIFY changed)

public:
    static AvpnPushBridge *instance();

    int unreadCount() const { return m_unreadCount; }
    QString deviceToken() const { return m_deviceToken; }
    QString platform() const { return m_platform; }
    QString authStatus() const { return m_authStatus; }
    QVariantList items() const { return m_items; }

    // --- QML API ---
    // Пользователь открыл центр уведомлений / отметил всё прочитанным → обнулить бейдж.
    Q_INVOKABLE void markAllRead();
    // Принудительная (пере)регистрация на пуши (например, после логина). На desktop — no-op.
    Q_INVOKABLE void requestAuthorization();

    // --- Натив-слой (iOS/Android), потокобезопасно (маршалят в Qt-поток) ---
    // Пришёл APNs/FCM device token. platform: "ios" | "android".
    void setDeviceToken(const QString &token, const QString &platform);
    void setAuthStatus(const QString &status);            // "granted" | "denied"
    // AVPN: APNs-окружение токена для регистрации на бэке: "sandbox" | "production".
    // Натив ОБЯЗАН звать ПЕРЕД setDeviceToken (обе вызова FIFO-маршалятся → env применится первым).
    void setPushEnvironment(const QString &environment);
    // Прилетел пуш: добавить в ленту и поднять бейдж непрочитанных.
    void onRemoteNotification(const QString &title, const QString &body);
    // Регистрация запрошена из QML — натив-слой подменит это (см. setAuthorizationRequester).
    void setAuthorizationRequester(void (*fn)());
    // AVPN: сброс системного бейджа иконки — натив ставит C-функцию (iOS: setBadgeCount:0).
    void setBadgeClearer(void (*fn)());

signals:
    void changed();
    // Натив-слой может слушать (на iOS не нужен — он сам инициатор).
    void authorizationRequested();
    // AVPN: device token готов (token непустой) → движок шлёт его на /v1/devices/push-token (Bearer).
    void deviceTokenReady(const QString &token, const QString &platform, const QString &environment);
    // AVPN: пользователь отметил всё прочитанным → движок шлёт POST /v1/notifications/read (сброс счётчика).
    void readRequested();

private:
    explicit AvpnPushBridge(QObject *parent = nullptr);
    void applyDeviceToken(const QString &token, const QString &platform);
    void applyAuthStatus(const QString &status);
    void applyPushEnvironment(const QString &environment);
    void applyRemoteNotification(const QString &title, const QString &body);
    // AVPN: локальная история уведомлений (QSettings) — переживает перезапуск приложения.
    void loadPersisted();   // вызвать в конструкторе: загрузить m_items + пересчитать m_unreadCount
    void persist() const;   // сохранить m_items (JSON) после каждого изменения

    int          m_unreadCount = 0;
    QString      m_deviceToken;
    QString      m_platform;
    QString      m_environment;   // AVPN: "sandbox" | "production" | "" (десктоп/неизвестно)
    QString      m_authStatus = QStringLiteral("unknown");
    QVariantList m_items;
    void (*m_authRequester)() = nullptr;
    void (*m_badgeClearer)() = nullptr;   // AVPN: натив-сброс бейджа иконки
};

} // namespace avpn
