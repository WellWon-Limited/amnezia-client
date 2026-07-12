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
    // Последние входящие уведомления (для центра уведомлений #3): [{id, title, body, time, read, type, days}].
    // type: "bonus_gift" | "payment" | "reminder" | "generic" (для типовых стилей делегата в QML,
    // «золотой подарок» и т.п.); days: >0 для бонус/оплата (показать «+N дней»), иначе 0.
    // id: серверный id строки /v1/notifications (>0) — для поэлементного mark-read; у локального
    // пуша id нет (0) — серверная история заместит его строкой с id при ближайшем refresh.
    Q_PROPERTY(QVariantList items READ items NOTIFY changed)

public:
    static AvpnPushBridge *instance();

    // AVPN: геттеры истории лениво подгружают её при первом доступе — БЕЗОПАСНО (после main), а не в
    // конструкторе (он может вызваться из __attribute__((constructor)) ДО main → CFPreferences-краш).
    int unreadCount() const { const_cast<AvpnPushBridge *>(this)->ensureLoaded(); return m_unreadCount; }
    QString deviceToken() const { return m_deviceToken; }
    QString platform() const { return m_platform; }
    QString authStatus() const { return m_authStatus; }
    QVariantList items() const { const_cast<AvpnPushBridge *>(this)->ensureLoaded(); return m_items; }

    // --- QML API ---
    // Пользователь нажал «Прочитать все» в центре уведомлений → обнулить бейдж.
    // (С 2026-07-12 центр НЕ зовёт это при открытии: read-state честный, per-элемент.)
    Q_INVOKABLE void markAllRead();
    // Пользователь открыл КОНКРЕТНОЕ уведомление (детальная страница) → пометить прочитанным
    // только его: локально сразу (точка гаснет, бейдж -1), на сервер — readItemRequested(id),
    // если у элемента есть серверный id. index — позиция в items (модель ListView).
    Q_INVOKABLE void markItemRead(int index);
    // Принудительная (пере)регистрация на пуши (например, после логина). На desktop — no-op.
    Q_INVOKABLE void requestAuthorization();
    // AVPN (Support): забрать отложенный «тап по пушу» (cold start: сигнал pushTapped ушёл
    // ДО создания QML — PageStart добирает его в onGoToPageHome). Возвращает type и чистит.
    Q_INVOKABLE QString takePendingPushTap();

    // AVPN (центр уведомлений, серверная история): движок дёргает после GET /v1/notifications —
    // серверная лента ЗАМЕЩАЕТ локальную (сервер = источник правды: переживает переустановку,
    // кормит платформы без пушей; каждый пуш и так рождается строкой в БД бэка). Формат элементов
    // тот же, что у items ({title, body, time, read, type, days}). Вызывать из Qt-потока.
    void setServerItems(const QVariantList &items);

    // --- Натив-слой (iOS/Android), потокобезопасно (маршалят в Qt-поток) ---
    // Пришёл APNs/FCM device token. platform: "ios" | "android".
    void setDeviceToken(const QString &token, const QString &platform);
    void setAuthStatus(const QString &status);            // "granted" | "denied"
    // AVPN: APNs-окружение токена для регистрации на бэке: "sandbox" | "production".
    // Натив ОБЯЗАН звать ПЕРЕД setDeviceToken (обе вызова FIFO-маршалятся → env применится первым).
    void setPushEnvironment(const QString &environment);
    // Прилетел пуш: добавить в ленту и поднять бейдж непрочитанных.
    // type/days — из custom-полей payload (APNs top-level "type"/"days", FCM data): типовой стиль
    // в центре (bonus_gift → «золотой подарок» +N дней). Пустой type → "generic" (старый пуш).
    // 2-арг перегрузка — обратная совместимость со старым натив-слоем/местами вызова.
    void onRemoteNotification(const QString &title, const QString &body);
    void onRemoteNotification(const QString &title, const QString &body,
                              const QString &type, int days);
    // AVPN (Support): пуш открыт ТАПОМ (натив различает по applicationState) —
    // после обычной обработки эмитит pushTapped(type) для диплинк-навигации в QML.
    void onPushTapped(const QString &type);
    // Регистрация запрошена из QML — натив-слой подменит это (см. setAuthorizationRequester).
    void setAuthorizationRequester(void (*fn)());
    // AVPN: сброс системного бейджа иконки — натив ставит C-функцию (iOS: setBadgeCount:0).
    void setBadgeClearer(void (*fn)());
    // AVPN (P-ANN, macOS): натив-установка ЧИСЛА на иконке (NSApp.dockTile.badgeLabel) — macOS
    // не получает aps.badge (пуша нет), бейдж питается локальным unreadCount при поллинге.
    void setBadgeSetter(void (*fn)(int));

signals:
    void changed();
    // Натив-слой может слушать (на iOS не нужен — он сам инициатор).
    void authorizationRequested();
    // AVPN: device token готов (token непустой) → движок шлёт его на /v1/devices/push-token (Bearer).
    void deviceTokenReady(const QString &token, const QString &platform, const QString &environment);
    // AVPN: пользователь отметил всё прочитанным → движок шлёт POST /v1/notifications/read (сброс счётчика).
    void readRequested();
    // AVPN (read per-элемент): открыта деталь уведомления с серверным id → движок шлёт
    // POST /v1/notifications/read {"ids":[id]} (помечает только его + декремент unread_count).
    void readItemRequested(qlonglong id);
    // AVPN (Support): пришёл пуш type=support (ответ оператора чата поддержки). В колокол
    // НЕ попадает (гейт в applyRemoteNotification) — слушает TribeSupportChat::onSupportPush.
    void supportPushReceived();
    // AVPN (store-flow E): пришёл пуш type=payment (оплата прошла, бэк продлил подписку) —
    // движок мгновенно перечитывает /v1/subscription (coreController коннектит к
    // AvpnEngineQml::refreshSubscription): бейдж/золотая CTA оживают сразу, даже если
    // приложение открыто на чате. В колокол пуш ТОЖЕ попадает (в отличие от support).
    void paymentPushReceived();
    // AVPN (объявления P-ANN): пришёл пуш type=announcement — движок перечитывает
    // /v1/announcements (попап всплывает сразу, без ожидания foreground-рефреша).
    // В колокол пуш ТОЖЕ попадает (обычная обработка перед сигналом).
    void announcementPushReceived();
    // AVPN (Support): пользователь ТАПНУЛ по пушу → QML-навигация (PageStart:
    // type=support → вкладка «Поддержка»).
    void pushTapped(const QString &type);

private:
    explicit AvpnPushBridge(QObject *parent = nullptr);
    void applyDeviceToken(const QString &token, const QString &platform);
    void applyAuthStatus(const QString &status);
    void applyPushEnvironment(const QString &environment);
    void applyRemoteNotification(const QString &title, const QString &body,
                                 const QString &type, int days);
    // AVPN: локальная история уведомлений (QSettings) — переживает перезапуск приложения.
    // ВАЖНО: НЕ грузить в конструкторе — он может выполниться из __attribute__((constructor)) ДО main()
    // (AvpnPushController.mm), а QSettings на Apple = CFPreferences → без org-name краш «CFEqual NULL».
    void ensureLoaded();    // ленивая загрузка при первом доступе, только когда приложение готово
    void loadPersisted();   // фактическая загрузка m_items + пересчёт m_unreadCount (через ensureLoaded)
    void persist() const;   // сохранить m_items (JSON) после изменения (guarded: no-op до готовности app)

    int          m_unreadCount = 0;
    QString      m_deviceToken;
    QString      m_platform;
    QString      m_environment;   // AVPN: "sandbox" | "production" | "" (десктоп/неизвестно)
    QString      m_authStatus = QStringLiteral("unknown");
    QString      m_pendingTapType;   // AVPN (Support): cold-start тап до готовности QML
    QVariantList m_items;
    bool         m_loaded = false;   // AVPN: история уже подгружена из QSettings (ленивая инициализация)
    void (*m_authRequester)() = nullptr;
    void (*m_badgeClearer)() = nullptr;   // AVPN: натив-сброс бейджа иконки
    void (*m_badgeSetter)(int) = nullptr; // AVPN (P-ANN): натив-установка числа (macOS dockTile)
    void updateNativeBadge();             // AVPN (P-ANN): m_badgeSetter(m_unreadCount), если задан
};

} // namespace avpn
