// AVPN (Task 9) — реализация моста пушей → QML. См. AvpnPushBridge.h.
#include "AvpnPushBridge.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMetaObject>
#include <QSettings>

#include <utility>

namespace avpn {

namespace {
// AVPN: ключ QSettings для локальной истории уведомлений (JSON-массив [{title,body,time,read}]).
constexpr auto kNotifSettingsKey = "avpn/notifications";
} // namespace

AvpnPushBridge::AvpnPushBridge(QObject *parent) : QObject(parent)
{
    // КРИТИЧНО: НЕ трогаем здесь QSettings! Этот синглтон впервые создаётся из
    // __attribute__((constructor)) avpnPushInstallRequester() в AvpnPushController.mm — то есть ДО main()
    // и до QCoreApplication::setOrganizationName(). На Apple QSettings = CFPreferences; обращение к нему
    // без bundle-id/org-name даёт «*** CFEqual() called with NULL first argument ***» → КРАШ ЗАПУСКА
    // (билды 22-24). Историю грузим ЛЕНИВО через ensureLoaded(), когда приложение уже инициализировано.
}

// AVPN: ленивая загрузка истории — ТОЛЬКО когда приложение готово (создан QCoreApplication и задан
// org-name). До main() (ранний конструктор/пуш-колбэк) — no-op, чтобы не трогать CFPreferences с NULL
// app-id. Повторно безопасно: грузим один раз (m_loaded), при следующем доступе попробуем снова.
void AvpnPushBridge::ensureLoaded()
{
    if (m_loaded)
        return;
    if (!QCoreApplication::instance() || QCoreApplication::organizationName().isEmpty())
        return;
    m_loaded = true;
    loadPersisted();
}

void AvpnPushBridge::loadPersisted()
{
    QSettings s;
    const QByteArray raw = s.value(QString::fromLatin1(kNotifSettingsKey)).toByteArray();
    if (raw.isEmpty())
        return;
    const QJsonDocument doc = QJsonDocument::fromJson(raw);
    if (!doc.isArray())
        return;
    m_items = doc.array().toVariantList();
    int unread = 0;
    for (const QVariant &v : std::as_const(m_items))
        if (!v.toMap().value(QStringLiteral("read")).toBool())
            ++unread;
    m_unreadCount = unread;
}

void AvpnPushBridge::persist() const
{
    // Защита от раннего вызова (до main): не трогаем CFPreferences без org-name (см. ensureLoaded).
    if (!QCoreApplication::instance() || QCoreApplication::organizationName().isEmpty())
        return;
    QSettings s;
    s.setValue(QString::fromLatin1(kNotifSettingsKey),
               QJsonDocument(QJsonArray::fromVariantList(m_items)).toJson(QJsonDocument::Compact));
}

AvpnPushBridge *AvpnPushBridge::instance()
{
    // Лениво создаём один экземпляр. Живёт в Qt-главном потоке (создаётся из coreController).
    static AvpnPushBridge *s_instance = new AvpnPushBridge();
    return s_instance;
}

void AvpnPushBridge::markAllRead()
{
    ensureLoaded();
    bool changedAny = (m_unreadCount != 0);
    m_unreadCount = 0;
    for (auto &v : m_items) {
        QVariantMap m = v.toMap();
        if (!m.value(QStringLiteral("read")).toBool()) {
            m[QStringLiteral("read")] = true;
            v = m;
            changedAny = true;
        }
    }
    if (changedAny)
        persist();   // AVPN: сохранить обновлённые read-флаги локально
    // AVPN: сбросить системный бейдж иконки (натив: setBadgeCount:0) — даже если локально уже 0,
    // системный бейдж мог быть выставлен прилетевшим aps.badge, пока приложение было закрыто.
    if (m_badgeClearer)
        m_badgeClearer();
    updateNativeBadge();   // AVPN (P-ANN, macOS): dockTile → 0
    // AVPN: сказать серверу «прочитано» (обнулит серверный счётчик) — движок слушает readRequested.
    emit readRequested();
    if (changedAny)
        emit changed();
}

// AVPN (read per-элемент): пометить прочитанным ОДНО уведомление (открыта детальная страница).
// Локально — сразу (точка в списке гаснет, бейдж -1); серверу — сигнал readItemRequested(id),
// только если у элемента есть серверный id (>0). Локальный пуш без id серверная история
// заместит строкой с id при ближайшем refreshNotifications — рассинхрон само-чинится.
void AvpnPushBridge::markItemRead(int index)
{
    setItemRead(index, true);
}

// AVPN (свайп-тоггл, эталон 2026-07-12): read-состояние одного элемента в обе стороны.
void AvpnPushBridge::setItemRead(int index, bool read)
{
    ensureLoaded();
    if (index < 0 || index >= m_items.size())
        return;
    QVariantMap m = m_items[index].toMap();
    if (m.value(QStringLiteral("read")).toBool() == read)
        return;   // уже в целевом состоянии — ни persist, ни сеть не нужны
    m[QStringLiteral("read")] = read;
    m_items[index] = m;
    m_unreadCount = qMax(0, m_unreadCount + (read ? -1 : 1));
    persist();
    updateNativeBadge();   // macOS dockTile ← unreadCount
    // iOS: числового сеттера нет (aps.badge ставит сервер) — гасим системный бейдж,
    // когда непрочитанных не осталось; частичное чтение подтянет следующий пуш.
    if (m_unreadCount == 0 && m_badgeClearer)
        m_badgeClearer();
    const qlonglong id = m.value(QStringLiteral("id")).toLongLong();
    if (id > 0)
        emit readItemRequested(id, read);
    emit changed();
}

// AVPN (свайп «Удалить»): локально сразу (лента и бейдж), сервер — по сигналу.
void AvpnPushBridge::removeItem(int index)
{
    ensureLoaded();
    if (index < 0 || index >= m_items.size())
        return;
    const QVariantMap m = m_items[index].toMap();
    const bool wasUnread = !m.value(QStringLiteral("read")).toBool();
    m_items.removeAt(index);
    if (wasUnread)
        m_unreadCount = qMax(0, m_unreadCount - 1);
    persist();
    updateNativeBadge();
    if (m_unreadCount == 0 && m_badgeClearer)
        m_badgeClearer();
    const qlonglong id = m.value(QStringLiteral("id")).toLongLong();
    if (id > 0)
        emit deleteItemRequested(id);
    emit changed();
}

// AVPN (центр уведомлений): серверная история /v1/notifications замещает локальную. Фетч-ошибки
// сюда не доходят (движок зовёт только на валидном 2xx-массиве) — офлайн живёт на локальной копии.
void AvpnPushBridge::setServerItems(const QVariantList &items)
{
    ensureLoaded();
    if (items == m_items)
        return;
    m_items = items;
    int unread = 0;
    for (const QVariant &v : std::as_const(m_items))
        if (!v.toMap().value(QStringLiteral("read")).toBool())
            ++unread;
    m_unreadCount = unread;
    persist();
    updateNativeBadge();
    emit changed();
}

void AvpnPushBridge::requestAuthorization()
{
    // На iOS m_authRequester указывает на C-функцию из AvpnPushController.mm (запросит UN + APNs).
    // На desktop/Android без регистратора — no-op (но сигнал отдаём, вдруг кто слушает).
    if (m_authRequester)
        m_authRequester();
    emit authorizationRequested();
}

void AvpnPushBridge::setAuthorizationRequester(void (*fn)())
{
    m_authRequester = fn;
}

void AvpnPushBridge::setBadgeClearer(void (*fn)())
{
    m_badgeClearer = fn;
}

void AvpnPushBridge::setBadgeSetter(void (*fn)(int))
{
    m_badgeSetter = fn;
    updateNativeBadge();   // сразу отразить текущее состояние (LKG-история уже могла загрузиться)
}

void AvpnPushBridge::updateNativeBadge()
{
    if (m_badgeSetter)
        m_badgeSetter(m_unreadCount);
}

// --- Натив-слой: маршалинг в Qt-поток ---

void AvpnPushBridge::setDeviceToken(const QString &token, const QString &platform)
{
    QMetaObject::invokeMethod(
        this, [this, token, platform]() { applyDeviceToken(token, platform); },
        Qt::QueuedConnection);
}

void AvpnPushBridge::setPushEnvironment(const QString &environment)
{
    QMetaObject::invokeMethod(
        this, [this, environment]() { applyPushEnvironment(environment); }, Qt::QueuedConnection);
}

void AvpnPushBridge::setAuthStatus(const QString &status)
{
    QMetaObject::invokeMethod(
        this, [this, status]() { applyAuthStatus(status); }, Qt::QueuedConnection);
}

void AvpnPushBridge::onRemoteNotification(const QString &title, const QString &body)
{
    onRemoteNotification(title, body, QString(), 0);
}

void AvpnPushBridge::onRemoteNotification(const QString &title, const QString &body,
                                          const QString &type, int days)
{
    QMetaObject::invokeMethod(
        this, [this, title, body, type, days]() { applyRemoteNotification(title, body, type, days); },
        Qt::QueuedConnection);
}

void AvpnPushBridge::onPushTapped(const QString &type)
{
    // Натив зовёт с main queue iOS — эмитим сигнал из Qt-потока (как остальные мосты).
    // Тип дополнительно запоминаем: на cold start сигнал уходит ДО создания QML —
    // PageStart доберёт его через takePendingPushTap() в onGoToPageHome.
    QMetaObject::invokeMethod(
        this,
        [this, type]() {
            m_pendingTapType = type;
            emit pushTapped(type);
        },
        Qt::QueuedConnection);
}

QString AvpnPushBridge::takePendingPushTap()
{
    const QString t = m_pendingTapType;
    m_pendingTapType.clear();
    return t;
}

// --- apply* — выполняются уже в Qt-потоке ---

void AvpnPushBridge::applyDeviceToken(const QString &token, const QString &platform)
{
    if (m_deviceToken == token && m_platform == platform)
        return;
    m_deviceToken = token;
    m_platform = platform;
    emit changed();
    // AVPN: токен готов → движок отправит его на бэкенд авторизованно (Bearer subscription_token).
    // Окружение (m_environment) уже применено — натив зовёт setPushEnvironment ПЕРЕД setDeviceToken.
    if (!token.isEmpty())
        emit deviceTokenReady(token, platform, m_environment);
}

void AvpnPushBridge::applyAuthStatus(const QString &status)
{
    if (m_authStatus == status)
        return;
    m_authStatus = status;
    emit changed();
}

void AvpnPushBridge::applyPushEnvironment(const QString &environment)
{
    m_environment = environment; // не эмитим changed(): служебное поле для регистрации, не для UI
}

void AvpnPushBridge::applyRemoteNotification(const QString &title, const QString &body,
                                             const QString &type, int days)
{
    // AVPN (Support): ответ оператора живёт в чате поддержки (своя история и свой
    // бейдж через TribeSupportChat) — в колокол/центр уведомлений его НЕ дублируем,
    // только сигналим движку чата (внеочередной фетч треда/счётчика).
    if (type == QLatin1String("support")) {
        emit supportPushReceived();
        return;
    }
    ensureLoaded();   // подгрузить прошлую историю, чтобы новый пуш не затёр её при persist()
    QVariantMap item;
    item[QStringLiteral("id")] = 0;   // серверного id у локального пуша нет — появится после refresh
    item[QStringLiteral("title")] = title;
    item[QStringLiteral("body")] = body;
    item[QStringLiteral("time")] = QDateTime::currentDateTime().toString(QStringLiteral("HH:mm"));
    // AVPN (эталон 2026-07-12): группа для секций списка + полная дата для детали.
    item[QStringLiteral("group")] = QStringLiteral("today");
    item[QStringLiteral("dateFull")] =
        tr("Сегодня в %1").arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm")));
    item[QStringLiteral("read")] = false;
    // Тип для стиля делегата в центре: пустой payload (старый пуш) → "generic".
    item[QStringLiteral("type")] = type.isEmpty() ? QStringLiteral("generic") : type;
    item[QStringLiteral("days")] = days;
    m_items.prepend(item);
    // Не копим бесконечно — держим последние 50.
    while (m_items.size() > 50)
        m_items.removeLast();
    m_unreadCount += 1;
    persist();   // AVPN: сохранить новый пуш в локальную историю (переживёт перезапуск)
    updateNativeBadge();   // AVPN (P-ANN, macOS): dockTile ← unreadCount
    emit changed();
    // AVPN (store-flow E): оплата прошла → сигнал движку на мгновенный рефреш подписки
    // (после обычной обработки: пуш «Доступ продлён (+N дней)» остаётся в колоколе).
    if (type == QLatin1String("payment"))
        emit paymentPushReceived();
    // AVPN (P-ANN): объявление опубликовано → движок перечитывает /v1/announcements
    // (попап поверх главного всплывает сразу; карточка в колоколе уже добавлена выше).
    if (type == QLatin1String("announcement"))
        emit announcementPushReceived();
}

} // namespace avpn
