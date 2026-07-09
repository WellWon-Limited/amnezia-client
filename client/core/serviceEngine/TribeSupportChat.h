// AVPN — Tribe: чат поддержки (клиент нативного приложения).
//
// Движковая половина экрана PageSupportTribe.qml: разговор с оператором через
// device-Bearer-зеркало бэкенда /v1/support/* (Tribe-Backend, openapi 0.6.0,
// спека documents/SUPPORT-CHAT.md §4a). Один тред на аккаунт, вся история одним
// ответом (без пагинации).
//
// Транспорт: поллинг (страница открыта → весь тред каждые kActivePollMs; фон →
// только /unread каждые kIdlePollMs) + внеочередной refresh() по APNs-пушу
// type=support (коннектится в coreController). SSE намеренно нет — см. спеку.
//
// ЖЕЛЕЗНОЕ правило движка: никаких nested QEventLoop на GUI-потоке — все запросы
// асинхронные с armTimeout (NetAwait.h), результат — через NOTIFY/сигналы.
//
// Медиа:
//  - превью (WebP ≤480px) качаются с Bearer и отдаются в QML data:-URL
//    (паттерн makeQrCode — штатный Image не умеет authed-заголовки);
//  - оригинал скачивается во временный файл → attachmentReady(file://…).
//    302-редирект на подписанный R2-URL обрабатывается ВРУЧНУЮ: авто-редирект
//    Qt повторил бы Authorization-заголовок, а S3 отвергает запросы с двумя
//    механизмами авторизации (presigned query + header).
//  - отправка: QHttpMultiPart; фото >~1.5 МБ/крупнее 1600px пережимаются в
//    JPEG (как canvas-компрессия Занавеса), видео стримится из файла.
#pragma once

#include <QByteArray>
#include <QHash>
#include <QObject>
#include <QSet>
#include <QString>
#include <QTimer>
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>

class QNetworkAccessManager;
class QNetworkReply;

namespace avpn {

class TribeSupportChat : public QObject {
    Q_OBJECT
    // Сообщения треда (хронология) + наши неподтверждённые «эхо» в хвосте.
    // Элемент: {id, sender: "client"|"operator", body, operatorName, isAuto,
    //           atMs (epoch мс, локальное время считает QML), pending, failed,
    //           attachments: [{id, kind: "image"|"video", mime, name, bytes,
    //                          width, height, hasThumb, thumbUrl (data:-URL или ""),
    //                          localUrl (file:// для эха, иначе "")}],
    //           card (опц., store-flow D): {title, body, buttons: [{label,
    //                          action: "open_url"|"compose_send", url, send}]} —
    //                          server-driven карточка, рендерится ВМЕСТО body}
    Q_PROPERTY(QVariantList messages READ messages NOTIFY messagesChanged)
    Q_PROPERTY(QString status READ status NOTIFY messagesChanged)      // "open" | "resolved"
    Q_PROPERTY(int unread READ unread NOTIFY unreadChanged)            // бейдж вкладки
    Q_PROPERTY(bool loading READ loading NOTIFY loadingChanged)        // первый фетч треда
    // Страница чата на экране: true → частый поллинг всего треда (и mark-read на
    // бэке), false → редкий поллинг только счётчика. Ставит QML (Component.on*).
    Q_PROPERTY(bool active READ active WRITE setActive NOTIFY activeChanged)

public:
    explicit TribeSupportChat(QNetworkAccessManager *nam, QObject *parent = nullptr);

    QVariantList messages() const { return m_messages; }
    QString status() const { return m_status; }
    int unread() const { return m_unread; }
    bool loading() const { return m_loading; }
    bool active() const { return m_active; }
    void setActive(bool on);

    Q_INVOKABLE void refresh();        // GET /thread (заодно mark-read на бэке)
    Q_INVOKABLE void refreshUnread();  // GET /unread (фоновый бейдж)
    Q_INVOKABLE void sendText(const QString &body);
    // Файл из пикера (file://…). Валидация типа/размера + пережатие фото — тут.
    Q_INVOKABLE void sendAttachmentFile(const QUrl &fileUrl);
    Q_INVOKABLE void retryMessage(int localId);    // повторить failed-эхо
    Q_INVOKABLE void discardMessage(int localId);  // убрать failed-эхо
    // Скачать оригинал вложения во временный файл → attachmentReady(file://…).
    Q_INVOKABLE void openAttachment(int attachmentId);
    // iOS: нативный PHPicker (фотоплёнка без пермишена; TribeMediaPicker.mm) →
    // выбранный файл вернётся в sendAttachmentFile. false → QML открывает FileDialog.
    Q_INVOKABLE bool pickMediaNative();

public slots:
    // APNs/FCM type=support (коннект в coreController): открыт чат → перечитать
    // тред; закрыт → ТОЛЬКО счётчик. GET /thread помечает прочитанным на бэке —
    // дёргать его на пуше при закрытом чате значит гасить непрочитанное за
    // спиной пользователя.
    void onSupportPush();

signals:
    void messagesChanged();
    void unreadChanged();
    void loadingChanged();
    void activeChanged();
    // Человекочитаемая причина для тоста (429/сеть/размер/тип файла).
    void sendFailed(const QString &reason);
    void attachmentReady(int attachmentId, const QString &kind, const QUrl &fileUrl);
    void attachmentFailed(int attachmentId);

private:
    struct Echo {
        int localId = 0;          // отрицательный — не пересекается с серверными id
        QString body;             // текст (пусто у вложения)
        QString kind;             // "" | "image" | "video"
        QString mime;
        QString fileName;
        QString filePath;         // исходный файл (видео стримится с диска)
        QByteArray imageBytes;    // пережатое фото (грузим из памяти)
        QString localUrl;         // file:// для локального превью эха
        qint64 atMs = 0;
        bool pending = true;
        bool failed = false;
    };

    QString authToken() const;
    QNetworkReply *authedGet(const QString &path, int timeoutMs);
    // JSON сообщения бэкенда → QVariantMap модели (заодно ставит превью в очередь).
    QVariantMap parseMessage(const QJsonObject &m);
    void schedulePoll();
    void rebuildMessages();                  // m_serverMessages + эхо → m_messages (+ emit при изменении)
    void applyThread(const QByteArray &json);
    void postEcho(Echo &echo);               // POST messages|attachments для эха
    void queueThumb(int attachmentId);
    void fetchNextThumb();
    void finishOriginal(int attachmentId, const QString &kind, const QString &mime,
                        const QByteArray &data);
    Echo *echoByLocalId(int localId);
    static QString sanitizeFileName(const QString &name);

    QNetworkAccessManager *m_nam = nullptr;
    QString m_baseUrl;

    QVariantList m_messages;                 // готовая модель для QML
    QVariantList m_serverMessages;           // последняя разобранная серверная история
    QByteArray m_lastSnapshot;               // анти-дребезг: не эмитим без изменений
    QString m_status = QStringLiteral("open");
    int m_unread = 0;
    bool m_loading = false;
    bool m_active = false;
    bool m_threadLoadedOnce = false;
    bool m_refreshInFlight = false;
    bool m_unreadInFlight = false;
    // Пока наш POST в полёте, тред НЕ перечитываем: поллинг мог привезти уже
    // закоммиченную серверную копию при ещё живом эхе → дубль на экране.
    // Отложенные запросы (поллинг/пуш во время долгого аплоада) копятся во флаг
    // и выстреливают ОДНИМ refresh() сразу после завершения POST — иначе ответ
    // оператора был бы невидим до конца 3-минутного видео-аплоада.
    int m_postsInFlight = 0;
    bool m_refreshPending = false;

    QList<Echo> m_echoes;
    int m_localSeq = 0;

    QTimer m_pollTimer;

    // Кэш превью: attachment id → data:-URL (живёт с процессом; WebP ≤480px — дёшево).
    QHash<int, QString> m_thumbCache;
    QList<int> m_thumbQueue;
    QSet<int> m_thumbQueued;
    bool m_thumbInFlight = false;

    // Скачивание оригиналов: id → путь готового temp-файла; и гард от дублей.
    QHash<int, QString> m_originalPath;
    QSet<int> m_originalInFlight;
};

} // namespace avpn
