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

#include <QAbstractListModel>
#include <QByteArray>
#include <QHash>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>

#include <memory>

#include "SupportReportQueue.h" // AVPN (L9, F12): on-disk queue of support reports

class QNetworkAccessManager;
class QNetworkReply;

namespace avpn {

// Точечная модель сообщений для ListView (жалоба 2026-07-12 «скролл дёрганый, медиа
// мигают/пропадают»): полная замена QVariantList-модели на КАЖДОЕ изменение (поллинг 5с,
// приезд превью, прогресс эха) пересоздавала ВСЕ делегаты — async-картинки мигали, позиция
// скролла слетала, флики становились рваными. Золотой паттерн QML-чатов (NeoChat/Kaidan):
// QAbstractListModel с дифом — изменившаяся строка = dataChanged, новое сообщение =
// insertRows в хвост; остальные делегаты НЕ трогаются. Диф по общему префиксу id:
// история append-only, меняется только хвост (эхо → серверная копия).
class TribeSupportMsgModel : public QAbstractListModel {
    Q_OBJECT
public:
    explicit TribeSupportMsgModel(QObject *parent = nullptr) : QAbstractListModel(parent) {}
    int rowCount(const QModelIndex &parent = QModelIndex()) const override
    {
        return parent.isValid() ? 0 : int(m_rows.size());
    }
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;
    void applyList(const QVariantList &msgs);

private:
    QList<QVariantMap> m_rows;
};

class TribeSupportChat : public QObject {
    Q_OBJECT
    // Сообщения треда (хронология) + наши неподтверждённые «эхо» в хвосте.
    // Элемент: {id, sender: "client"|"operator", body, operatorName, isAuto,
    //           atMs (epoch мс, локальное время считает QML), pending, failed,
    //           attachments: [{id, kind: "image"|"video"|"log", mime, name, bytes,
    //                          width, height, hasThumb, thumbUrl (data:-URL или ""),
    //                          localUrl (file:// для эха, иначе "")}],
    //           card (опц., store-flow D + cards v2): {title, body,
    //                          tone: "info"|"warning"|"success", buttons: [{label,
    //                          action: "open_url"|"compose_send", url, send,
    //                          variant: "primary"|"secondary"}]} —
    //                          server-driven карточка, рендерится ВМЕСТО body}
    Q_PROPERTY(QVariantList messages READ messages NOTIFY messagesChanged)
    // Модель для ListView (роли msgId/sender/body/…): точечные обновления вместо полного
    // пересоздания делегатов. messages (QVariantList) остаётся для галереи лайтбокса.
    Q_PROPERTY(QObject *msgModel READ msgModel CONSTANT)
    Q_PROPERTY(QString status READ status NOTIFY messagesChanged)      // "open" | "resolved"
    Q_PROPERTY(int unread READ unread NOTIFY unreadChanged)            // бейдж вкладки
    Q_PROPERTY(bool loading READ loading NOTIFY loadingChanged)        // первый фетч треда
    // Страница чата на экране: true → частый поллинг всего треда (и mark-read на
    // бэке), false → редкий поллинг только счётчика. Ставит QML (Component.on*).
    Q_PROPERTY(bool active READ active WRITE setActive NOTIFY activeChanged)
    // Нативный пикер обрабатывает выбранное медиа (iOS: очистка GPS/пережатие видео/постер —
    // секунды БЕЗ какого-либо UI-фидбека) → QML показывает «Готовим…» (жалоба 2026-07-11).
    Q_PROPERTY(bool mediaPreparing READ mediaPreparing NOTIFY mediaPreparingChanged)
    // Прогресс аплоада вложения 0..1 (−1 = не идёт) — полоска над композером.
    Q_PROPERTY(qreal uploadProgress READ uploadProgress NOTIFY uploadProgressChanged)
    // AVPN (L9, F12): support-report queue (SupportReportQueue.h). Reports not yet settled by the
    // server, and "no room for a new full check" (backpressure: «Отчёты ждут связи: N. Новая
    // проверка — после отправки»). reportsFull also turns false when an abandoned reservation
    // expires; that edge is not signalled (read it again when the button is pressed).
    Q_PROPERTY(int reportsPending READ reportsPending NOTIFY reportQueueChanged)
    Q_PROPERTY(bool reportsFull READ reportsFull NOTIFY reportQueueChanged)
    // F4: reports the server refused (terminal 4xx), kept with their payload in the rejected store
    // (5 most recent / 16 MiB); retried once after an app update or a change of the server's support
    // limits, and with the user's next «Отправить логи» (sendDiagReport / resendRejectedReports).
    Q_PROPERTY(int reportsRejected READ reportsRejected NOTIFY reportQueueChanged)

public:
    // reportQueueDir: tests only; empty = <AppDataLocation>/support-report-queue.
    explicit TribeSupportChat(QNetworkAccessManager *nam, QObject *parent = nullptr,
                              const QString &reportQueueDir = QString());
    ~TribeSupportChat() override;

    QVariantList messages() const { return m_messages; }
    QObject *msgModel() const { return m_msgModel; }
    QString status() const { return m_status; }
    int unread() const { return m_unread; }
    bool loading() const { return m_loading; }
    bool active() const { return m_active; }
    void setActive(bool on);
    bool mediaPreparing() const { return m_mediaPreparing; }
    qreal uploadProgress() const { return m_uploadProgress; }
    void setMediaPreparing(bool on); // мост из TribeMediaPicker.mm (Tribe_supportMediaPreparing)

    Q_INVOKABLE void refresh();        // GET /thread (заодно mark-read на бэке)
    Q_INVOKABLE void refreshUnread();  // GET /unread (фоновый бейдж)
    Q_INVOKABLE void sendText(const QString &body);
    // Файл из пикера (file://…). Валидация типа/размера + пережатие фото — тут.
    Q_INVOKABLE void sendAttachmentFile(const QUrl &fileUrl);
    // AVPN (diag, Task 5 bff-3): диагностический отчёт (TribeEngine.buildDiagReport) в тред —
    // multipart text/plain на /v1/support/attachments, generic-имя diag.log (privacy-паттерн).
    // Гейт: kill-switch features.support_diag (default TRUE) — при false no-op с тостом.
    // 404/405/415 бэка = «эндпоинт ещё не принимает text/plain» → честный тост БЕЗ «Повторить».
    // AVPN (L9): now goes through the report queue (one log part); kept for every existing caller.
    Q_INVOKABLE void sendDiagReport(const QString &reportText);

    // AVPN (L9, F12) — the support-report queue for the Scanner's «Проверить и отправить отчёт».
    // reserveReport(): admission of a full check at its start; "" = queue full (backpressure, do not
    // start the check). The token keeps one slot for the report the check produces.
    Q_INVOKABLE QString reserveReport();
    Q_INVOKABLE void releaseReport(const QString &reservation); // the check was aborted
    // Enqueues one report: humanText -> a thread message, diagText -> diag.log, benchJson -> POST
    // /v1/bench/report (optional; empty = not part of this report). Returns {result, id}:
    // result "queued" | "full" | "too_large" | "empty" | "invalid" | "disabled" (kill switch
    // support_diag) | "unsupported" (server log_mime has no text/plain) | "unsaved_sending" (F3: the
    // queue could not write it; ONE direct attempt is running, nothing survives the app - follow
    // reportStatusChanged(id): "sent_unsaved" = both support parts acknowledged, "not_saved" = not
    // persisted and not confirmed) | "not_saved" (not persisted and no direct attempt possible).
    // Never "queued" for something that is not on disk. The reservation is consumed on "queued" and
    // released on every other result.
    Q_INVOKABLE QVariantMap submitReport(const QString &humanText, const QString &diagText,
                                         const QString &benchJson = QString(),
                                         const QString &reservation = QString());
    // "queued" | "sending" | "delivered" | "rejected" (kept in the rejected store, or evicted from it:
    // see reportStatus.kept) | "unsaved_sending" | "sent_unsaved" | "not_saved" | "unknown".
    Q_INVOKABLE QString reportResult(const QString &reportId) const;
    // {result, reason ("log:413", "evicted:log:413", "corrupt:checksum", "not_persisted", ...),
    //  parts: {text|log|bench: pending|acked|rejected|failed}, kept (payload in the rejected store)}
    Q_INVOKABLE QVariantMap reportStatus(const QString &reportId) const;
    // F4: the user's explicit «Отправить логи»: every rejected report back into the queue. Returns how
    // many moved (the queue's room permitting). sendDiagReport() calls it itself.
    Q_INVOKABLE int resendRejectedReports();
    int reportsPending() const;
    bool reportsFull() const;
    int reportsRejected() const;

    Q_INVOKABLE void retryMessage(int localId);    // повторить failed-эхо
    Q_INVOKABLE void discardMessage(int localId);  // убрать failed-эхо
    // Скачать оригинал вложения во временный файл → attachmentReady(file://…).
    Q_INVOKABLE void openAttachment(int attachmentId);
    // iOS: нативный PHPicker (фотоплёнка без пермишена; TribeMediaPicker.mm) →
    // выбранный файл вернётся в sendAttachmentFile. false → QML открывает FileDialog.
    Q_INVOKABLE bool pickMediaNative();
    // iOS: нативный просмотр скачанного вложения (QLPreviewController: видео-плеер, зум фото;
    // TribeMediaViewer.mm). false → QML падает на Qt.openUrlExternally (десктоп/Android).
    Q_INVOKABLE bool presentMediaNative(const QUrl &fileUrl);

public slots:
    // APNs/FCM type=support (коннект в coreController): открыт чат → перечитать
    // тред; закрыт → ТОЛЬКО счётчик. GET /thread помечает прочитанным на бэке —
    // дёргать его на пуше при закрытом чате значит гасить непрочитанное за
    // спиной пользователя.
    void onSupportPush();
    // AVPN backend-first (2026-07-10): следует за edge-walk control plane (AvpnEngineQml::apiBaseChanged).
    // Env-пин (AVPN_API_URL) сильнее любых edge-переключений.
    void setBaseUrl(const QString &base);

signals:
    void messagesChanged();
    void unreadChanged();
    void loadingChanged();
    void activeChanged();
    void mediaPreparingChanged();
    void uploadProgressChanged();
    // Новое ВХОДЯЩЕЕ сообщение оператора при работающем приложении (рост unread в фоне
    // вкладки или новый op-msg в открытом чате) — QML играет хаптику (жалоба 2026-07-12
    // «нет тактильной связи, что прилетело сообщение»). НЕ эмитится на первичной загрузке
    // треда/кэша и первом чтении unread после старта.
    void incomingMessage();
    // Человекочитаемая причина для тоста (429/сеть/размер/тип файла).
    void sendFailed(const QString &reason);
    void attachmentReady(int attachmentId, const QString &kind, const QUrl &fileUrl);
    void attachmentFailed(int attachmentId);
    // AVPN (L9): pending count / full changed; one report's result changed (reportResult values).
    void reportQueueChanged();
    void reportStatusChanged(const QString &reportId, const QString &result);

private:
    struct Echo {
        int localId = 0;          // отрицательный — не пересекается с серверными id
        QString body;             // текст (пусто у вложения)
        QString kind;             // "" | "image" | "video" | "log"
        QString mime;
        QString fileName;
        QString filePath;         // исходный файл (видео стримится с диска)
        QByteArray imageBytes;    // пережатое фото ЛИБО text/plain диагностика (грузим из памяти)
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
    // Коалесер rebuild'ов: превью подъезжают пачкой (параллельные фетчи + диск), а каждый
    // rebuild = полная замена модели ListView (сброс делегатов). Один отложенный rebuild
    // на пачку вместо N подряд.
    void scheduleRebuild();
    // fromCache=true — рендер thread.json с диска при старте (телеграм-паттерн: история
    // видна МГНОВЕННО, сеть только освежает). Кэш не эмитит incomingMessage и не пишется
    // обратно на диск.
    void applyThread(const QByteArray &json, bool fromCache = false);
    void loadThreadCache();
    void saveThreadCache(const QByteArray &json);
    // AVPN backend-first (T18): эффективные лимиты вложений — серверные (лимиты
    // из /thread), фолбэк — вкомпиленные kImageMaxBytes/kVideoMaxBytes/whitelist.
    qint64 effImageMaxBytes() const;
    qint64 effVideoMaxBytes() const;
    qint64 effLogMaxBytes() const;
    bool effAllowedImageMime(const QString &mime) const;
    bool effAllowedVideoMime(const QString &mime) const;
    bool effAllowedLogMime(const QString &mime) const;
    void postEcho(Echo &echo);               // POST messages|attachments для эха
    void queueThumb(int attachmentId);
    void fetchNextThumb();
    void finishOriginal(int attachmentId, const QString &kind, const QString &mime,
                        const QByteArray &data);
    Echo *echoByLocalId(int localId);
    // AVPN (L9): delivery of the report queue — one part in flight, triggers in the .cpp.
    void pumpReportQueue();
    void postQueuedPart(const srq::Due &due);
    void kickReportQueue(bool foreground); // live answer (false) / app active (true), then pump
    void reportQueueTouched(const QString &reportId);
    void appendSavedServerMessage(const QByteArray &replyBody, const QString &echoLocalUrl);
    // F3: a report the queue could not persist - one direct attempt, tracked by its own id.
    struct Unsaved {
        QString id;
        QMap<QString, QString> parts; // text|log -> pending|acked|failed
        QString result;               // "" while sending | "sent_unsaved" | "not_saved"
    };
    QString sendUnsaved(const QString &humanText, const QByteArray &diagBytes, const QByteArray &benchJson,
                        QString *reportId);
    const Unsaved *unsavedById(const QString &reportId) const;
    void settleUnsavedEcho(int localId, bool ok);
    // Бэкофф-поллинг серверного постера видео (handoff Занавеса §C: постер генерится
    // асинхронно, один refresh после POST почти всегда рано): 2с→5с→10с×3, стоп по
    // появлению постера / исчерпанию попыток / уходу со страницы (mark-read-гигиена).
    void watchPoster(int attachmentId);
    static QString sanitizeFileName(const QString &name);

    QNetworkAccessManager *m_nam = nullptr;
    QString m_baseUrl;
    bool m_envPinned = false;

    // AVPN backend-first (T18): лимиты вложений с /thread. 0/пусто = «сервер не
    // сообщил» → фолбэк на вкомпиленные kImageMaxBytes/kVideoMaxBytes/whitelist
    // (kImageMaxBytes — constexpr анонимного namespace в .cpp, тут недоступен).
    qint64 m_imageMaxBytes = 0;
    qint64 m_videoMaxBytes = 0;
    qint64 m_logMaxBytes = 0;
    QStringList m_imageMime;
    QStringList m_videoMime;
    QStringList m_logMime;

    QVariantList m_messages;                 // готовая модель для QML (галерея лайтбокса)
    TribeSupportMsgModel *m_msgModel = nullptr; // точечная модель ленты (создаётся в кторе)
    QVariantList m_serverMessages;           // последняя разобранная серверная история
    QByteArray m_lastSnapshot;               // анти-дребезг: не эмитим без изменений
    QString m_status = QStringLiteral("open");
    int m_unread = 0;
    bool m_loading = false;
    bool m_active = false;
    bool m_mediaPreparing = false;   // нативный пикер готовит медиа (см. Q_PROPERTY)
    qreal m_uploadProgress = -1;     // 0..1 во время POST вложения; −1 = не идёт
    bool m_threadLoadedOnce = false;
    bool m_refreshInFlight = false;
    bool m_unreadInFlight = false;
    // AVPN (L9, F12): replaces the single AvpnSupport/pendingDiag setting (migrated once in the ctor).
    std::unique_ptr<srq::SupportReportQueue> m_reportQueue;
    bool m_queuePostInFlight = false;
    QHash<QString, int> m_queueRowIds; // "<report>/<part>" -> stable negative row id in the feed
    QList<Unsaved> m_unsaved;                       // F3: last 16 unsaved reports (memory only, honest)
    QHash<int, QPair<QString, QString>> m_unsavedEcho; // echo localId -> (unsaved report id, part kind)
    QString m_limitsKey;                             // F4: digest of the server's support limits seen last
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

    // Кэш превью: attachment id → URL для Image (file:// на дисковый кэш; data:-URL —
    // только фолбэк, если диск не записался).
    QHash<int, QString> m_thumbCache;
    // Локальные превью бывших эх: server attId → file:// (фото или постер-кадр видео).
    // Впрыскивается в серверную историю при rebuild — превью видно непрерывно с момента
    // отправки, серверный WebP тихо подъезжает фоном (PWA-GUIDE §4).
    QHash<int, QString> m_localUrlByAttId;
    // Видео без серверного постера — бэкофф-поллер.
    QSet<int> m_posterWatch;
    QTimer m_posterTimer;
    int m_posterAttempt = 0;
    QList<int> m_thumbQueue;
    QSet<int> m_thumbQueued;
    int m_thumbsInFlight = 0;   // параллельные фетчи превью (кап kThumbParallel в .cpp)
    QTimer m_rebuildTimer;      // коалесер rebuild'ов (см. scheduleRebuild)
    // Хаптика входящих: максимум виденного id сообщения оператора + гард «первое чтение
    // unread после старта не жужжит» (там лежит непрочитанное ещё с прошлой сессии).
    int m_maxOpMsgId = 0;
    bool m_unreadFetchedOnce = false;

    // Скачивание оригиналов: id → путь готового temp-файла; и гард от дублей.
    QHash<int, QString> m_originalPath;
    QSet<int> m_originalInFlight;
};

} // namespace avpn
