// client/core/serviceEngine/TribeJournal.cpp — см. TribeJournal.h и JournalPolicy.h.
#include "TribeJournal.h"

#include "logger.h" // штатный файловый лог Qt приложения (Logger::userLogsFilePath)

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLoggingCategory>
#include <QMutex>
#include <QMutexLocker>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPointer>
#include <QSettings>
#include <QStandardPaths>
#include <QTimer>
#include <QUrl>

#include <atomic>

#ifdef Q_OS_IOS
#include "platforms/ios/TribeJournalIos.h"
#endif

namespace avpn {

namespace {

std::atomic<bool> g_active{false};
// Запись структурного журнала (любой поток) и его ротация (главный поток) — под одним замком.
QMutex g_structMutex;
bool g_loggerOwned = false; // лог Qt открыл журнал, а не пользователь

const QString kOffsetPrefix = QStringLiteral("avpn/journal/offset/");
const QString kWasActiveKey = QStringLiteral("avpn/journal/wasActive");
const QString kOffAtPrefix = QStringLiteral("avpn/journal/offAt/"); // размер лога при выключении
const QString kLastSentKey = QStringLiteral("avpn/journal/lastSentAt");
// Снимок диагностики в одном событии — не больше этого (серверный кап распакованного — 4 МиБ).
constexpr int kSnapshotMaxChars = 512 * 1024;
// Таймаут одной пачки: укладывается в фоновое время iOS (~30 с) с запасом.
constexpr int kRequestTimeoutMs = 20000;

qint64 loadOffset(const QString &key)
{
    return QSettings().value(kOffsetPrefix + key, 0).toLongLong();
}

void storeOffset(const QString &key, qint64 value)
{
    QSettings().setValue(kOffsetPrefix + key, value);
}

qint64 fileSize(const QString &path)
{
    const QFileInfo fi(path);
    return fi.exists() ? fi.size() : 0;
}

QString nowIso()
{
    return journal::isoUtcMs(QDateTime::currentDateTimeUtc());
}

} // namespace

// ── TribeJournal ────────────────────────────────────────────────────────────────────────────

QString TribeJournal::dir()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + QStringLiteral("/journal");
}

QString TribeJournal::structuredPath()
{
    return dir() + QStringLiteral("/app.jsonl");
}

QString TribeJournal::structuredRotatedPath()
{
    return dir() + QStringLiteral("/app.jsonl.1");
}

bool TribeJournal::active()
{
    return g_active.load();
}

bool TribeJournal::isTestFlight()
{
#ifdef Q_OS_IOS
    return TribeJournalIos_isTestFlight();
#else
    return false;
#endif
}

QList<journal::JournalSource> TribeJournal::sources()
{
    using journal::TextFormat;
    QList<journal::JournalSource> list{
        {QStringLiteral("struct1"), structuredRotatedPath(), TextFormat::Structured, QStringLiteral("app")},
        {QStringLiteral("struct"), structuredPath(), TextFormat::Structured, QStringLiteral("app")},
    };
#ifndef Q_OS_ANDROID
    list.append({QStringLiteral("qt"), Logger::userLogsFilePath(), TextFormat::QtLog, QStringLiteral("app")});
#endif
#if defined(Q_OS_MACOS) || defined(Q_OS_WIN) || defined(Q_OS_LINUX)
    // Десктоп: туннель живёт в привилегированной службе — её лог (тот же формат Logger) = «туннель».
    list.append({QStringLiteral("svc"), Logger::serviceLogsFilePath(), TextFormat::QtLog, QStringLiteral("ne")});
#endif
#ifdef Q_OS_IOS
    const QString group = TribeJournalIos_appGroupDir();
    if (!group.isEmpty()) {
        // app.log — Swift-части приложения, ne.log — туннель; оба в формате Log.swift (местное время).
        list.append({QStringLiteral("swift"), group + QStringLiteral("/app.log"), TextFormat::NeLog, QStringLiteral("app")});
        list.append({QStringLiteral("ne"), group + QStringLiteral("/ne.log"), TextFormat::NeLog, QStringLiteral("ne")});
    }
#endif
    return list;
}

void TribeJournal::setActive(bool on, bool keepFileLogs)
{
    QSettings settings;
    const bool wasActive = settings.value(kWasActiveKey, false).toBool();
    if (on && !wasActive) {
        // Включили: при первом включении старую историю текстовых логов не шлём, только новое;
        // при повторном (выкл→вкл) неотправленное досылаем (JournalPolicy::offsetOnEnable).
        for (const journal::JournalSource &s : sources()) {
            if (s.fmt == journal::TextFormat::Structured)
                continue;
            const QString mark = kOffAtPrefix + s.key;
            const qint64 offAt = settings.value(mark, -1).toLongLong();
            storeOffset(s.key, journal::offsetOnEnable(loadOffset(s.key), offAt, fileSize(s.path)));
            settings.remove(mark);
        }
        settings.setValue(kWasActiveKey, true);
    } else if (!on && wasActive) {
        // Размер логов в момент выключения: по нему повторное включение отличит неотправленное
        // от записанного, пока журнал был выключен.
        for (const journal::JournalSource &s : sources()) {
            if (s.fmt != journal::TextFormat::Structured)
                settings.setValue(kOffAtPrefix + s.key, fileSize(s.path));
        }
        settings.setValue(kWasActiveKey, false);
    }

    const bool was = g_active.exchange(on);
    if (was == on)
        return;

    // Подробный сетевой лог Qt (TLS, монитор сети) — пока журнал включён: объясняет зависшие
    // и оборванные запросы. Только наши категории qt.network.*; выключение возвращает умолчания.
    QLoggingCategory::setFilterRules(on ? QStringLiteral("qt.network.ssl.debug=true\n"
                                                         "qt.network.monitor.debug=true")
                                        : QString());
#ifndef Q_OS_ANDROID
    if (on) {
        // На desktop пользовательский лог уже открыт апстримом (CoreController::initLogging); на iOS
        // апстрим открывает его только по переключателю — открываем сами. Повторный init — no-op.
# ifdef Q_OS_IOS
        const bool openQtLog = true;
# else
        const bool openQtLog = !keepFileLogs;
# endif
        if (openQtLog && Logger::init(false))
            g_loggerOwned = !keepFileLogs;
    } else if (g_loggerOwned) {
        Logger::deInit();
        g_loggerOwned = false;
    }
#endif
#ifdef Q_OS_IOS
    TribeJournalIos_setNativeLogging(on || keepFileLogs);
#endif
#if defined(Q_OS_MACOS) || defined(Q_OS_WIN) || defined(Q_OS_LINUX)
    Logger::setServiceLogsEnabled(on || keepFileLogs); // лог службы туннеля (IPC; служба не запущена — no-op)
#endif
    Q_UNUSED(keepFileLogs)
}

void TribeJournal::append(const QString &ev, const QJsonObject &fields)
{
    if (!g_active.load())
        return;
    QJsonObject e = fields;
    e.insert(QStringLiteral("t"), nowIso());
    e.insert(QStringLiteral("src"), QStringLiteral("app"));
    e.insert(QStringLiteral("ev"), ev);
    QByteArray line = QJsonDocument(e).toJson(QJsonDocument::Compact);
    line += '\n';

    QMutexLocker lock(&g_structMutex);
    QDir().mkpath(dir());
    QFile f(structuredPath());
    if (f.open(QIODevice::WriteOnly | QIODevice::Append))
        f.write(line);
}

// ── TribeJournalUploader ────────────────────────────────────────────────────────────────────

TribeJournalUploader::TribeJournalUploader(QNetworkAccessManager *nam, std::function<QString()> baseUrl,
                                           std::function<QString()> token, QObject *parent)
    : QObject(parent), m_nam(nam), m_baseUrl(std::move(baseUrl)), m_token(std::move(token))
{
    m_lastSentAt = QSettings().value(kLastSentKey).toDateTime();
}

qint64 TribeJournalUploader::pendingBytes() const
{
    qint64 total = 0;
    for (const journal::JournalSource &s : TribeJournal::sources()) {
        const qint64 size = fileSize(s.path);
        total += size - journal::effectiveOffset(loadOffset(s.key), size);
    }
    return total;
}

// Ротация структурного журнала и обрезка отправленных текстовых логов. Главный поток.
void TribeJournalUploader::maintain()
{
    {
        QMutexLocker lock(&g_structMutex);
        const QString cur = TribeJournal::structuredPath();
        const QString rot = TribeJournal::structuredRotatedPath();
        // Отправленный целиком *.1 больше не нужен.
        if (QFile::exists(rot) && loadOffset(QStringLiteral("struct1")) >= fileSize(rot)) {
            QFile::remove(rot);
            storeOffset(QStringLiteral("struct1"), 0);
        }
        if (fileSize(cur) > journal::kStructRotateBytes) {
            QFile::remove(rot); // неотправленный остаток старого *.1 теряем — журнал не растёт без меры
            if (QFile::rename(cur, rot)) {
                storeOffset(QStringLiteral("struct1"), loadOffset(QStringLiteral("struct")));
                storeOffset(QStringLiteral("struct"), 0);
            }
        }
    }
    for (const journal::JournalSource &s : TribeJournal::sources()) {
        if (s.fmt == journal::TextFormat::Structured)
            continue;
        const qint64 size = fileSize(s.path);
        if (size == 0 || !journal::shouldTruncate(size, loadOffset(s.key)))
            continue;
        // Писатели (Logger, Log.swift) дописывают в конец — обрезка под ними безопасна.
        QFile f(s.path);
        if (f.resize(0))
            storeOffset(s.key, 0);
    }
}

void TribeJournalUploader::flush(const QString &reason, const QString &snapshot)
{
    if (m_inFlight) {
        m_flushAgain = true;
        m_againReason = reason;
        if (!snapshot.isEmpty())
            m_pendingSnapshot = snapshot;
        return;
    }
    if (!TribeJournal::active()) {
        emit idle();
        return;
    }
    if (!m_nam || m_token().isEmpty()) {
        m_lastError = tr("Нет авторизации устройства");
        emit statusChanged();
        emit flushFinished(false);
        emit idle();
        return;
    }
    m_inFlight = true;
    m_batches = 0;
    m_anyOk = false;
    m_lastError.clear();
    emit statusChanged();

    TribeJournal::append(QStringLiteral("journal_flush"), {{QStringLiteral("reason"), reason}});
    maintain();

    if (snapshot.isEmpty()) {
        sendNext();
        return;
    }
    QJsonObject e;
    e.insert(QStringLiteral("t"), nowIso());
    e.insert(QStringLiteral("src"), QStringLiteral("app"));
    e.insert(QStringLiteral("ev"), QStringLiteral("snapshot"));
    e.insert(QStringLiteral("reason"), reason);
    e.insert(QStringLiteral("msg"), snapshot.left(kSnapshotMaxChars));
    QByteArray line = QJsonDocument(e).toJson(QJsonDocument::Compact);
    line += '\n';
    post(line, QStringLiteral("app"), 1, [this](int code) {
        if (code >= 200 && code < 300) {
            m_anyOk = true;
            ++m_batches;
            sendNext();
            return;
        }
        m_lastError = code == 0 ? tr("Нет связи с сервером") : tr("Сервер ответил %1").arg(code);
        finish(false);
    });
}

void TribeJournalUploader::sendNext()
{
    if (m_batches >= journal::kMaxBatchesPerFlush) {
        finish(true); // остальное — со следующей досылкой
        return;
    }
    const QList<journal::JournalSource> srcs = TribeJournal::sources();
    QHash<QString, qint64> offsets;
    for (const journal::JournalSource &s : srcs)
        offsets.insert(s.key, loadOffset(s.key));
    const journal::BatchPlan plan = journal::planBatch(
        srcs, offsets, journal::kBatchRawBytes, QDateTime::currentDateTime().offsetFromUtc(), nowIso());
    if (plan.newOffsets.isEmpty()) {
        finish(true); // нового нет
        return;
    }
    const QHash<QString, qint64> next = plan.newOffsets;
    auto apply = [next]() {
        for (auto it = next.cbegin(); it != next.cend(); ++it)
            storeOffset(it.key(), it.value());
    };
    if (plan.events == 0) {
        // Прочитали только пустые/битые строки — сдвигаемся без запроса.
        apply();
        ++m_batches;
        QTimer::singleShot(0, this, &TribeJournalUploader::sendNext);
        return;
    }
    post(plan.jsonl, plan.srcTag, plan.events, [this, apply](int code) {
        if (code >= 200 && code < 300) {
            apply();
            m_anyOk = true;
            ++m_batches;
            sendNext();
        } else if (code == 400 || code == 413) {
            // Пачку сервер не примет никогда — пропускаем, иначе источник встал бы навсегда.
            apply();
            ++m_batches;
            m_lastError = tr("Сервер отклонил часть журнала (%1)").arg(code);
            sendNext();
        } else {
            m_lastError = code == 0 ? tr("Нет связи с сервером") : tr("Сервер ответил %1").arg(code);
            finish(false);
        }
    });
}

void TribeJournalUploader::post(const QByteArray &jsonl, const QString &srcTag, int events,
                                std::function<void(int)> done)
{
    // qCompress = 4 байта длины (Qt) + поток zlib; сервер принимает чистый zlib.
    const QByteArray body = qCompress(jsonl, 6).mid(4);
    QNetworkRequest req{QUrl(m_baseUrl() + QStringLiteral("/v1/diag/journal"))};
    req.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/octet-stream"));
    req.setRawHeader(QByteArrayLiteral("Authorization"), QByteArrayLiteral("Bearer ") + m_token().toUtf8());
    req.setRawHeader(QByteArrayLiteral("X-Journal-Source"), srcTag.toLatin1());
    req.setRawHeader(QByteArrayLiteral("X-App-Version"), QCoreApplication::applicationVersion().left(64).toUtf8());
    req.setTransferTimeout(kRequestTimeoutMs);
    QNetworkReply *reply = m_nam->post(req, body);
    m_reply = reply;
    m_replyClock.start();
    QPointer<TribeJournalUploader> self(this);
    const qint64 sent = body.size();
    const qint64 raw = jsonl.size();
    connect(reply, &QNetworkReply::finished, this,
            [self, reply, done = std::move(done), sent, raw, srcTag, events]() {
        reply->deleteLater();
        if (!self)
            return;
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        // Результат каждой отправки — в журнал (уйдёт следующей пачкой): без него зависшая или
        // отклонённая досылка невидима при разборе.
        QJsonObject f{{QStringLiteral("code"), code},
                      {QStringLiteral("ms"), self->m_replyClock.isValid() ? self->m_replyClock.elapsed() : -1},
                      {QStringLiteral("bytes"), sent},
                      {QStringLiteral("raw"), raw},
                      {QStringLiteral("events"), events},
                      {QStringLiteral("batch_src"), srcTag}};
        if (reply->error() != QNetworkReply::NoError)
            f.insert(QStringLiteral("net_error"), int(reply->error()));
        // Не сразу в файл: иначе эта же досылка тут же отправила бы пачку ради этого события.
        self->m_uploadLog.append(f);
        if (self->m_reply == reply)
            self->m_reply.clear();
        done(code);
    });
}

bool TribeJournalUploader::kickIfStale(int maxAgeMs)
{
    if (!m_inFlight || !m_reply || !m_replyClock.isValid() || m_replyClock.elapsed() < maxAgeMs)
        return false;
    TribeJournal::append(QStringLiteral("journal_kick"),
                         {{QStringLiteral("age_ms"), m_replyClock.elapsed()}});
    m_reply->abort(); // finished(OperationCanceledError), code 0 → досылка завершится неудачей
    return true;
}

void TribeJournalUploader::finish(bool ok)
{
    m_inFlight = false;
    for (const QJsonObject &f : std::as_const(m_uploadLog))
        TribeJournal::append(QStringLiteral("journal_upload"), f);
    m_uploadLog.clear();
    if (m_anyOk) {
        m_lastSentAt = QDateTime::currentDateTime();
        QSettings().setValue(kLastSentKey, m_lastSentAt);
    }
    emit statusChanged();
    emit flushFinished(ok);
    if (m_flushAgain) {
        m_flushAgain = false;
        const QString reason = m_againReason;
        const QString snapshot = m_pendingSnapshot;
        m_pendingSnapshot.clear();
        QTimer::singleShot(0, this, [this, reason, snapshot]() { flush(reason, snapshot); });
        return; // idle — после досылки из очереди
    }
    emit idle();
}

} // namespace avpn
