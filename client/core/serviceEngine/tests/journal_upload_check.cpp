// AVPN (журнал тестирования, Tribe-Backend docs/specs/2026-09-23-tester-journal-design.md):
// TribeJournal + TribeJournalUploader против локального HTTP-сервера — запись структурных событий
// только во включённом журнале, выкл→вкл не шлёт старую историю логов, пачка = zlib JSONL с
// заголовками контракта, смещения двигаются только после 2xx, 400 пропускает пачку, 5xx
// останавливает досылку, снимок уходит отдельным событием, ротация структурного журнала.
#include "../TribeJournal.h"
#include "logger.h" // заглушка из tests/stub

#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QSettings>
#include <QStandardPaths>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QTimer>
#include <cstdio>

using namespace avpn;

static int g_failed = 0;
static int g_total = 0;

#define CHECK(expr, what)                                                                           \
    do {                                                                                            \
        ++g_total;                                                                                  \
        if (!(expr)) {                                                                              \
            ++g_failed;                                                                             \
            std::printf("FAIL: %s (%s:%d)\n", what, __FILE__, __LINE__);                            \
        }                                                                                           \
    } while (0)

static QString g_qtLogPath;
QString Logger::userLogsFilePath() { return g_qtLogPath; }
QString Logger::serviceLogsFilePath() { return g_qtLogPath + QStringLiteral(".svc"); }
bool Logger::setServiceLogsEnabled(bool) { return true; }
bool Logger::init(bool) { return true; }
void Logger::deInit() {}

struct Received {
    QByteArray head;
    QByteArray body;
};

// Минимальный HTTP/1.1-сервер: отвечает кодами из очереди (пусто → 201), копит запросы.
class FakeServer : public QObject {
public:
    QList<int> codes;
    QList<Received> got;
    QTcpServer srv;
    FakeServer()
    {
        srv.listen(QHostAddress::LocalHost);
        connect(&srv, &QTcpServer::newConnection, this, [this]() {
            QTcpSocket *s = srv.nextPendingConnection();
            auto buf = std::make_shared<QByteArray>();
            connect(s, &QTcpSocket::readyRead, s, [this, s, buf]() {
                *buf += s->readAll();
                const int he = buf->indexOf("\r\n\r\n");
                if (he < 0)
                    return;
                const QByteArray head = buf->left(he);
                qint64 len = 0;
                for (const QByteArray &l : head.split('\n')) {
                    if (l.toLower().startsWith("content-length:"))
                        len = l.mid(15).trimmed().toLongLong();
                }
                if (buf->size() - he - 4 < len)
                    return;
                got.append({head, buf->mid(he + 4, len)});
                buf->remove(0, he + 4 + len);
                const int code = codes.isEmpty() ? 201 : codes.takeFirst();
                if (code < 0)
                    return; // «зависший» сервер: запрос принят, ответа нет
                const QByteArray body = "{\"id\":\"1\",\"accepted\":1,\"dropped\":0}";
                s->write("HTTP/1.1 " + QByteArray::number(code) + " X\r\nContent-Type: application/json\r\n"
                         "Content-Length: " + QByteArray::number(body.size()) + "\r\n\r\n" + body);
            });
        });
    }
    QString base() const { return QStringLiteral("http://127.0.0.1:%1").arg(srv.serverPort()); }
};

static QByteArray header(const Received &r, const QByteArray &name)
{
    for (const QByteArray &l : r.head.split('\n')) {
        if (l.toLower().startsWith(name.toLower() + ":"))
            return l.mid(name.size() + 1).trimmed();
    }
    return {};
}

static QList<QJsonObject> events(const Received &r)
{
    const QByteArray raw = r.body;
    QByteArray withLen(4, '\0');
    withLen[0] = char(0); // qUncompress ждёт 4 байта ожидаемой длины; 0 → «неизвестно»
    const QByteArray plain = qUncompress(withLen + raw);
    QList<QJsonObject> out;
    for (const QByteArray &l : plain.split('\n')) {
        if (!l.trimmed().isEmpty())
            out.append(QJsonDocument::fromJson(l).object());
    }
    return out;
}

static bool flushAndWait(TribeJournalUploader &up, const QString &reason, const QString &snapshot = {})
{
    QEventLoop loop;
    bool result = false;
    auto c = QObject::connect(&up, &TribeJournalUploader::flushFinished, &loop, [&](bool ok) {
        result = ok;
        loop.quit();
    });
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    up.flush(reason, snapshot);
    if (up.sending())
        loop.exec();
    QObject::disconnect(c);
    return result;
}

static void appendLine(const QString &path, const QByteArray &line)
{
    QFile f(path);
    if (f.open(QIODevice::WriteOnly | QIODevice::Append))
        f.write(line);
}

int main(int argc, char **argv)
{
    QTemporaryDir home;
    qputenv("HOME", home.path().toUtf8());
    QStandardPaths::setTestModeEnabled(true);
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("TribeJournalCheck"));
    QCoreApplication::setApplicationName(QStringLiteral("journal_upload_check"));
    QCoreApplication::setApplicationVersion(QStringLiteral("5.1.91.121"));
    QSettings().clear();
    QDir(TribeJournal::dir()).removeRecursively();
    g_qtLogPath = home.filePath(QStringLiteral("AmneziaVPN.log"));

    // Старая история лога Qt до включения — не должна уйти.
    appendLine(g_qtLogPath, "[2026-09-23 09:00:00.000Z] [INFO] AmneziaVPN  : old history\n");

    TribeJournal::append(QStringLiteral("before_on"));
    CHECK(!QFile::exists(TribeJournal::structuredPath()), "append is a no-op while off");

    TribeJournal::setActive(true, false);
    CHECK(TribeJournal::active(), "active after setActive(true)");
    TribeJournal::append(QStringLiteral("ring"), {{QStringLiteral("msg"), QStringLiteral("guarded_stop")}});
    appendLine(g_qtLogPath, "[2026-09-24 10:00:00.000Z] [INFO] AmneziaVPN  : fresh line\n");

    FakeServer server;
    QNetworkAccessManager nam;
    TribeJournalUploader up(&nam, [&]() { return server.base(); }, []() { return QStringLiteral("tok"); });

    CHECK(flushAndWait(up, QStringLiteral("enabled")), "first flush ok");
    CHECK(server.got.size() == 1, "one batch for small journal");
    if (!server.got.isEmpty()) {
        const Received &r = server.got.first();
        CHECK(r.head.startsWith("POST /v1/diag/journal "), "POST /v1/diag/journal");
        CHECK(header(r, "Authorization") == "Bearer tok", "bearer token");
        CHECK(header(r, "X-Journal-Source") == "app", "app-only batch -> app");
        CHECK(header(r, "X-App-Version") == "5.1.91.121", "app version header");
        CHECK(!r.body.isEmpty() && quint8(r.body.at(0)) == 0x78, "zlib stream (0x78), no Qt length prefix");
        const QList<QJsonObject> ev = events(r);
        QStringList names;
        QString all;
        for (const QJsonObject &o : ev) {
            names << o.value(QStringLiteral("ev")).toString();
            all += o.value(QStringLiteral("msg")).toString();
            CHECK(o.value(QStringLiteral("t")).toString().endsWith(QLatin1Char('Z')), "every event has UTC t");
        }
        CHECK(names.contains(QStringLiteral("ring")) && names.contains(QStringLiteral("journal_flush")),
              "structured events sent");
        CHECK(all.contains(QStringLiteral("fresh line")), "new Qt log line sent");
        CHECK(!all.contains(QStringLiteral("old history")), "history before enabling not sent");
        CHECK(!names.contains(QStringLiteral("before_on")), "events while off never written");
    }

    // Нового нет (кроме события самой досылки) — одна маленькая пачка, повтор не дублирует старое.
    server.got.clear();
    CHECK(flushAndWait(up, QStringLiteral("timer")), "second flush ok");
    int ringCount = 0;
    for (const Received &r : server.got)
        for (const QJsonObject &o : events(r))
            ringCount += o.value(QStringLiteral("ev")).toString() == QLatin1String("ring");
    CHECK(ringCount == 0, "sent events are not resent");

    // 5xx: досылка останавливается, смещение не двигается — строка уйдёт следующей.
    TribeJournal::append(QStringLiteral("ring"), {{QStringLiteral("msg"), QStringLiteral("retry_me")}});
    server.got.clear();
    server.codes = {503};
    CHECK(!flushAndWait(up, QStringLiteral("timer")), "5xx -> flush fails");
    CHECK(!up.lastError().isEmpty(), "error kept for status line");
    server.got.clear();
    CHECK(flushAndWait(up, QStringLiteral("timer")), "retry ok");
    bool retried = false;
    for (const Received &r : server.got)
        for (const QJsonObject &o : events(r))
            retried |= o.value(QStringLiteral("msg")).toString() == QLatin1String("retry_me");
    CHECK(retried, "batch after 5xx is resent");
    CHECK(up.lastError().isEmpty(), "error cleared after success");

    // 400: пачку пропускаем (иначе источник встал бы навсегда), досылка продолжается.
    TribeJournal::append(QStringLiteral("ring"), {{QStringLiteral("msg"), QStringLiteral("rejected")}});
    server.got.clear();
    server.codes = {400};
    flushAndWait(up, QStringLiteral("timer"));
    server.got.clear();
    flushAndWait(up, QStringLiteral("timer"));
    bool resentRejected = false;
    for (const Received &r : server.got)
        for (const QJsonObject &o : events(r))
            resentRejected |= o.value(QStringLiteral("msg")).toString() == QLatin1String("rejected");
    CHECK(!resentRejected, "400 batch is skipped, not resent");

    // Снимок диагностики — отдельным событием первым.
    server.got.clear();
    CHECK(flushAndWait(up, QStringLiteral("manual"), QStringLiteral("DIAG SNAPSHOT")), "manual flush ok");
    CHECK(!server.got.isEmpty(), "snapshot posted");
    if (!server.got.isEmpty()) {
        const QList<QJsonObject> ev = events(server.got.first());
        CHECK(ev.size() == 1 && ev.first().value(QStringLiteral("ev")).toString() == QLatin1String("snapshot")
                  && ev.first().value(QStringLiteral("msg")).toString() == QLatin1String("DIAG SNAPSHOT"),
              "snapshot is its own first batch");
    }
    CHECK(up.lastSentAt().isValid(), "lastSentAt set");

    // Ротация структурного журнала: отправленный большой файл уезжает в *.1 и удаляется.
    {
        QFile f(TribeJournal::structuredPath());
        CHECK(f.open(QIODevice::WriteOnly | QIODevice::Append), "open structured journal");
        const QByteArray line = "{\"t\":\"2026-09-24T10:00:00.000Z\",\"src\":\"app\",\"ev\":\"pad\",\"msg\":\""
                                + QByteArray(1000, 'x') + "\"}\n";
        while (f.size() <= journal::kStructRotateBytes)
            f.write(line);
    }
    server.got.clear();
    flushAndWait(up, QStringLiteral("timer"));
    CHECK(QFile::exists(TribeJournal::structuredRotatedPath()), "big structured journal rotated to *.1");
    CHECK(server.got.size() == journal::kMaxBatchesPerFlush, "flush capped at kMaxBatchesPerFlush batches");
    for (int i = 0; i < 40 && up.pendingBytes() > 0; ++i)
        flushAndWait(up, QStringLiteral("timer"));
    flushAndWait(up, QStringLiteral("timer")); // maintain() удаляет отправленный *.1
    CHECK(!QFile::exists(TribeJournal::structuredRotatedPath()), "fully sent *.1 removed");

    // Выключили — события не пишутся, досылка не идёт.
    TribeJournal::setActive(false, false);
    const qint64 before = QFileInfo(TribeJournal::structuredPath()).size();
    TribeJournal::append(QStringLiteral("after_off"));
    CHECK(QFileInfo(TribeJournal::structuredPath()).size() == before, "no writes after off");
    server.got.clear();
    up.flush(QStringLiteral("timer"));
    CHECK(!up.sending() && server.got.isEmpty(), "no upload while off");

    // ── v2: очередь досылок, событие journal_upload, обрыв застрявшего запроса ──
    TribeJournal::setActive(true, false);
    {
        int finished = 0, idle = 0;
        auto c1 = QObject::connect(&up, &TribeJournalUploader::flushFinished, [&](bool) { ++finished; });
        auto c2 = QObject::connect(&up, &TribeJournalUploader::idle, [&]() { ++idle; });
        TribeJournal::append(QStringLiteral("ring"), {{QStringLiteral("msg"), QStringLiteral("q1")}});
        server.got.clear();
        QEventLoop loop;
        QObject::connect(&up, &TribeJournalUploader::idle, &loop, &QEventLoop::quit);
        QTimer::singleShot(5000, &loop, &QEventLoop::quit);
        up.flush(QStringLiteral("first"));
        up.flush(QStringLiteral("second")); // во время первой — в очередь
        loop.exec();
        CHECK(finished == 2, "queued flush runs after the first one");
        CHECK(idle == 1, "idle fires once, only when the queue is empty");
        QObject::disconnect(c1);
        QObject::disconnect(c2);
    }
    {
        // Результат каждой отправки — событием в журнале (уходит следующей пачкой).
        server.got.clear();
        flushAndWait(up, QStringLiteral("timer"));
        bool sawUpload = false;
        for (const Received &r : server.got)
            for (const QJsonObject &o : events(r))
                if (o.value(QStringLiteral("ev")).toString() == QLatin1String("journal_upload")) {
                    sawUpload = o.value(QStringLiteral("code")).toInt() == 201
                                && o.contains(QStringLiteral("ms")) && o.contains(QStringLiteral("bytes"));
                }
        CHECK(sawUpload, "journal_upload event with code/ms/bytes");
    }
    {
        // Запрос, застрявший (например, в заморозке iOS), обрывается при выходе на экран.
        TribeJournal::append(QStringLiteral("ring"), {{QStringLiteral("msg"), QStringLiteral("stuck")}});
        server.codes = {-1};
        server.got.clear();
        up.flush(QStringLiteral("background"));
        CHECK(up.sending(), "request in flight on a hung server");
        QElapsedTimer waitClock;
        waitClock.start();
        while (server.got.isEmpty() && waitClock.elapsed() < 3000)
            QCoreApplication::processEvents(QEventLoop::AllEvents, 50); // запрос дошёл и завис
        CHECK(!up.kickIfStale(60000), "fresh request is not kicked");
        QEventLoop loop;
        bool ok = true;
        auto c = QObject::connect(&up, &TribeJournalUploader::flushFinished, &loop, [&](bool r) {
            ok = r;
            loop.quit();
        });
        QTimer::singleShot(3000, &loop, &QEventLoop::quit);
        CHECK(up.kickIfStale(0), "stale request is kicked");
        loop.exec();
        QObject::disconnect(c);
        CHECK(!ok && !up.sending(), "kicked flush finishes as failed and frees the queue");
        server.got.clear();
        CHECK(flushAndWait(up, QStringLiteral("foreground")), "next flush goes through");
        bool resent = false;
        for (const Received &r : server.got)
            for (const QJsonObject &o : events(r))
                resent |= o.value(QStringLiteral("msg")).toString() == QLatin1String("stuck");
        CHECK(resent, "events of the kicked batch are resent");
    }

    {
        // Разбор журнала 25.09: досылка не прошла, пользователь выключил и снова включил журнал —
        // неотправленные строки текстового лога не выбрасываются (раньше смещение уходило в конец).
        appendLine(g_qtLogPath, "[2026-09-25 02:05:00.000Z] [INFO] AmneziaVPN  : unsent night line\n");
        server.codes = {503};
        server.got.clear();
        flushAndWait(up, QStringLiteral("timer"));
        TribeJournal::setActive(false, false);
        TribeJournal::setActive(true, false);
        server.got.clear();
        CHECK(flushAndWait(up, QStringLiteral("enabled")), "flush after off->on goes through");
        bool night = false;
        for (const Received &r : server.got)
            for (const QJsonObject &o : events(r))
                night |= o.value(QStringLiteral("msg")).toString().contains(QLatin1String("unsent night line"));
        CHECK(night, "unsent text-log line survives journal off->on");
    }

    QSettings().clear();
    std::printf("journal_upload_check: %d/%d passed\n", g_total - g_failed, g_total);
    return g_failed == 0 ? 0 : 1;
}
