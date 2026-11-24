// AVPN (desktop test rig): the test command channel (DevControl.h + DevControlApp.h) over a real QLocalServer against
// fakes: the engine, the Scanner and PageController (dev_control_fakes.h) and the app's QML shape
// (dev_control_fake.qml, offscreen + software scene graph). Every command; bad JSON, unknown command, an oversized
// line, a full queue, too many clients, two clients at once, a client leaving in the middle of a wait; the socket's
// and the directory's modes; stale / live / foreign files at the socket path; the driver script (--local) and a
// one-shot nc. Run by build_dev_control.sh.
//   dev_control_check <dev_control_fake.qml> <client/tests/tools/tribe-mac.sh>
#include "DevControl.h"
#include "DevControlApp.h"
#include "dev_control_fakes.h"

#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
#include <QImage>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLocalSocket>
#include <QProcess>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickWindow>
#include <QTemporaryDir>
#include <QTimer>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

using namespace avpn::devctl;

static int g_fail = 0;
static int g_pass = 0;
#define CHECK(cond, msg)                                                                                               \
    do {                                                                                                               \
        if (cond) {                                                                                                    \
            ++g_pass;                                                                                                  \
        } else {                                                                                                       \
            ++g_fail;                                                                                                  \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);                                         \
        }                                                                                                              \
    } while (0)

static void pump(int ms)
{
    QElapsedTimer t;
    t.start();
    while (t.elapsed() < ms)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
}

struct Client {
    QLocalSocket s;
    QByteArray buf;
    bool open(const QString &path)
    {
        s.connectToServer(path);
        if (!s.waitForConnected(1000))
            return false;
        pump(20);
        return true;
    }
    void send(const QByteArray &bytes)
    {
        s.write(bytes);
        s.flush();
    }
    // the next reply line (empty object on timeout)
    QJsonObject reply(int ms = 3000)
    {
        QElapsedTimer t;
        t.start();
        while (!buf.contains('\n') && t.elapsed() < ms) {
            QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
            buf += s.readAll();
        }
        const qsizetype nl = buf.indexOf('\n');
        if (nl < 0)
            return {};
        const QByteArray line = buf.left(nl);
        buf.remove(0, nl + 1);
        return QJsonDocument::fromJson(line).object();
    }
    QJsonObject ask(const QByteArray &json, int ms = 3000)
    {
        send(json + '\n');
        return reply(ms);
    }
    QJsonObject cmd(const char *name, const QJsonObject &args = {}, int ms = 3000)
    {
        QJsonObject o{{QStringLiteral("id"), QString::fromLatin1(name)}, {QStringLiteral("cmd"), QString::fromLatin1(name)}};
        if (!args.isEmpty())
            o.insert(QStringLiteral("args"), args);
        return ask(QJsonDocument(o).toJson(QJsonDocument::Compact), ms);
    }
    bool closedWithin(int ms)
    {
        QElapsedTimer t;
        t.start();
        while (s.state() != QLocalSocket::UnconnectedState && t.elapsed() < ms)
            QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        return s.state() == QLocalSocket::UnconnectedState;
    }
};

static bool ok(const QJsonObject &r) { return r.value(QStringLiteral("ok")).toBool(); }
static QJsonObject res(const QJsonObject &r) { return r.value(QStringLiteral("result")).toObject(); }
static QString errOf(const QJsonObject &r) { return r.value(QStringLiteral("error")).toString(); }

static int modeOf(const QString &path)
{
    struct stat st {};
    if (::lstat(QFile::encodeName(path).constData(), &st) != 0)
        return -1;
    return int(st.st_mode & 0777);
}

// A socket file whose process is gone: bound, then the descriptor closed without unlinking.
static bool makeStaleSocket(const QString &path)
{
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un a {};
    a.sun_family = AF_UNIX;
    const QByteArray p = QFile::encodeName(path);
    std::memcpy(a.sun_path, p.constData(), size_t(p.size()) + 1);
    const bool bound = ::bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) == 0;
    ::close(fd);
    return bound;
}

static int runProcess(const QString &program, const QStringList &args, QByteArray *out, int ms = 15000)
{
    QProcess p;
    p.start(program, args);
    QElapsedTimer t;
    t.start();
    while (p.state() != QProcess::NotRunning && t.elapsed() < ms)
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
    if (p.state() != QProcess::NotRunning) {
        p.kill();
        p.waitForFinished(1000);
        return -2;
    }
    if (out)
        *out = p.readAllStandardOutput();
    return p.exitStatus() == QProcess::NormalExit ? p.exitCode() : -1;
}

int main(int argc, char **argv)
{
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QQuickWindow::setGraphicsApi(QSGRendererInterface::Software);
    QGuiApplication qapp(argc, argv);
    if (argc < 3) {
        std::fprintf(stderr, "usage: dev_control_check <fake.qml> <tribe-mac.sh>\n");
        return 2;
    }
    const QString qmlPath = QString::fromLocal8Bit(argv[1]);
    const QString driver = QString::fromLocal8Bit(argv[2]);

    // ---- pure helpers ----------------------------------------------------------------------------------------
    CHECK(App::orbFace("disconnected", false, false, false, false, false, false) == "off", "face off");
    CHECK(App::orbFace("connecting", true, false, false, false, false, false) == "connecting", "face connecting");
    CHECK(App::orbFace("disconnected", true, true, false, false, false, false) == "off",
          "a foreign transition with intent off: the orb shows Connect");
    CHECK(App::orbFace("connected", true, true, true, false, false, false) == "disconnecting", "own stop");
    CHECK(App::orbFace("disconnected", false, false, false, true, false, false) == "waiting_network", "waiting");
    CHECK(App::orbFace("connected", false, false, false, false, false, true) == "verifying", "verifying");
    CHECK(App::orbFace("connected", true, false, false, false, true, false) == "checking", "adopting");
    CHECK(App::orbFace("connected", false, false, false, false, false, false) == "connected", "connected");
    {
        const QString r = App::redact("fail 203.0.113.7:443 and 2001:db8::1 key ABCDEFGHIJKLMNOPQRSTUVWX12345678 "
                                      "id 123e4567-e89b-12d3-a456-426614174000 at 12:30:45");
        CHECK(!r.contains("203.0.113.7") && !r.contains("2001:db8") && !r.contains("ABCDEFGHIJKL")
                  && !r.contains("123e4567") && r.contains("12:30:45"),
              qPrintable("redact: " + r));
    }
    CHECK(App::publicId("15") == "15" && App::publicId("9:xray") == "9:xray", "own ids stay");
    CHECK(App::publicId("up:3f9c2a7b1d4e8f60").startsWith("ref:") && !App::publicId("up:3f9c2a7b1d4e8f60").contains("3f9c"),
          "provider ids are hashed");
    {
        const Request a = parseRequest("{\"id\":7,\"cmd\":\"state\"}");
        CHECK(a.error.isEmpty() && a.cmd == "state" && a.id.toInt() == 7 && a.args.isEmpty(), "parse ok");
        CHECK(parseRequest("{oops").error == "bad_json", "bad json");
        CHECK(parseRequest("[1,2]").error == "not_an_object", "not an object");
        CHECK(parseRequest("{\"cmd\":\"State!\"}").error == "bad_cmd", "bad cmd");
        CHECK(parseRequest("{\"cmd\":\"nav\",\"args\":[1]}").error == "bad_args", "bad args");
        CHECK(parseRequest("{\"cmd\":\"state\"}").id.isNull(), "absent id = null");
    }

    // ---- the world ---------------------------------------------------------------------------------------------
    QTemporaryDir tmp(QDir::tempPath() + QStringLiteral("/dc-XXXXXX"));
    const QString data = tmp.path() + QStringLiteral("/d");
    FakeEngine eng;
    FakeScanner scn;
    FakePageController pc;
    eng.m_currentNode = QVariantMap{{"nodeId", "up:3f9c2a7b1d4e8f60"}, {"name", "Нидерланды 1"},
                                    {"countryCode", "NL"}, {"proto", "xray"}, {"endpoint", "198.51.100.23:8443"},
                                    {"ip", "198.51.100.23"}, {"pinned", false}, {"auto", true}, {"connected", false},
                                    {"upstream", true}, {"choiceNodeId", ""}};
    eng.m_nodePool = QVariantList{QVariantMap{{"nodeId", "15"}, {"proto", "awg"}},
                                  QVariantMap{{"nodeId", "up:3f9c2a7b1d4e8f60"}, {"proto", "xray"}},
                                  QVariantMap{{"nodeId", "20"}, {"proto", "wireguard"}},
                                  QVariantMap{{"nodeId", "11:xray"}, {"proto", "xray"}}};
    eng.snapshot = QVariantMap{
        {"state", "disconnected"}, {"rxBytes", 10}, {"currentNodeId", "up:3f9c2a7b1d4e8f60"},
        {"pool", QVariantList{QVariantMap{{"nodeId", "15"}, {"endpoint", "203.0.113.9:585"}, {"ip", "203.0.113.9"},
                                          {"alive", true}}}},
        {"switchLog", QVariantList{"to 203.0.113.9"}},
        {"upstream", QVariantMap{{"state", "idle"}, {"node", "up:3f9c2a7b1d4e8f60"}, {"lease_token", "LEASEVALUE00000000000000000"}}},
        {"privateKey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1="}};
    scn.m_view = QJsonObject{
        {"phase", "idle"},
        {"rows", QJsonArray{QJsonObject{{"id", "up:3f9c2a7b1d4e8f60#full"}, {"label", "Нидерланды 1"}, {"cc", "NL"},
                                        {"transport", "xray"}, {"state", "works"}, {"speed", "fast"}, {"bars", 4},
                                        {"ms", 87}, {"flags", QJsonArray{"cache"}}},
                            QJsonObject{{"id", "15"}, {"label", "Эстония"}, {"cc", "EE"}, {"transport", "awg"},
                                        {"state", "failed"}, {"speed", "none"}, {"bars", 0}, {"ms", -1},
                                        {"flags", QJsonArray{"not_tappable"}}}}},
        {"verified", 1}, {"unverified", 0},
        {"slots", QJsonArray{QJsonObject{{"scope", "DE"}, {"works", 3}, {"ago_min", 4}}}},
        {"bar", QJsonObject{{"button", "retry"}, {"button_enabled", true},
                            {"scope_countries", QJsonArray{QJsonObject{{"cc", "DE"}, {"count", 12}},
                                                           QJsonObject{{"cc", "NL"}, {"count", 5}}}}}}};

    QQmlApplicationEngine qml;
    qml.rootContext()->setContextProperty(QStringLiteral("TribeEngine"), &eng);
    qml.rootContext()->setContextProperty(QStringLiteral("TribeScanner"), &scn);
    qml.rootContext()->setContextProperty(QStringLiteral("PageController"), &pc);
    qml.load(QUrl::fromLocalFile(qmlPath));
    CHECK(!qml.rootObjects().isEmpty(), "fake QML loaded");
    if (qml.rootObjects().isEmpty())
        return 1;
    pump(50);

    QList<QPair<QString, QJsonObject>> journal;
    QStringList logLines;
    bool quitCalled = false;
    AppEnv env;
    env.object = [&qml](const QString &name) { return qml.rootContext()->contextProperty(name).value<QObject *>(); };
    env.root = [&qml]() -> QObject * { return qml.rootObjects().value(0); };
    env.dataDir = data;
    env.version = QStringLiteral("5.1.999.1");
    env.commit = QStringLiteral("abc1234");
    env.journal = [&journal](const QString &ev, const QJsonObject &f) { journal.append({ev, f}); };
    env.journalActive = [] { return true; };
    env.log = [&logLines](const QString &l) { logLines << l; };
    env.quit = [&quitCalled] { quitCalled = true; };
    int present = 0;            // AvpnEngineQml::notePersonPresent stand-in
    qsizetype presentAt = -1;   // how many engine calls had been made when the person was noted
    env.personPresent = [&present, &presentAt, &eng] { ++present; presentAt = eng.calls.size(); };
    App app(env);
    Server server(data, &app);
    app.setServer(&server);

    // ---- socket setup ------------------------------------------------------------------------------------------
    QString why;
    CHECK(server.start(&why), qPrintable("start: " + why));
    const QString sock = server.path();
    CHECK(sock == data + "/dev/control.sock", "socket in the data directory");
    CHECK(modeOf(sock) == 0600, qPrintable(QStringLiteral("socket mode %1").arg(modeOf(sock), 0, 8)));
    CHECK(modeOf(data + "/dev") == 0700, qPrintable(QStringLiteral("dir mode %1").arg(modeOf(data + "/dev"), 0, 8)));
    {
        Server second(data, &app);
        QString w;
        CHECK(!second.start(&w) && w == "in_use", qPrintable("a live socket is never taken over: " + w));
        CHECK(QFileInfo::exists(sock), "the live socket stays");
    }
    {
        const QString d2 = tmp.path() + QStringLiteral("/s");
        QDir().mkpath(d2 + "/dev");
        CHECK(makeStaleSocket(d2 + "/dev/control.sock"), "stale socket made");
        Server s2(d2, &app);
        QString w;
        CHECK(s2.start(&w), qPrintable("a stale socket is replaced: " + w));
        Client c;
        CHECK(c.open(s2.path()) && ok(c.cmd("help")), "the replacing server answers");
    }
    {
        const QString d3 = tmp.path() + QStringLiteral("/f");
        QDir().mkpath(d3 + "/dev");
        QFile f(d3 + "/dev/control.sock");
        CHECK(f.open(QIODevice::WriteOnly), "regular file made");
        f.write("not a socket");
        f.close();
        Server s3(d3, &app);
        QString w;
        CHECK(!s3.start(&w) && w == "path_not_a_socket" && QFileInfo(f.fileName()).size() == 12,
              qPrintable("a regular file is never deleted: " + w));
    }
    {
        const QString d4 = tmp.path() + QStringLiteral("/") + QString(90, QLatin1Char('x'));
        Server s4(d4, &app);
        QString w;
        CHECK(!s4.start(&w) && w == "path_too_long", qPrintable("a path longer than sun_path is refused: " + w));
    }
    {
        const QString d5 = tmp.path() + QStringLiteral("/l");
        QDir().mkpath(tmp.path() + QStringLiteral("/target"));
        QDir().mkpath(d5);
        QFile::link(tmp.path() + QStringLiteral("/target"), d5 + QStringLiteral("/dev"));
        Server s5(d5, &app);
        QString w;
        CHECK(!s5.start(&w) && w == "dir_not_ours", qPrintable("a symlinked channel directory is refused: " + w));
    }

    Client c;
    CHECK(c.open(sock), "connect");

    // ---- protocol ----------------------------------------------------------------------------------------------
    {
        QJsonObject r = c.ask("{not json");
        CHECK(!ok(r) && errOf(r) == "bad_json", "bad json -> error");
        r = c.ask("{\"id\":\"u1\",\"cmd\":\"fly\"}");
        CHECK(!ok(r) && errOf(r).startsWith("unknown_command") && r.value("id").toString() == "u1",
              "unknown command -> error with the id");
        r = c.ask("{\"id\":42,\"cmd\":\"help\"}");
        CHECK(ok(r) && r.value("id").toInt() == 42 && res(r).value("commands").toArray().size() == 21, "help");
        c.send("\n\r\n");
        r = c.ask("{\"cmd\":\"help\"}");
        CHECK(ok(r) && r.value("id").isNull(), "empty lines are skipped; absent id -> null");
        // two requests in one write, answered in order
        c.send("{\"id\":1,\"cmd\":\"help\"}\n{\"id\":2,\"cmd\":\"state\"}\n");
        const QJsonObject r1 = c.reply(), r2 = c.reply();
        CHECK(r1.value("id").toInt() == 1 && r2.value("id").toInt() == 2, "pipelined requests in order");
    }

    // ---- state: a whitelist -------------------------------------------------------------------------------------
    {
        const QJsonObject r = c.cmd("state");
        const QByteArray raw = QJsonDocument(r).toJson(QJsonDocument::Compact);
        CHECK(ok(r), "state ok");
        const QJsonObject s = res(r);
        CHECK(s.value("app").toObject().value("commit").toString() == "abc1234", "state: commit");
        CHECK(s.value("orb").toString() == "off" && s.value("intent").toString() == "off", "state: orb off, intent off");
        CHECK(s.value("engine").toObject().value("network_kind").toString() == "wifi", "state: network kind");
        CHECK(s.value("node").toObject().value("country").toString() == "NL", "state: node country");
        CHECK(s.value("snapshot").toObject().value("pool_size").toInt() == 1, "state: pool size only");
        CHECK(s.value("scanner").toObject().value("rows").toInt() == 2, "state: scanner rows count");
        CHECK(s.value("ui").toObject().value("page").toString() == "PageConnectTribe", "state: page");
        for (const char *secret : {"198.51.100.23", "203.0.113.9", "3f9c2a7b1d4e8f60", "LEASEVALUE", "AAAAAAAAAAAA",
                                   "privateKey", "endpoint", "lease_token"})
            CHECK(!raw.contains(secret), qPrintable(QStringLiteral("state leaks %1").arg(QString::fromLatin1(secret))));
    }

    // ---- connect / stop: the orb -------------------------------------------------------------------------------
    {
        eng.calls.clear();
        const int present0 = present;
        QJsonObject r = c.cmd("connect");
        CHECK(ok(r) && res(r).value("tapped").toBool() && eng.calls == QStringList{"orbTap"},
              qPrintable("connect taps the orb once: " + eng.calls.join(',')));
        CHECK(present == present0 + 1 && presentAt == 0, "connect: the person is noted once, before the orb's call");
        CHECK(res(r).value("after").toObject().value("face").toString() == "connecting", "connect: connecting after");
        eng.calls.clear();
        r = c.cmd("connect");
        CHECK(ok(r) && !res(r).value("tapped").toBool() && res(r).value("face").toString() == "connecting"
                  && eng.calls.isEmpty(),
              "connect while connecting: nothing tapped (a tap would stop)");
        eng.calls.clear();
        r = c.cmd("stop");
        CHECK(ok(r) && res(r).value("tapped").toBool() && eng.calls == QStringList{"orbTap"}, "stop taps the orb");
        eng.set("disconnected", false);
        eng.calls.clear();
        r = c.cmd("stop");
        CHECK(ok(r) && !res(r).value("tapped").toBool() && eng.calls.isEmpty(), "stop while off: nothing tapped");
        eng.m_whitelistMode = true;
        eng.calls.clear();
        c.cmd("connect");
        CHECK(eng.calls == (QStringList{"setWhitelistAcked:0", "orbTap"}), qPrintable("the orb handler's whitelist step: "
                                                                                      + eng.calls.join(',')));
        eng.m_whitelistMode = false;
        eng.set("disconnected", false);
        CHECK(journal.size() >= 2 && journal.last().first == "dev_cmd", "actions are journaled as dev_cmd");
        CHECK(!logLines.isEmpty() && logLines.last().startsWith("[avpn devctl] cmd="), "actions are logged");
    }

    // ---- nav ---------------------------------------------------------------------------------------------------
    {
        QJsonObject r = c.cmd("nav", {{"page", "settings"}});
        CHECK(ok(r) && res(r).value("page").toString() == "PageAccountTribe", "nav settings");
        r = c.cmd("nav", {{"page", "servers"}});
        CHECK(ok(r) && res(r).value("page").toString() == "PageServersTribe", "nav servers (home, then the card)");
        r = c.cmd("nav", {{"page", "scanner"}});
        CHECK(ok(r) && res(r).value("page").toString() == "PageScannerTribe" && scn.calls.contains("show"),
              "nav scanner from servers");
        r = c.cmd("nav", {{"page", "connect"}});
        CHECK(ok(r) && res(r).value("page").toString() == "PageConnectTribe", "nav connect");
        r = c.cmd("nav", {{"page", "nowhere"}});
        CHECK(!ok(r) && errOf(r).startsWith("unknown_page"), "nav unknown page");
        QObject *ps = qml.rootObjects().value(0)->findChild<QObject *>("pageStart");
        ps->setProperty("onboardingActive", true);
        r = c.cmd("nav", {{"page", "settings"}});
        CHECK(!ok(r) && errOf(r).startsWith("navigation_hidden"), "nav refused while the bottom bar is hidden");
        ps->setProperty("onboardingActive", false);
        eng.m_scannerEnabled = false;
        r = c.cmd("nav", {{"page", "scanner"}});
        CHECK(!ok(r) && errOf(r).startsWith("scanner_off"), "nav scanner with the switch off: no button, refused");
        eng.m_scannerEnabled = true;
        // doctor_legacy: the home has no «Сканер» button - the Servers page's one is taken
        eng.m_doctorLegacy = true;
        c.cmd("nav", {{"page", "connect"}});
        r = c.cmd("nav", {{"page", "scanner"}});
        QObject *cur = qml.rootObjects().value(0)->findChild<QObject *>("tabBarStackView")->property("currentItem").value<QObject *>();
        CHECK(ok(r) && res(r).value("page").toString() == "PageScannerTribe" && cur
                  && cur->property("origin").toString() == "servers",
              "nav scanner with doctor_legacy: through the Servers page's button");
        eng.m_doctorLegacy = false;
        r = c.cmd("nav", {{"page", "connect"}});
        r = c.cmd("nav", {{"page", "scanner"}});
        cur = qml.rootObjects().value(0)->findChild<QObject *>("tabBarStackView")->property("currentItem").value<QObject *>();
        CHECK(ok(r) && cur && cur->property("origin").toString() == "home", "nav scanner from home: the home button");
        c.cmd("nav", {{"page", "connect"}});
    }

    // ---- servers / choose / auto / mode --------------------------------------------------------------------------
    QString nlRef;
    {
        QJsonObject r = c.cmd("servers");
        const QJsonArray rows = res(r).value("rows").toArray();
        CHECK(ok(r) && rows.size() == 4 && res(r).value("opened").toBool(), "servers: four rows, page opened");
        const QByteArray raw = QJsonDocument(r).toJson(QJsonDocument::Compact);
        CHECK(!raw.contains("3f9c2a7b1d4e8f60"), "servers: no provider id");
        CHECK(rows.at(0).toObject().value("node").toString() == "15" && rows.at(0).toObject().value("picks").toString() == "awg",
              "servers: own id and the transport the row picks");
        CHECK(rows.at(0).toObject().value("kinds").toArray().size() == 2, "servers: kinds");
        nlRef = rows.at(1).toObject().value("ref").toString();
        CHECK(nlRef.size() == 8 && rows.at(1).toObject().value("provider").toBool(), "servers: provider row ref");

        eng.calls.clear();
        r = c.cmd("choose", {{"id", nlRef}});
        CHECK(ok(r) && res(r).value("tapped").toString() == "picked"
                  && eng.calls == QStringList{"pinAndReconnect:up:3f9c2a7b1d4e8f60"},
              qPrintable("choose by ref -> the row's pickNode -> pinAndReconnect: " + eng.calls.join(',')));
        CHECK(res(r).value("after").toObject().value("page").toString() == "PageConnectTribe",
              "choose: the host goes home first, as the row tap does");
        eng.calls.clear();
        r = c.cmd("choose", {{"row", 1}});
        CHECK(ok(r) && eng.calls == QStringList{"pinAndReconnect:15"}, "choose by row");
        eng.calls.clear();
        pc.calls.clear();
        r = c.cmd("choose", {{"id", "20"}});
        CHECK(ok(r) && res(r).value("tapped").toString() == "disabled" && eng.calls.isEmpty()
                  && pc.calls == QStringList{"toast:недоступно в этой версии"},
              "choose a grey row: the row's toast, no engine call");
        eng.calls.clear();
        r = c.cmd("choose", {{"name", "Финляндия"}});
        CHECK(ok(r) && res(r).value("tapped").toString() == "mode_auto_then_pick"
                  && eng.calls == (QStringList{"setTransportMode:auto", "pinAndReconnect:11:xray"}),
              qPrintable("choose a mode-only row: mode Auto, then the server: " + eng.calls.join(',')));
        eng.calls.clear();
        r = c.cmd("choose", {{"id", "15"}, {"kind", "xray"}});
        CHECK(!ok(r) && errOf(r).startsWith("kind_not_picked") && eng.calls.isEmpty(),
              "choose with a transport the row does not pick: refused, nothing tapped");
        r = c.cmd("choose", {{"id", "nope"}});
        CHECK(!ok(r) && errOf(r).startsWith("no_such_row"), "choose unknown row");

        eng.calls.clear();
        r = c.cmd("auto");
        CHECK(ok(r) && res(r).value("tapped").toString() == "already_auto" && eng.calls.isEmpty(),
              "auto while Auto: the card does nothing");
        eng.m_currentNode.insert("pinned", true);
        emit eng.changed();
        r = c.cmd("auto");
        CHECK(ok(r) && eng.calls == QStringList{"selectAuto"}, "auto -> pickAuto -> the host's selectAuto");
        eng.m_currentNode.insert("pinned", false);
        emit eng.changed();

        eng.calls.clear();
        r = c.cmd("mode", {{"value", "xray"}});
        CHECK(ok(r) && res(r).value("tapped").toString() == "requested" && eng.calls == QStringList{"setTransportMode:xray"}
                  && res(r).value("mode_after").toString() == "xray",
              "mode xray -> the segment -> setTransportMode");
        eng.calls.clear();
        r = c.cmd("mode", {{"value", "xray"}});
        CHECK(ok(r) && res(r).value("tapped").toString() == "selected" && eng.calls.isEmpty(), "mode: the selected one");
        r = c.cmd("mode", {{"value", "wireguard"}});
        CHECK(!ok(r) && errOf(r).startsWith("bad_value"), "mode: bad value");
        c.cmd("mode", {{"value", "auto"}});
    }

    // ---- Scanner -----------------------------------------------------------------------------------------------
    QString rowRef;
    {
        scn.close();
        QJsonObject r = c.cmd("scan.select", {{"scope", "DE"}});
        CHECK(!ok(r) && errOf(r).startsWith("scanner_closed"), "scan.select needs the open screen");
        scn.calls.clear();
        r = c.cmd("scan.open");
        CHECK(ok(r) && res(r).value("page").toString() == "PageScannerTribe" && res(r).value("screen_open").toBool()
                  && scn.calls.contains("show"),
              "scan.open: the page opens and shows the Scanner");
        CHECK(res(r).value("pane").toString() == "choose" && res(r).value("selected").toString().isEmpty(),
              "scan.open: the page opens on its choice, «Все страны» selected");
        // the scope row: the selection only - nothing reaches the Scanner until the button
        scn.calls.clear();
        r = c.cmd("scan.select", {{"scope", "DE"}});
        CHECK(ok(r) && res(r).value("fresh").toBool() && res(r).value("selected").toString() == "DE"
                  && res(r).value("action").toString() == "scan" && scn.calls.isEmpty(),
              qPrintable("scan.select: the page's select(scope), no Scanner call: " + scn.calls.join(',')));
        r = c.cmd("scan.select", {{"scope", "ZZ"}});
        CHECK(!ok(r) && errOf(r).startsWith("unknown_scope"), "scan.select unknown scope");
        r = c.cmd("scan.select", {{"scope", "whitelist"}});
        CHECK(!ok(r) && errOf(r).startsWith("unknown_scope"), "scan.select whitelist without white lists in the pool");
        // the one button on the choice: «Сканировать» the selected scope -> the page's scanSelected
        scn.calls.clear();
        r = c.cmd("scan.start");
        CHECK(ok(r) && res(r).value("pressed").toString() == "scan" && res(r).value("from").toString() == "choice"
                  && scn.calls == (QStringList{"chooseCountry:DE", "retry"}) && res(r).value("pane").toString() == "result"
                  && res(r).value("phase").toString() == "preparing",
              qPrintable("scan.start on the choice -> scan the selected scope: " + scn.calls.join(',')));
        r = c.cmd("scan.select", {{"scope", "NL"}});
        CHECK(!ok(r) && errOf(r).startsWith("not_choosing"), "scan.select on the result: refused");
        scn.setButton("stop");
        r = c.cmd("scan.start");
        CHECK(!ok(r) && errOf(r).startsWith("scanning"), "scan.start while «Остановить»: refused");
        scn.calls.clear();
        r = c.cmd("scan.stop");
        CHECK(ok(r) && res(r).value("stopped").toBool() && scn.calls == QStringList{"stop"}, "scan.stop -> the button's stop");
        scn.setButton("retry");
        scn.calls.clear();
        r = c.cmd("scan.stop");
        CHECK(ok(r) && !res(r).value("stopped").toBool() && scn.calls.isEmpty(), "scan.stop when the button does not say it");
        scn.calls.clear();
        r = c.cmd("scan.start");
        CHECK(ok(r) && res(r).value("pressed").toString() == "retry" && scn.calls == QStringList{"retry"},
              "scan.start on the result -> «Сканировать снова»");
        scn.setButton("retry", false);
        r = c.cmd("scan.start");
        CHECK(!ok(r) && errOf(r).startsWith("button_disabled"), "scan.start with the button disabled: refused");
        scn.setButton("connect_and_scan");
        scn.calls.clear();
        r = c.cmd("scan.start");
        CHECK(ok(r) && res(r).value("pressed").toString() == "connect" && scn.calls == QStringList{"connectAndScan"},
              "scan.start on the result as the bar says: connectAndScan");
        // back: the result -> the choice (the page stays)
        r = c.cmd("scan.back");
        CHECK(ok(r) && res(r).value("page").toString() == "PageScannerTribe", "scan.back from the result: the choice");
        scn.calls.clear();
        r = c.cmd("scan.start");
        CHECK(ok(r) && res(r).value("pressed").toString() == "connect" && scn.calls == (QStringList{"chooseCountry:DE", "connectAndScan"}),
              qPrintable("scan.start on the choice, VPN off: connect and scan the selected scope: " + scn.calls.join(',')));
        c.cmd("scan.back");
        // during the pause: a scope with a fresh result offers «Показать результат», one without it a disabled scan
        scn.setButton("retry_in_s", false);
        scn.calls.clear();
        r = c.cmd("scan.start");
        CHECK(ok(r) && res(r).value("pressed").toString() == "show" && scn.calls == QStringList{"showSlot:DE"},
              qPrintable("scan.start during the pause: show the fresh result: " + scn.calls.join(',')));
        c.cmd("scan.back");
        c.cmd("scan.select", {{"scope", "NL"}});
        scn.calls.clear();
        r = c.cmd("scan.start");
        CHECK(!ok(r) && errOf(r).startsWith("button_disabled: scan") && scn.calls.isEmpty(),
              "scan.start during the pause without a fresh result: the disabled «Сканировать через N с»");
        scn.setButton("retry");
        c.cmd("scan.select", {{"scope", "DE"}});
        c.cmd("scan.start");
        scn.setPhase("done");
        scn.m_view.insert("available", 1);
        scn.m_view.insert("partial", true);
        emit scn.viewChanged();

        r = c.cmd("scan.rows");
        const QJsonArray rows = res(r).value("rows").toArray();
        const QByteArray raw = QJsonDocument(r).toJson(QJsonDocument::Compact);
        CHECK(ok(r) && rows.size() == 2 && rows.at(0).toObject().value("latency_ms").toInt() == 87
                  && rows.at(0).toObject().value("status").toString() == "works"
                  && rows.at(0).toObject().value("kind").toString() == "xray",
              "scan.rows: name, kind, status, latency");
        CHECK(!raw.contains("3f9c2a7b1d4e8f60"), "scan.rows: no provider id");
        CHECK(res(r).value("available").toInt() == 1 && res(r).value("partial").toBool()
                  && res(r).value("pane").toString() == "result" && res(r).value("scopes").toArray().size() == 2
                  && res(r).value("slots").toArray().size() == 1,
              "scan.rows: the rings' count, the stopped scan's mark, the pane, the scopes and their fresh results");
        rowRef = rows.at(0).toObject().value("ref").toString();
        scn.calls.clear();
        r = c.cmd("scan.connect", {{"row", 1}, {"ref", rowRef}});
        CHECK(ok(r) && scn.calls == QStringList{"tapRow:up:3f9c2a7b1d4e8f60#full"}, "scan.connect -> tapRow(id)");
        scn.calls.clear();
        r = c.cmd("scan.connect", {{"row", 2}});
        CHECK(!ok(r) && errOf(r) == "not_tappable" && scn.calls.isEmpty(), "scan.connect: a not tappable row");
        r = c.cmd("scan.connect", {{"row", 2}, {"ref", rowRef}});
        CHECK(!ok(r) && errOf(r).startsWith("row_changed"), "scan.connect: the row changed under the ref");

        c.cmd("scan.back"); // the result -> the choice
        pc.calls.clear();
        r = c.cmd("scan.back");
        CHECK(ok(r) && pc.calls == QStringList{QStringLiteral("keyPressEvent:%1").arg(int(Qt::Key_Escape))}
                  && res(r).value("page").toString() == "PageServersTribe",
              qPrintable("scan.back = Escape -> the page's systemBack (back to the Servers page it was opened from): "
                         + pc.calls.join(',') + " " + res(r).value("page").toString()));
        r = c.cmd("scan.back");
        CHECK(!ok(r) && errOf(r).startsWith("not_on_scanner"), "scan.back off the Scanner: refused");
    }

    // ---- window.show, shot, mark ---------------------------------------------------------------------------------
    {
        auto *w = qobject_cast<QQuickWindow *>(qml.rootObjects().value(0));
        w->hide();
        pump(20);
        QJsonObject r = c.cmd("window.show");
        CHECK(ok(r) && res(r).value("visible").toBool() && w->isVisible(), "window.show -> raiseMainWindow -> shown");
        pump(50);
        r = c.cmd("shot", {{"path", "r1/connect"}}, 8000);
        const QString path = res(r).value("path").toString();
        CHECK(ok(r) && path == data + "/dev/shots/r1/connect.png" && QFileInfo(path).size() > 0
                  && res(r).value("width").toInt() == 360,
              qPrintable("shot: a PNG of the window in the data dir: " + errOf(r) + " " + path));
        CHECK(!QImage(path).isNull(), "shot: a readable image");
        r = c.cmd("shot", {{"path", "../escape"}});
        CHECK(!ok(r) && errOf(r).startsWith("bad_path"), "shot: no path outside dev/shots");
        r = c.cmd("shot", {{"path", "/etc/x"}});
        CHECK(!ok(r) && errOf(r).startsWith("bad_path"), "shot: no absolute path");
        w->hide();
        pump(20);
        r = c.cmd("shot", {{"path", "hidden"}}, 8000);
        std::printf("note: shot of a hidden window: ok=%d visible=%d error=%s\n", int(ok(r)),
                    int(res(r).value("visible").toBool()), qPrintable(errOf(r)));
        w->show();
        pump(20);

        journal.clear();
        r = c.cmd("mark", {{"text", "R3 step 2\nafter wake 203.0.113.5"}});
        CHECK(ok(r) && journal.size() == 1 && journal.first().first == "dev_mark"
                  && journal.first().second.value("text").toString() == "R3 step 2 after wake <ip>"
                  && logLines.last() == "[avpn devctl] mark R3 step 2 after wake <ip>",
              qPrintable("mark: one log line and one journal event, masked: " + logLines.last()));
        r = c.cmd("mark");
        CHECK(!ok(r) && errOf(r).startsWith("bad_text"), "mark without text");
    }

    // ---- wait: signals, two clients, a client leaving ---------------------------------------------------------------
    {
        eng.set("disconnected", false);
        QJsonObject r = c.cmd("wait", {{"for", "off"}, {"timeout_ms", 1000}});
        CHECK(ok(r) && res(r).value("after_ms").toInt() < 500, "wait for a state already there: at once");
        r = c.cmd("wait", {{"for", "connected"}, {"timeout_ms", 300}}, 2000);
        CHECK(!ok(r) && errOf(r).startsWith("timeout"), "wait timeout -> ok:false timeout");
        r = c.cmd("wait", {{"for", "sideways"}});
        CHECK(!ok(r) && errOf(r).startsWith("bad_for"), "wait: bad for");

        const int baseline = eng.changedReceivers();
        c.send("{\"id\":\"w1\",\"cmd\":\"wait\",\"args\":{\"for\":\"verified\",\"timeout_ms\":5000}}\n");
        c.send("{\"id\":\"after\",\"cmd\":\"help\"}\n");
        pump(30);
        CHECK(eng.changedReceivers() == baseline + 1, "a wait listens to changed()");
        Client b;
        CHECK(b.open(sock), "second client");
        r = b.cmd("state");
        CHECK(ok(r), "the second client is served while the first waits");
        CHECK(c.reply(100).isEmpty(), "the waiting client's next request waits behind its wait");
        QTimer::singleShot(100, &eng, [&eng] { eng.set("connected", false, true, false); });
        QTimer::singleShot(200, &eng, [&eng] { eng.set("connected", false, false, true); });
        r = c.reply(3000);
        CHECK(ok(r) && r.value("id").toString() == "w1" && res(r).value("verified").toBool()
                  && res(r).value("after_ms").toInt() >= 150,
              "wait verified completes on the engine's signals (not on verifying)");
        r = c.reply(1000);
        CHECK(ok(r) && r.value("id").toString() == "after", "then the queued request runs");
        pump(30);
        CHECK(eng.changedReceivers() == baseline, "the finished wait left no connection");

        eng.set("disconnected", false);
        Client d;
        CHECK(d.open(sock), "third client");
        d.send("{\"id\":\"w2\",\"cmd\":\"wait\",\"args\":{\"for\":\"connected\",\"timeout_ms\":5000}}\n");
        pump(50);
        CHECK(eng.changedReceivers() == baseline + 1, "the third client waits");
        const int before = server.clientCount();
        d.s.abort();
        pump(80);
        CHECK(server.clientCount() == before - 1, "the leaving client is dropped");
        CHECK(eng.changedReceivers() == baseline, "its wait is cancelled: no connection left");
        eng.set("connected", false);
        pump(30);
        CHECK(ok(b.cmd("state")), "the server is fine after a client left mid-wait");
        eng.set("disconnected", false);

        scn.setPhase("data");
        c.send("{\"id\":\"w3\",\"cmd\":\"wait\",\"args\":{\"for\":\"scan_done\",\"timeout_ms\":5000}}\n");
        QTimer::singleShot(100, &scn, [&scn] { scn.setPhase("done"); });
        r = c.reply(3000);
        CHECK(ok(r) && r.value("id").toString() == "w3" && res(r).value("was_scanning").toBool(),
              "wait scan_done on the Scanner's viewChanged");
    }

    // ---- limits --------------------------------------------------------------------------------------------------
    {
        Client big;
        CHECK(big.open(sock), "oversized client connects");
        QByteArray line = "{\"cmd\":\"mark\",\"args\":{\"text\":\"";
        line += QByteArray(kMaxLineBytes + 10, 'a');
        line += "\"}}\n";
        big.send(line);
        const QJsonObject r = big.reply(3000);
        CHECK(!ok(r) && errOf(r) == "line_too_long", "an oversized line -> line_too_long");
        CHECK(big.closedWithin(2000), "... and the connection ends");

        Client nl;
        CHECK(nl.open(sock), "no-newline client connects");
        nl.send(QByteArray(kMaxLineBytes + 1, 'b'));
        const QJsonObject r2 = nl.reply(3000);
        CHECK(!ok(r2) && errOf(r2) == "line_too_long" && nl.closedWithin(2000), "no newline within the limit -> closed");

        Client q;
        CHECK(q.open(sock), "queue client connects");
        QByteArray many = "{\"cmd\":\"wait\",\"args\":{\"for\":\"connected\",\"timeout_ms\":5000}}\n";
        for (int i = 0; i < kMaxQueued + 1; ++i)
            many += "{\"cmd\":\"help\"}\n";
        q.send(many);
        QJsonObject r3;
        for (int i = 0; i < 3 && errOf(r3).isEmpty(); ++i)
            r3 = q.reply(1500);
        CHECK(errOf(r3) == "queue_full" && q.closedWithin(2000), qPrintable("a full queue -> queue_full: " + errOf(r3)));
        pump(50);

        QList<Client *> extra;
        int refused = 0;
        for (int i = 0; i < kMaxClients + 1; ++i) {
            auto *x = new Client;
            x->open(sock);
            extra << x;
        }
        pump(100);
        for (Client *x : extra) {
            const QJsonObject r4 = x->reply(200);
            refused += errOf(r4) == "too_many_clients" ? 1 : 0;
        }
        CHECK(refused >= 1, qPrintable(QStringLiteral("clients beyond %1 are refused (%2)").arg(kMaxClients).arg(refused)));
        qDeleteAll(extra);
        pump(100);
    }

    // ---- the driver script (--local) and a one-shot nc ------------------------------------------------------------
    {
        QByteArray out;
        int rc = runProcess("/bin/bash", {driver, "--socket", sock, "--local", "state"}, &out);
        CHECK(rc == 0 && QJsonDocument::fromJson(out.trimmed()).object().value("ok").toBool(),
              qPrintable(QStringLiteral("driver state: rc=%1 %2").arg(rc).arg(QString::fromUtf8(out.left(120)))));
        rc = runProcess("/bin/bash", {driver, "--socket", sock, "--local", "fly"}, &out);
        CHECK(rc == 1 && out.contains("unknown_command"), qPrintable(QStringLiteral("driver unknown command: rc=%1").arg(rc)));
        rc = runProcess("/bin/bash", {driver, "--socket", sock, "--local", "wait", "{\"for\":\"connected\",\"timeout_ms\":300}"}, &out);
        CHECK(rc == 1 && out.contains("timeout"), qPrintable(QStringLiteral("driver wait timeout: rc=%1").arg(rc)));
        QTimer::singleShot(300, &eng, [&eng] { eng.set("connected", false); });
        rc = runProcess("/bin/bash", {driver, "--socket", sock, "--local", "wait", "{\"for\":\"connected\",\"timeout_ms\":4000}"}, &out);
        CHECK(rc == 0 && out.contains("\"for\":\"connected\""), qPrintable(QStringLiteral("driver wait met: rc=%1").arg(rc)));
        eng.set("disconnected", false);
        rc = runProcess("/bin/bash", {driver, "--socket", data + "/nope.sock", "--local", "state"}, &out);
        CHECK(rc == 3, qPrintable(QStringLiteral("driver without a socket: rc=%1").arg(rc)));
        rc = runProcess("/bin/bash", {driver, "--local", "state"}, &out);
        CHECK(rc == 2, "driver --local without --socket: usage");
        rc = runProcess("/bin/bash", {driver, "--socket", sock, "--local", "Bad!"}, &out);
        CHECK(rc == 2, "driver bad command name: usage");
        rc = runProcess("/bin/sh", {"-c", QStringLiteral("printf '%s\\n' '{\"id\":\"nc\",\"cmd\":\"state\"}' | nc -U '%1'").arg(sock)}, &out);
        CHECK(rc == 0 && out.startsWith("{\"id\":\"nc\",\"ok\":true"), "a one-shot nc -U gets its reply");
    }

    // ---- the person: noted for the commands that act for one, never for a read ----------------------------------
    {
        eng.set("disconnected", false);
        int before = present;
        c.cmd("state");
        c.cmd("help");
        c.cmd("mark", {{"text", "x"}});
        c.cmd("shot", {{"path", "p"}}, 8000);
        c.cmd("wait", {{"for", "off"}, {"timeout_ms", 100}});
        CHECK(present == before, qPrintable(QStringLiteral("read commands note no person (%1)").arg(present - before)));
        before = present;
        c.cmd("nav", {{"page", "connect"}});
        c.cmd("stop");
        c.cmd("servers");
        c.cmd("scan.rows");
        c.cmd("window.show");
        CHECK(present == before + 5, qPrintable(QStringLiteral("acting commands note the person (%1 of 5)").arg(present - before)));
    }

    // ---- quit ------------------------------------------------------------------------------------------------------
    {
        const int before = present;
        const QJsonObject r = c.cmd("quit");
        CHECK(ok(r) && res(r).value("quitting").toBool() && !quitCalled && present == before + 1,
              "quit: the person is noted, the reply comes first");
        pump(400);
        CHECK(quitCalled, "quit: then the tray's quit path");
    }

    std::printf("dev_control_check: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
