// AVPN (desktop test rig, 24.11.2026): what the test command channel (DevControl.h) does in the app. Desktop dev-tools
// builds only (AVPN_DESKTOP_TEST_CHANNEL).
//
// Every action command makes the SAME call the button of the screen makes, on the GUI thread, behind the screen's own
// guards; it reaches the app only through its QML-visible API by name (Q_INVOKABLE, Q_PROPERTY, QML functions and
// signals) - never private state. The mapping is pinned in tests/dev_control_map.tsv and checked against this file,
// the QML and the engine headers by tests/check_dev_control_wiring.sh:
//   connect / stop   PageConnectTribe.onOrbClicked() - the orb's handler (TribeEngine.orbTap: decideOrbTap). connect
//                    taps only while the orb shows «Подключиться» (face "off"), stop only while it shows anything else;
//                    otherwise nothing is tapped (tapped:false, the face).
//   nav {page}       the bottom bar's activated(index) (PageStart.goAvpnTab) for connect/support/referral/settings;
//                    servers = the Connect card's requestServerPicker(); scanner = the «Сканер» button's
//                    requestScanner() of the Connect or the Servers page (PageStart.openScanner). Refused while the bar
//                    is hidden (onboarding, keyboard, Amnezia mode).
//   servers          the rows of the open Servers page in the order on screen (PageServersTribe.shownKeys, each
//                    key's values from rowsByKey: the order taken at open, ServerListOrder.js) - opened first if needed.
//   choose {id|row}  PageServersTribe.tapRow(row values) - the row's tap; auto = tapAuto() (the «Авто» card);
//   mode {value}     PageServersTribe.tapMode(value) -> TribeTransportSelector.tapSegment (the segment's tap).
//   scan.*           the Scanner page (one screen: the scope choice, then the result) and its one pinned button:
//                    select {scope} = the scope row's tap, PageScannerTribe.select(scope) - the selection only, on the
//                    choice; start = the button pressed for what it says now (TribeScanBar action() + fire(): the
//                    choice's scan / show / connect of the selected scope, the result's «Сканировать снова» /
//                    connect), refused while it is disabled or says «Остановить»; stop = the same button while it says
//                    «Остановить»; connect {row} = TribeScanner.tapRow(id) of a tappable row (the row's tap); back =
//                    PageController.keyPressEvent(Escape) - the Escape key, which the page answers with systemBack()
//                    (the result -> the choice, the choice -> out); open = nav scanner. scan.rows also gives the rings'
//                    count (view.available), the stopped scan's mark (view.partial), the scopes and their fresh results.
//   window.show      PageController.raiseMainWindow() - the tray's «Show».
//   quit             QCoreApplication::quit() - what the tray's «Quit» does (systemTrayNotificationHandler.cpp).
// Before every command that acts for the person (connect, stop, nav, servers, choose, auto, mode, scan.*, window.show,
// quit) the channel tells the engine that a person is here (AppEnv::personPresent = notePersonPresent: the system-sleep
// gate holds a programmatic start until then); it never posts an input event.
// Read-only: state, servers, scan.rows, shot, mark, wait, help. state is a WHITELIST of fields (no key, token, UUID,
// endpoint, IP or credential); node and row ids other than our own numeric node ids go out as an 8-hex hash (ref).
#pragma once

#include "DevControl.h"

#include <QJsonArray>
#include <QJsonObject>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QVariant>

#include <functional>

class QImage;
class QQmlEngine;

namespace avpn::devctl {

struct AppEnv {
    // The QML context objects by name: "TribeEngine", "TribeScanner", "PageController" (null = not there yet).
    std::function<QObject *(const QString &name)> object;
    // The QML root object (the main window), null before the QML is loaded.
    std::function<QObject *()> root;
    QString dataDir;        // the app's data directory (AppDataLocation)
    QString version;        // APP_VERSION
    QString commit;         // GIT_COMMIT_HASH
    std::function<void(const QString &ev, const QJsonObject &fields)> journal; // TribeJournal::append
    std::function<bool()> journalActive;
    std::function<void(const QString &line)> log; // one line into the app log
    std::function<void()> quit;                   // the tray «Quit»: QCoreApplication::quit
    // AvpnEngineQml::notePersonPresent() - the engine's one entry for "a person is here" (SystemAwake.h): called
    // before every command that acts for the person, never a faked input event
    std::function<void()> personPresent;
};

class App : public QObject, public Handler {
    Q_OBJECT
public:
    explicit App(AppEnv env, QObject *parent = nullptr);
    void handle(const QString &cmd, const QJsonObject &args, QObject *ctx, const Done &done) override;
    void setServer(Server *server) { m_server = server; }

    // Pure helpers (tested directly): the orb's face from the engine's public properties, exactly as
    // PageConnectTribe draws it (isOn / showBusy / engineOwnStopping); a text with IPs, UUIDs and long tokens masked;
    // the public form of a node / row id.
    static QString orbFace(const QString &state, bool busy, bool stopping, bool ownStopping, bool waitingUplink,
                           bool adopting, bool verifying);
    static QString redact(const QString &text);
    static QString publicId(const QString &id);
    static QString ref(const QString &id);

private slots:
    void onEngineError(const QString &message);

private:
    // commands (the names below are what tests/dev_control_map.tsv pins)
    QJsonObject cmdHelp();
    QJsonObject cmdState();
    QJsonObject cmdConnect(QString *err);
    QJsonObject cmdStop(QString *err);
    QJsonObject cmdReplace(QString *err);
    QJsonObject cmdNav(const QJsonObject &args, QString *err);
    QJsonObject cmdServers(QString *err);
    QJsonObject cmdChoose(const QJsonObject &args, QString *err);
    QJsonObject cmdAuto(QString *err);
    QJsonObject cmdMode(const QJsonObject &args, QString *err);
    QJsonObject cmdScanOpen(QString *err);
    QJsonObject cmdScanSelect(const QJsonObject &args, QString *err);
    QJsonObject cmdScanStart(QString *err);
    QJsonObject cmdScanStop(QString *err);
    QJsonObject cmdScanRows(QString *err);
    QJsonObject cmdScanConnect(const QJsonObject &args, QString *err);
    QJsonObject cmdScanBack(QString *err);
    QJsonObject cmdWindowShow(QString *err);
    QJsonObject cmdShot(const QJsonObject &args, QString *err);
    QJsonObject cmdMark(const QJsonObject &args, QString *err);
    void cmdWait(const QJsonObject &args, QObject *ctx, const Done &done);
    void cmdQuit(const Done &done);

    // navigation: the page `name` is shown the app's own way (see the header comment); returns it or null + *err
    QObject *showPage(const QString &name, QString *err);

    // access
    QObject *engine(QString *err = nullptr);
    QObject *scanner(QString *err = nullptr);
    QObject *pages(QString *err = nullptr); // PageController
    QObject *pageStart(QString *err = nullptr);
    QObject *currentPage();
    QString currentPageName();
    QObject *window();
    void hookSignals();

    // the engine's view
    QString face();
    bool verified();
    QJsonObject serverRows(QObject *page);
    QVariantMap scanView();
    bool wantMet(const QString &what);

    QJsonObject stateBrief();

    AppEnv m_env;
    QPointer<Server> m_server;
    QPointer<QObject> m_hookedEngine;
    QString m_lastError;
    qint64 m_lastErrorMs = 0;
};

// The app's channel: App + Server over the QML engine of the app (context objects and root window from it), the data
// directory, the log and the journal. Logs and returns null when the socket cannot be set up.
Server *install(QQmlEngine *qml, QObject *parent);

} // namespace avpn::devctl
