// AVPN (desktop test rig): the test command channel's commands (DevControlApp.h). Every call into the app below goes
// through js() / cpp() / sig() with a literal method name: tests/check_dev_control_wiring.sh reads those names per
// command function and compares them with tests/dev_control_map.tsv.
#include "DevControlApp.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QImage>
#include <QJSValue>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMetaMethod>
#include <QQuickWindow>
#include <QRegularExpression>
#include <QSysInfo>
#include <QTimer>
#include <QWindow>

namespace avpn::devctl {

// A slot target for signals connected by name (string-based connect) whose lifetime is a request's context.
class Relay : public QObject {
    Q_OBJECT
public:
    using QObject::QObject;
    std::function<void()> fn;
public slots:
    void fire()
    {
        if (fn)
            fn();
    }
};

namespace {

// ---- calls by name ------------------------------------------------------------------------------------------------

QVariant plain(const QVariant &v)
{
    if (v.metaType() == QMetaType::fromType<QJSValue>())
        return plain(v.value<QJSValue>().toVariant());
    if (v.metaType() == QMetaType::fromType<QJsonObject>())
        return v.toJsonObject().toVariantMap();
    if (v.metaType() == QMetaType::fromType<QJsonArray>())
        return v.toJsonArray().toVariantList();
    if (v.metaType() == QMetaType::fromType<QVariantList>()) {
        QVariantList out;
        for (const QVariant &x : v.toList())
            out << plain(x);
        return out;
    }
    if (v.metaType() == QMetaType::fromType<QVariantMap>()) {
        QVariantMap out;
        const QVariantMap m = v.toMap();
        for (auto it = m.constBegin(); it != m.constEnd(); ++it)
            out.insert(it.key(), plain(it.value()));
        return out;
    }
    return v;
}

QVariant prop(QObject *o, const char *name)
{
    return o ? plain(o->property(name)) : QVariant();
}

// One method of o by name and argument count (the most derived first): a QML function, a Q_INVOKABLE or a signal
// (invoking a signal emits it). Arguments are converted to the parameter types; QVariant parameters take them as is.
bool metaCall(QObject *o, const char *name, const QVariantList &args, QVariant *ret, QString *err)
{
    if (!o) {
        *err = QStringLiteral("not_ready");
        return false;
    }
    if (args.size() > 4) {
        *err = QStringLiteral("too_many_args");
        return false;
    }
    const QMetaObject *mo = o->metaObject();
    QMetaMethod m;
    for (int i = mo->methodCount() - 1; i >= 0; --i) {
        const QMetaMethod c = mo->method(i);
        if (c.methodType() != QMetaMethod::Constructor && c.parameterCount() == args.size() && c.name() == name) {
            m = c;
            break;
        }
    }
    if (!m.isValid()) {
        *err = QStringLiteral("missing: ") + QString::fromLatin1(name);
        return false;
    }
    QVariantList conv;
    for (int i = 0; i < args.size(); ++i) {
        const QMetaType t = m.parameterMetaType(i);
        QVariant v = args.at(i);
        if (t != QMetaType::fromType<QVariant>() && v.metaType() != t && !v.convert(t)) {
            *err = QStringLiteral("arg_type: ") + QString::fromLatin1(name);
            return false;
        }
        conv << v;
    }
    QGenericArgument a[4];
    for (int i = 0; i < conv.size(); ++i) {
        const QMetaType t = m.parameterMetaType(i);
        a[i] = t == QMetaType::fromType<QVariant>() ? QGenericArgument("QVariant", &conv[i])
                                                    : QGenericArgument(t.name(), conv[i].constData());
    }
    QVariant r;
    QGenericReturnArgument gr;
    const QMetaType rt = m.returnMetaType();
    if (rt.isValid() && rt.id() != QMetaType::Void) {
        if (rt == QMetaType::fromType<QVariant>()) {
            gr = QGenericReturnArgument("QVariant", &r);
        } else {
            r = QVariant(rt);
            gr = QGenericReturnArgument(rt.name(), r.data());
        }
    }
    if (!m.invoke(o, Qt::DirectConnection, gr, a[0], a[1], a[2], a[3])) {
        *err = QStringLiteral("call_failed: ") + QString::fromLatin1(name);
        return false;
    }
    if (ret)
        *ret = plain(r);
    return true;
}

// The three ways a command reaches the app (the wiring check reads their literal names): a QML function of a page,
// a Q_INVOKABLE of a C++ object, a signal of either. read() is a const getter (debugSnapshot, networkKind): no action.
bool js(QObject *o, const char *fn, const QVariantList &args, QVariant *ret, QString *err)
{
    return metaCall(o, fn, args, ret, err);
}
bool cpp(QObject *o, const char *fn, const QVariantList &args, QString *err)
{
    return metaCall(o, fn, args, nullptr, err);
}
bool sig(QObject *o, const char *signal, const QVariantList &args, QString *err)
{
    return metaCall(o, signal, args, nullptr, err);
}
QVariant read(QObject *o, const char *getter)
{
    QVariant r;
    QString ignored;
    metaCall(o, getter, {}, &r, &ignored);
    return r;
}

// ---- values ---------------------------------------------------------------------------------------------------

QJsonValue scalar(const QVariant &v)
{
    switch (v.metaType().id()) {
    case QMetaType::Bool: return v.toBool();
    case QMetaType::Int:
    case QMetaType::UInt:
    case QMetaType::Long:
    case QMetaType::LongLong:
    case QMetaType::ULongLong:
    case QMetaType::Short: return double(v.toLongLong());
    case QMetaType::Double:
    case QMetaType::Float: return v.toDouble();
    case QMetaType::QString: return App::redact(v.toString());
    default: break;
    }
    if (!v.isValid() || v.isNull())
        return QJsonValue(QJsonValue::Null);
    return QJsonValue(QJsonValue::Null); // never a structure through a scalar field
}

bool scanningPhase(const QString &phase)
{
    return phase == QLatin1String("preparing") || phase == QLatin1String("connecting") || phase == QLatin1String("reach")
        || phase == QLatin1String("data");
}

const QHash<QString, QString> &pageFiles()
{
    static const QHash<QString, QString> m{
        {QStringLiteral("connect"), QStringLiteral("PageConnectTribe")},
        {QStringLiteral("support"), QStringLiteral("PageSupportTribe")},
        {QStringLiteral("referral"), QStringLiteral("PageReferralTribe")},
        {QStringLiteral("settings"), QStringLiteral("PageAccountTribe")},
        {QStringLiteral("servers"), QStringLiteral("PageServersTribe")},
        {QStringLiteral("scanner"), QStringLiteral("PageScannerTribe")},
    };
    return m;
}

// The bottom bar's fixed indices (TribeBottomNav.qml: 0 home / 1 support / 2 referral / 3 settings).
int tabIndex(const QString &page)
{
    if (page == QLatin1String("connect")) return 0;
    if (page == QLatin1String("support")) return 1;
    if (page == QLatin1String("referral")) return 2;
    if (page == QLatin1String("settings")) return 3;
    return -1;
}

// The commands that act for the person: the engine is told a person is here before each (SystemAwake.h).
const QStringList &personCommands()
{
    static const QStringList l{QStringLiteral("connect"), QStringLiteral("stop"), QStringLiteral("replace"), QStringLiteral("nav"),
                               QStringLiteral("servers"), QStringLiteral("choose"), QStringLiteral("auto"),
                               QStringLiteral("mode"), QStringLiteral("scan.open"), QStringLiteral("scan.select"),
                               QStringLiteral("scan.start"), QStringLiteral("scan.stop"), QStringLiteral("scan.rows"),
                               QStringLiteral("scan.connect"), QStringLiteral("scan.back"), QStringLiteral("window.show"),
                               QStringLiteral("quit")};
    return l;
}

const QStringList &actionCommands()
{
    static const QStringList l{QStringLiteral("connect"), QStringLiteral("stop"), QStringLiteral("replace"), QStringLiteral("nav"),
                               QStringLiteral("choose"), QStringLiteral("auto"), QStringLiteral("mode"),
                               QStringLiteral("scan.open"), QStringLiteral("scan.select"), QStringLiteral("scan.start"),
                               QStringLiteral("scan.stop"), QStringLiteral("scan.connect"), QStringLiteral("scan.back"),
                               QStringLiteral("window.show"), QStringLiteral("quit")};
    return l;
}

} // namespace

// ---- pure helpers -----------------------------------------------------------------------------------------------

QString App::orbFace(const QString &state, bool busy, bool stopping, bool ownStopping, bool waitingUplink, bool adopting,
                     bool verifying)
{
    // PageConnectTribe: isOn = state "connected"; showBusy = (busy && !stopping) || waitingUplink; the caption's order
    // waitingNet -> verifyingNow -> engineOwnStopping -> showBusy (adopting = «Проверяем…») -> isOn -> «Подключиться».
    const bool showBusy = (busy && !stopping) || waitingUplink;
    if (waitingUplink)
        return QStringLiteral("waiting_network");
    if (verifying)
        return QStringLiteral("verifying");
    if (ownStopping)
        return QStringLiteral("disconnecting");
    if (showBusy)
        return adopting ? QStringLiteral("checking") : QStringLiteral("connecting");
    if (state == QLatin1String("connected"))
        return QStringLiteral("connected");
    return QStringLiteral("off");
}

QString App::redact(const QString &text)
{
    static const QRegularExpression uuid(
        QStringLiteral("[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"));
    static const QRegularExpression token(QStringLiteral("(?=[A-Za-z0-9+/_=-]*\\d)[A-Za-z0-9+/_=-]{24,}")); // keys, tokens
    static const QRegularExpression ipv4(QStringLiteral("\\b(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d{1,5})?\\b"));
    static const QRegularExpression ipv6(QStringLiteral("\\[?[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}\\]?(?::\\d{1,5})?"));
    QString s = text;
    s.replace(uuid, QStringLiteral("<uuid>"));
    s.replace(token, QStringLiteral("<token>"));
    s.replace(ipv4, QStringLiteral("<ip>"));
    // an IPv6 address has "::" or at least three colons (a clock "12:30:45" has two)
    QString out;
    qsizetype at = 0;
    auto it = ipv6.globalMatch(s);
    while (it.hasNext()) {
        const auto m = it.next();
        const QString hit = m.captured(0);
        if (hit.contains(QLatin1String("::")) || hit.count(QLatin1Char(':')) >= 3) {
            out += s.mid(at, m.capturedStart(0) - at) + QStringLiteral("<ip6>");
            at = m.capturedEnd(0);
        }
    }
    out += s.mid(at);
    return out.left(400);
}

QString App::ref(const QString &id)
{
    return QString::fromLatin1(
        QCryptographicHash::hash(QByteArray("avpn-devctl:") + id.toUtf8(), QCryptographicHash::Sha256).toHex().left(8));
}

QString App::publicId(const QString &id)
{
    // our own listeners: "9", "9:xray" (openapi node_id); anything else (provider "up:<profile>", ...) as a hash
    static const QRegularExpression own(QStringLiteral("^\\d{1,9}(?::[a-z0-9_-]{1,16})?$"));
    if (id.isEmpty() || own.match(id).hasMatch())
        return id;
    return QStringLiteral("ref:") + ref(id);
}

// ---- the handler -----------------------------------------------------------------------------------------------

App::App(AppEnv env, QObject *parent) : QObject(parent), m_env(std::move(env))
{
    // the QML context is complete only after the controllers are made: hook the engine's error signal then
    QTimer::singleShot(0, this, [this] { hookSignals(); });
}

void App::hookSignals()
{
    QObject *e = engine();
    if (!e || m_hookedEngine == e)
        return;
    m_hookedEngine = e;
    if (e->metaObject()->indexOfSignal("error(QString)") >= 0)
        connect(e, SIGNAL(error(QString)), this, SLOT(onEngineError(QString)));
}

void App::onEngineError(const QString &message)
{
    m_lastError = redact(message);
    m_lastErrorMs = QDateTime::currentMSecsSinceEpoch();
}

QObject *App::engine(QString *err)
{
    QObject *o = m_env.object ? m_env.object(QStringLiteral("TribeEngine")) : nullptr;
    if (!o && err)
        *err = QStringLiteral("not_ready: TribeEngine");
    return o;
}

QObject *App::scanner(QString *err)
{
    QObject *o = m_env.object ? m_env.object(QStringLiteral("TribeScanner")) : nullptr;
    if (!o && err)
        *err = QStringLiteral("not_ready: TribeScanner (no Scanner on this build)");
    return o;
}

QObject *App::pages(QString *err)
{
    QObject *o = m_env.object ? m_env.object(QStringLiteral("PageController")) : nullptr;
    if (!o && err)
        *err = QStringLiteral("not_ready: PageController");
    return o;
}

QObject *App::window()
{
    return m_env.root ? m_env.root() : nullptr;
}

QObject *App::pageStart(QString *err)
{
    QObject *root = window();
    QObject *ps = root ? root->findChild<QObject *>(QStringLiteral("pageStart")) : nullptr;
    if (!ps && err)
        *err = QStringLiteral("not_ready: the main window is not loaded");
    return ps;
}

QObject *App::currentPage()
{
    QObject *ps = pageStart();
    QObject *stack = ps ? ps->findChild<QObject *>(QStringLiteral("tabBarStackView")) : nullptr;
    return stack ? prop(stack, "currentItem").value<QObject *>() : nullptr;
}

QString App::currentPageName()
{
    QObject *p = currentPage();
    if (!p)
        return QString();
    QString n = p->objectName().section(QLatin1Char('/'), -1);
    if (n.endsWith(QLatin1String(".qml")))
        n.chop(4);
    return n;
}

QString App::face()
{
    QObject *e = engine();
    if (!e)
        return QString();
    return orbFace(prop(e, "state").toString(), prop(e, "busy").toBool(), prop(e, "stopping").toBool(),
                   prop(e, "ownStopping").toBool(), prop(e, "waitingUplink").toBool(), prop(e, "adopting").toBool(),
                   prop(e, "verifying").toBool());
}

// «Подключено» with data through the tunnel: the orb shows Connected and the engine's ONLINE fact (dataFlowing).
bool App::verified()
{
    QObject *e = engine();
    return e && face() == QLatin1String("connected") && prop(e, "dataFlowing").toBool();
}

QVariantMap App::scanView()
{
    QObject *s = scanner();
    return s ? prop(s, "view").toMap() : QVariantMap();
}

QJsonObject App::stateBrief()
{
    QObject *e = engine();
    QJsonObject o;
    o.insert(QStringLiteral("state"), e ? prop(e, "state").toString() : QString());
    o.insert(QStringLiteral("face"), face());
    o.insert(QStringLiteral("verified"), verified());
    o.insert(QStringLiteral("page"), currentPageName());
    return o;
}

void App::handle(const QString &cmd, const QJsonObject &args, QObject *ctx, const Done &done)
{
    hookSignals();
    if (actionCommands().contains(cmd)) {
        if (m_env.log)
            m_env.log(QStringLiteral("[avpn devctl] cmd=") + cmd);
        if (m_env.journal)
            m_env.journal(QStringLiteral("dev_cmd"), {{QStringLiteral("cmd"), cmd}});
    }
    if (personCommands().contains(cmd) && m_env.personPresent)
        m_env.personPresent(); // the engine's one "a person is here" entry, before the button's call
    if (cmd == QLatin1String("wait"))
        return cmdWait(args, ctx, done);
    if (cmd == QLatin1String("quit"))
        return cmdQuit(done);
    QString err;
    QJsonObject r;
    if (cmd == QLatin1String("help")) r = cmdHelp();
    else if (cmd == QLatin1String("state")) r = cmdState();
    else if (cmd == QLatin1String("connect")) r = cmdConnect(&err);
    else if (cmd == QLatin1String("stop")) r = cmdStop(&err);
    else if (cmd == QLatin1String("replace")) r = cmdReplace(&err);
    else if (cmd == QLatin1String("nav")) r = cmdNav(args, &err);
    else if (cmd == QLatin1String("servers")) r = cmdServers(&err);
    else if (cmd == QLatin1String("choose")) r = cmdChoose(args, &err);
    else if (cmd == QLatin1String("auto")) r = cmdAuto(&err);
    else if (cmd == QLatin1String("mode")) r = cmdMode(args, &err);
    else if (cmd == QLatin1String("scan.open")) r = cmdScanOpen(&err);
    else if (cmd == QLatin1String("scan.select")) r = cmdScanSelect(args, &err);
    else if (cmd == QLatin1String("scan.start")) r = cmdScanStart(&err);
    else if (cmd == QLatin1String("scan.stop")) r = cmdScanStop(&err);
    else if (cmd == QLatin1String("scan.rows")) r = cmdScanRows(&err);
    else if (cmd == QLatin1String("scan.connect")) r = cmdScanConnect(args, &err);
    else if (cmd == QLatin1String("scan.back")) r = cmdScanBack(&err);
    else if (cmd == QLatin1String("window.show")) r = cmdWindowShow(&err);
    else if (cmd == QLatin1String("shot")) r = cmdShot(args, &err);
    else if (cmd == QLatin1String("mark")) r = cmdMark(args, &err);
    else err = QStringLiteral("unknown_command: ") + cmd;
    done(r, err);
}

QJsonObject App::cmdHelp()
{
    QJsonArray c;
    for (const char *n : {"help", "state", "connect", "stop", "replace", "nav", "servers", "choose", "auto", "mode", "scan.open",
                          "scan.select", "scan.start", "scan.stop", "scan.rows", "scan.connect", "scan.back",
                          "window.show", "shot", "mark", "wait", "quit"})
        c << QString::fromLatin1(n);
    return {{QStringLiteral("commands"), c}, {QStringLiteral("protocol"), 1}};
}

// ---- state -------------------------------------------------------------------------------------------------------

QJsonObject App::cmdState()
{
    QJsonObject o;
    o.insert(QStringLiteral("app"), QJsonObject{{QStringLiteral("version"), m_env.version},
                                                {QStringLiteral("commit"), m_env.commit},
                                                {QStringLiteral("platform"), QSysInfo::productType() + QLatin1Char(' ')
                                                                                 + QSysInfo::productVersion()}});
    QObject *e = engine();
    if (e) {
        static const char *const engineFields[][2] = {
            {"state", "state"}, {"busy", "busy"}, {"stopping", "stopping"}, {"own_stopping", "ownStopping"},
            {"waiting_uplink", "waitingUplink"}, {"adopting", "adopting"}, {"verifying", "verifying"},
            {"data_flowing", "dataFlowing"}, {"path_check", "pathCheck"}, {"active_proto", "activeProto"},
            {"transport_mode", "transportMode"}, {"paused", "paused"}, {"svc_installing", "svcInstalling"},
            {"sub_loaded", "subLoaded"}, {"sub_active", "subActive"}, {"sub_offline", "subOffline"},
            {"whitelist_mode", "whitelistMode"}, {"live_rtt_ms", "liveRttMs"}, {"live_bars", "liveBars"},
            {"live_reachable", "liveReachable"}, {"live_dead", "liveDead"}, {"attempt_checked", "attemptChecked"},
            {"attempt_total", "attemptTotal"}, {"scanner_enabled", "scannerEnabled"}};
        QJsonObject en;
        for (const auto &f : engineFields)
            en.insert(QString::fromLatin1(f[0]), scalar(prop(e, f[1])));
        en.insert(QStringLiteral("network_kind"), scalar(read(e, "networkKind")));
        o.insert(QStringLiteral("engine"), en);

        const QString fc = face();
        o.insert(QStringLiteral("orb"), fc);
        // the intent as the orb shows it (the engine keeps its own flag private): on while it connects, checks,
        // waits for the network or is connected; "paused" for the shopping pause
        const bool paused = prop(e, "paused").toBool();
        o.insert(QStringLiteral("intent"), paused ? QStringLiteral("paused")
                                           : (fc == QLatin1String("off") || fc == QLatin1String("disconnecting"))
                                               ? QStringLiteral("off") : QStringLiteral("on"));
        o.insert(QStringLiteral("connected"), fc == QLatin1String("connected"));
        o.insert(QStringLiteral("verified"), verified());

        const QVariantMap n = prop(e, "currentNode").toMap();
        QJsonObject node;
        node.insert(QStringLiteral("id"), publicId(n.value(QStringLiteral("nodeId")).toString()));
        node.insert(QStringLiteral("ref"), n.value(QStringLiteral("nodeId")).toString().isEmpty()
                                               ? QString() : ref(n.value(QStringLiteral("nodeId")).toString()));
        node.insert(QStringLiteral("name"), redact(n.value(QStringLiteral("name")).toString()));
        node.insert(QStringLiteral("country"), n.value(QStringLiteral("countryCode")).toString());
        node.insert(QStringLiteral("kind"), n.value(QStringLiteral("proto")).toString());
        node.insert(QStringLiteral("kind_version"), n.value(QStringLiteral("protoVersion")).toString());
        node.insert(QStringLiteral("provider"), n.value(QStringLiteral("upstream")).toBool());
        node.insert(QStringLiteral("provider_kind"), n.value(QStringLiteral("upstreamKind")).toString());
        node.insert(QStringLiteral("pinned"), n.value(QStringLiteral("pinned")).toBool());
        node.insert(QStringLiteral("auto"), n.value(QStringLiteral("auto")).toBool());
        node.insert(QStringLiteral("connected"), n.value(QStringLiteral("connected")).toBool());
        node.insert(QStringLiteral("rtt_ms"), scalar(n.value(QStringLiteral("measuredRttMs"))));
        if (n.contains(QStringLiteral("choiceNodeId"))) {
            const QString choice = n.value(QStringLiteral("choiceNodeId")).toString();
            node.insert(QStringLiteral("choice"), choice.isEmpty() ? QStringLiteral("auto") : publicId(choice));
            node.insert(QStringLiteral("choice_name"), redact(n.value(QStringLiteral("choiceName")).toString()));
        }
        o.insert(QStringLiteral("node"), node);

        // the debug snapshot (PageDiagnostics' source), its scalar fields only - never pool rows, endpoints, logs
        const QVariantMap s = read(e, "debugSnapshot").toMap();
        static const char *const snapFields[] = {
            "state", "latestHandshakeAgeSec", "rxBytes", "txBytes", "subStatus", "lkgStale", "activeProto",
            "transportMode", "verifying", "poolRevision", "rttCacheAgeMs", "awaitingStopConfirm",
            "needStatusBeforeStart", "stopRetries", "permissionPromptPending", "liveSessionPending",
            "lastSelectionMeasured", "reseedPending"};
        QJsonObject snap;
        for (const char *f : snapFields)
            if (s.contains(QString::fromLatin1(f)))
                snap.insert(QString::fromLatin1(f), scalar(s.value(QString::fromLatin1(f))));
        snap.insert(QStringLiteral("currentNodeId"), publicId(s.value(QStringLiteral("currentNodeId")).toString()));
        const QVariantList pool = s.value(QStringLiteral("pool")).toList();
        int alive = 0;
        for (const QVariant &r : pool)
            alive += r.toMap().value(QStringLiteral("alive")).toBool() ? 1 : 0;
        snap.insert(QStringLiteral("pool_size"), int(pool.size()));
        snap.insert(QStringLiteral("pool_alive"), alive);
        snap.insert(QStringLiteral("switch_log_lines"), int(s.value(QStringLiteral("switchLog")).toList().size()));
        const QVariantMap up = s.value(QStringLiteral("upstream")).toMap();
        if (!up.isEmpty()) {
            QJsonObject u;
            for (const char *f : {"state", "code", "revision", "expires_in_ms", "standbyEntries"})
                if (up.contains(QString::fromLatin1(f)))
                    u.insert(QString::fromLatin1(f), scalar(up.value(QString::fromLatin1(f))));
            u.insert(QStringLiteral("node"), publicId(up.value(QStringLiteral("node")).toString()));
            snap.insert(QStringLiteral("upstream"), u);
        }
        o.insert(QStringLiteral("snapshot"), snap);
    }
    if (!m_lastError.isEmpty())
        o.insert(QStringLiteral("last_error"),
                 QJsonObject{{QStringLiteral("text"), m_lastError},
                             {QStringLiteral("age_s"), double((QDateTime::currentMSecsSinceEpoch() - m_lastErrorMs) / 1000)}});
    else
        o.insert(QStringLiteral("last_error"), QJsonValue(QJsonValue::Null));

    if (QObject *sc = scanner()) {
        const QVariantMap v = scanView();
        const QVariantMap bar = v.value(QStringLiteral("bar")).toMap();
        const QString phase = v.value(QStringLiteral("phase")).toString();
        o.insert(QStringLiteral("scanner"),
                 QJsonObject{{QStringLiteral("enabled"), prop(sc, "enabled").toBool()},
                             {QStringLiteral("screen_open"), prop(sc, "screenOpen").toBool()},
                             {QStringLiteral("phase"), phase},
                             {QStringLiteral("scanning"), scanningPhase(phase)},
                             {QStringLiteral("stage"), v.value(QStringLiteral("stage")).toString()},
                             {QStringLiteral("rows"), int(v.value(QStringLiteral("rows")).toList().size())},
                             {QStringLiteral("verified"), v.value(QStringLiteral("verified")).toInt()},
                             {QStringLiteral("unverified"), v.value(QStringLiteral("unverified")).toInt()},
                             {QStringLiteral("available"), v.value(QStringLiteral("available")).toInt()},
                             {QStringLiteral("partial"), v.value(QStringLiteral("partial")).toBool()},
                             {QStringLiteral("slots"), int(v.value(QStringLiteral("slots")).toList().size())},
                             {QStringLiteral("more_available"), v.value(QStringLiteral("more_available")).toBool()},
                             {QStringLiteral("button"), bar.value(QStringLiteral("button")).toString()},
                             {QStringLiteral("button_enabled"), bar.value(QStringLiteral("button_enabled"), true).toBool()},
                             {QStringLiteral("net"), v.value(QStringLiteral("net")).toString()}});
    } else {
        o.insert(QStringLiteral("scanner"), QJsonValue(QJsonValue::Null));
    }

    QJsonObject ui;
    ui.insert(QStringLiteral("page"), currentPageName());
    QObject *ps = pageStart();
    ui.insert(QStringLiteral("onboarding"), ps ? prop(ps, "onboardingActive").toBool() : false);
    if (auto *w = qobject_cast<QWindow *>(window())) {
        ui.insert(QStringLiteral("window"),
                  QJsonObject{{QStringLiteral("visible"), w->isVisible()},
                              {QStringLiteral("exposed"), w->isExposed()},
                              {QStringLiteral("minimized"), bool(w->windowStates() & Qt::WindowMinimized)},
                              {QStringLiteral("active"), w->isActive()}});
    }
    o.insert(QStringLiteral("ui"), ui);
    o.insert(QStringLiteral("channel"), QJsonObject{{QStringLiteral("clients"), m_server ? m_server->clientCount() : 0}});
    return o;
}

// ---- connect / stop: the orb ---------------------------------------------------------------------------------------

QJsonObject App::cmdConnect(QString *err)
{
    if (!engine(err))
        return {};
    const QString before = face();
    if (before != QLatin1String("off")) // the orb does not show «Подключиться»: a tap now would not connect
        return {{QStringLiteral("tapped"), false}, {QStringLiteral("face"), before}};
    QObject *page = showPage(QStringLiteral("connect"), err);
    if (!page)
        return {};
    if (!js(page, "onOrbClicked", {}, nullptr, err))
        return {};
    return {{QStringLiteral("tapped"), true}, {QStringLiteral("face_before"), before},
            {QStringLiteral("after"), stateBrief()}};
}

QJsonObject App::cmdStop(QString *err)
{
    if (!engine(err))
        return {};
    const QString before = face();
    if (before == QLatin1String("off")) // nothing to stop: a tap now would connect
        return {{QStringLiteral("tapped"), false}, {QStringLiteral("face"), before}};
    QObject *page = showPage(QStringLiteral("connect"), err);
    if (!page)
        return {};
    if (!js(page, "onOrbClicked", {}, nullptr, err))
        return {};
    return {{QStringLiteral("tapped"), true}, {QStringLiteral("face_before"), before},
            {QStringLiteral("after"), stateBrief()}};
}

// «Заменить сервер» on the home page (round mac-D2): the button's own function, its guards included - connected: the
// next live node (rotateNext); off or an ended attempt: the server choice; busy: nothing. Hidden with an expired
// access (the page shows the renewal instead): refused, as no one can press it.
QJsonObject App::cmdReplace(QString *err)
{
    if (!engine(err))
        return {};
    QObject *home = showPage(QStringLiteral("connect"), err);
    if (!home)
        return {};
    if (prop(home, "subExpired").toBool())
        return {{QStringLiteral("pressed"), false}, {QStringLiteral("reason"), QStringLiteral("not_shown")}};
    const QString before = face();
    QVariant did;
    if (!js(home, "onReplaceServerClicked", {}, &did, err))
        return {};
    return {{QStringLiteral("pressed"), true}, {QStringLiteral("did"), did.toString()},
            {QStringLiteral("face_before"), before}, {QStringLiteral("after"), stateBrief()}};
}

// ---- navigation --------------------------------------------------------------------------------------------------

QObject *App::showPage(const QString &name, QString *err)
{
    const QString file = pageFiles().value(name);
    if (file.isEmpty()) {
        *err = QStringLiteral("unknown_page: ") + name + QStringLiteral(" (connect servers scanner settings support referral)");
        return nullptr;
    }
    QObject *ps = pageStart(err);
    if (!ps)
        return nullptr;
    if (currentPageName() == file)
        return currentPage();
    QObject *bar = ps->findChild<QObject *>(QStringLiteral("avpnBottomNav"));
    if (prop(ps, "avpnNav").toBool() == false || prop(ps, "onboardingActive").toBool() || !bar
        || !prop(bar, "visible").toBool()) {
        *err = QStringLiteral("navigation_hidden: the bottom bar is not shown (onboarding, keyboard or Amnezia mode)");
        return nullptr;
    }
    const int tab = tabIndex(name);
    if (tab >= 0) {
        if (tab == 2 && prop(bar, "referralVisible").toBool() == false) {
            *err = QStringLiteral("tab_hidden: referral");
            return nullptr;
        }
        if (!sig(bar, "activated", {tab}, err))
            return nullptr;
    } else if (name == QLatin1String("servers")) {
        QObject *home = showPage(QStringLiteral("connect"), err);
        if (!home || !sig(home, "requestServerPicker", {}, err))
            return nullptr;
    } else { // scanner: a «Сканер» button that is shown - the Servers page's (ScanSwitches.scanner), else the home one
             // (ScanSwitches.replacesDoctor = scanner && !doctorLegacy), else the Servers page first
        QObject *e = engine(err);
        if (!e)
            return nullptr;
        if (!prop(e, "scannerEnabled").toBool()) {
            *err = QStringLiteral("scanner_off: the Scanner switch is off (no Scanner button is shown)");
            return nullptr;
        }
        if (currentPageName() != QLatin1String("PageServersTribe") && !prop(e, "doctorLegacy").toBool()) {
            QObject *home = showPage(QStringLiteral("connect"), err);
            if (!home || !sig(home, "requestScanner", {}, err))
                return nullptr;
        } else {
            QObject *list = showPage(QStringLiteral("servers"), err);
            if (!list || !sig(list, "requestScanner", {}, err))
                return nullptr;
        }
    }
    if (currentPageName() != file) {
        *err = QStringLiteral("page_not_shown: ") + name
            + (name == QLatin1String("scanner") ? QStringLiteral(" (the Scanner switch is off?)") : QString());
        return nullptr;
    }
    return currentPage();
}

QJsonObject App::cmdNav(const QJsonObject &args, QString *err)
{
    const QString page = args.value(QStringLiteral("page")).toString().toLower();
    const QString before = currentPageName();
    if (!showPage(page, err))
        return {};
    return {{QStringLiteral("page"), currentPageName()}, {QStringLiteral("from"), before}};
}

// ---- servers -----------------------------------------------------------------------------------------------------

// The Servers page's rows as it shows them: the location keys in their order on screen (shownKeys, the ListView's
// model: the order taken when the page opened, ServerListOrder.js) and each key's values (rowsByKey) - what a row
// delegate draws (row.d) and hands to tapRow.
static QVariantList shownServerRows(QObject *page)
{
    QVariantList out;
    const QVariantMap byKey = prop(page, "rowsByKey").toMap();
    for (const QVariant &k : prop(page, "shownKeys").toList()) {
        const QVariant row = byKey.value(k.toString());
        if (row.isValid())
            out << row;
    }
    return out;
}

QJsonObject App::serverRows(QObject *page)
{
    QHash<QString, QString> protoOf;
    if (QObject *e = engine())
        for (const QVariant &v : prop(e, "nodePool").toList()) {
            const QVariantMap n = v.toMap();
            protoOf.insert(n.value(QStringLiteral("nodeId")).toString(),
                           n.value(QStringLiteral("proto"), QStringLiteral("awg")).toString());
        }
    QJsonArray rows;
    const QVariantList list = shownServerRows(page);
    for (int i = 0; i < list.size(); ++i) {
        const QVariantMap e = list.at(i).toMap();
        QJsonArray kinds;
        for (const QVariant &b : e.value(QStringLiteral("badges")).toList()) {
            const QVariantMap bm = b.toMap();
            kinds << QJsonObject{{QStringLiteral("kind"), bm.value(QStringLiteral("proto")).toString()},
                                 {QStringLiteral("version"), bm.value(QStringLiteral("version")).toString()},
                                 {QStringLiteral("supported"), bm.value(QStringLiteral("supported")).toBool()},
                                 {QStringLiteral("active"), bm.value(QStringLiteral("active")).toBool()}};
        }
        const QString nodeId = e.value(QStringLiteral("nodeId")).toString();
        rows << QJsonObject{{QStringLiteral("row"), i + 1},
                            {QStringLiteral("ref"), ref(e.value(QStringLiteral("key")).toString())},
                            {QStringLiteral("name"), redact(e.value(QStringLiteral("name")).toString())},
                            {QStringLiteral("country"), e.value(QStringLiteral("cc")).toString()},
                            {QStringLiteral("kinds"), kinds},
                            {QStringLiteral("node"), publicId(nodeId)},
                            {QStringLiteral("picks"), protoOf.value(nodeId)},
                            {QStringLiteral("rtt_ms"), scalar(e.value(QStringLiteral("rtt")))},
                            {QStringLiteral("bars"), scalar(e.value(QStringLiteral("bars")))},
                            {QStringLiteral("provider"), e.value(QStringLiteral("upstream")).toBool()},
                            {QStringLiteral("current"), e.value(QStringLiteral("isCurrent")).toBool()},
                            {QStringLiteral("chosen"), e.value(QStringLiteral("isChosen")).toBool()},
                            {QStringLiteral("disabled"), e.value(QStringLiteral("disabled")).toBool()},
                            {QStringLiteral("mode_only"), e.value(QStringLiteral("modeOnly")).toBool()},
                            {QStringLiteral("failed_here"), e.value(QStringLiteral("attemptFailed")).toBool()}};
    }
    return {{QStringLiteral("rows"), rows},
            {QStringLiteral("auto"), prop(page, "autoMode").toBool()},
            {QStringLiteral("mode"), prop(page, "transportMode").toString()},
            {QStringLiteral("mode_selector"), prop(page, "showTransportSelector").toBool()},
            {QStringLiteral("awg_in_pool"), prop(page, "awgInPool").toBool()},
            {QStringLiteral("xray_in_pool"), prop(page, "xrayInPool").toBool()}};
}

QJsonObject App::cmdServers(QString *err)
{
    const bool wasOpen = currentPageName() == QLatin1String("PageServersTribe");
    QObject *page = showPage(QStringLiteral("servers"), err);
    if (!page)
        return {};
    QJsonObject r = serverRows(page);
    r.insert(QStringLiteral("opened"), !wasOpen);
    return r;
}

QJsonObject App::cmdChoose(const QJsonObject &args, QString *err)
{
    QObject *page = showPage(QStringLiteral("servers"), err);
    if (!page)
        return {};
    const QVariantList list = shownServerRows(page);
    const int rowNo = args.value(QStringLiteral("row")).toInt(0);
    const QString id = args.value(QStringLiteral("id")).toString();
    const QString name = args.value(QStringLiteral("name")).toString();
    int at = -1;
    for (int i = 0; i < list.size() && at < 0; ++i) {
        const QVariantMap e = list.at(i).toMap();
        const QString key = e.value(QStringLiteral("key")).toString();
        const QString nodeId = e.value(QStringLiteral("nodeId")).toString();
        if ((rowNo > 0 && rowNo == i + 1)
            || (!id.isEmpty() && (id == ref(key) || id == QStringLiteral("ref:") + ref(key) || id == publicId(nodeId)))
            || (!name.isEmpty() && name.compare(e.value(QStringLiteral("name")).toString(), Qt::CaseInsensitive) == 0))
            at = i;
    }
    if (at < 0) {
        *err = QStringLiteral("no_such_row (see `servers`)");
        return {};
    }
    const QVariantMap e = list.at(at).toMap();
    QString picks;
    if (QObject *eng = engine())
        for (const QVariant &v : prop(eng, "nodePool").toList())
            if (v.toMap().value(QStringLiteral("nodeId")).toString() == e.value(QStringLiteral("nodeId")).toString())
                picks = v.toMap().value(QStringLiteral("proto"), QStringLiteral("awg")).toString();
    const QString kind = args.value(QStringLiteral("kind")).toString();
    if (!kind.isEmpty() && (e.value(QStringLiteral("modeOnly")).toBool() || picks != kind)) {
        // a row picks the best node of its location for the current mode: another transport needs the mode first
        *err = QStringLiteral("kind_not_picked: the row takes ") + (picks.isEmpty() ? QStringLiteral("?") : picks)
            + QStringLiteral(" in mode ") + prop(page, "transportMode").toString() + QStringLiteral("; send mode {\"value\":\"")
            + kind + QStringLiteral("\"} first");
        return {};
    }
    QVariant outcome;
    if (!js(page, "tapRow", {QVariant(e)}, &outcome, err))
        return {};
    return {{QStringLiteral("tapped"), outcome.toString()}, {QStringLiteral("row"), at + 1},
            {QStringLiteral("name"), redact(e.value(QStringLiteral("name")).toString())}, {QStringLiteral("picks"), picks},
            {QStringLiteral("after"), stateBrief()}};
}

QJsonObject App::cmdAuto(QString *err)
{
    QObject *page = showPage(QStringLiteral("servers"), err);
    if (!page)
        return {};
    QVariant outcome;
    if (!js(page, "tapAuto", {}, &outcome, err))
        return {};
    return {{QStringLiteral("tapped"), outcome.toString()}, {QStringLiteral("after"), stateBrief()}};
}

QJsonObject App::cmdMode(const QJsonObject &args, QString *err)
{
    const QString value = args.value(QStringLiteral("value")).toString();
    if (value != QLatin1String("auto") && value != QLatin1String("awg") && value != QLatin1String("xray")) {
        *err = QStringLiteral("bad_value: auto | awg | xray");
        return {};
    }
    QObject *page = showPage(QStringLiteral("servers"), err);
    if (!page)
        return {};
    const QString before = prop(page, "transportMode").toString();
    QVariant outcome;
    if (!js(page, "tapMode", {value}, &outcome, err))
        return {};
    return {{QStringLiteral("tapped"), outcome.toString()}, {QStringLiteral("mode_before"), before},
            {QStringLiteral("mode_after"), prop(page, "transportMode").toString()}};
}

// ---- Scanner -----------------------------------------------------------------------------------------------------

// The Scanner page on the screen (null when another page is shown) and its one pinned button (TribeScanBar: the page's
// `scannerBar`, its button `scannerActionButton`).
static QObject *scanBarOf(QObject *sp)
{
    return sp ? sp->findChild<QObject *>(QStringLiteral("scannerBar")) : nullptr;
}

static QJsonObject scanPaneOf(QObject *sp)
{
    if (!sp)
        return {};
    return {{QStringLiteral("pane"), prop(sp, "pane").toString()},
            {QStringLiteral("selected"), prop(sp, "selected").toString()},
            {QStringLiteral("action"), prop(sp, "chooseAction").toString()}};
}

QJsonObject App::cmdScanOpen(QString *err)
{
    if (!showPage(QStringLiteral("scanner"), err))
        return {};
    QObject *s = scanner(err);
    if (!s)
        return {};
    QJsonObject r{{QStringLiteral("page"), currentPageName()}, {QStringLiteral("screen_open"), prop(s, "screenOpen").toBool()},
                  {QStringLiteral("phase"), scanView().value(QStringLiteral("phase")).toString()}};
    const QJsonObject pane = scanPaneOf(currentPage());
    for (auto it = pane.constBegin(); it != pane.constEnd(); ++it)
        r.insert(it.key(), it.value());
    return r;
}

// A scope row of the choice: the selection only (PageScannerTribe select(scope), as the row's tap) - nothing scans until
// the button (scan.start).
QJsonObject App::cmdScanSelect(const QJsonObject &args, QString *err)
{
    QObject *s = scanner(err);
    if (!s)
        return {};
    QObject *sp = currentPageName() == QLatin1String("PageScannerTribe") ? currentPage() : nullptr;
    if (!prop(s, "screenOpen").toBool() || !sp) {
        *err = QStringLiteral("scanner_closed: send scan.open first");
        return {};
    }
    if (!prop(sp, "choosing").toBool()) {
        *err = QStringLiteral("not_choosing: a result is on the screen (scan.back shows the choice)");
        return {};
    }
    const QString scope = args.value(QStringLiteral("scope")).toString();
    const QVariantMap v = scanView();
    const QVariantMap bar = v.value(QStringLiteral("bar")).toMap();
    // the rows the choice lists: «Все страны», «Белые списки» while the pool has them, a country of the pool
    bool known = scope.isEmpty() || (scope == QLatin1String("whitelist") && bar.value(QStringLiteral("scope_whitelist")).toInt() > 0);
    for (const QVariant &c : bar.value(QStringLiteral("scope_countries")).toList())
        known = known || c.toMap().value(QStringLiteral("cc")).toString() == scope;
    if (!known) {
        *err = QStringLiteral("unknown_scope: \"\" (all), \"whitelist\" or a country of the pool (scan.rows: scopes)");
        return {};
    }
    if (!js(sp, "select", {scope}, nullptr, err))
        return {};
    bool fresh = false; // view.slots: this network's fresh result of the scope (the button may then show it)
    for (const QVariant &sl : v.value(QStringLiteral("slots")).toList())
        fresh = fresh || sl.toMap().value(QStringLiteral("scope")).toString() == scope;
    QJsonObject r = scanPaneOf(sp);
    r.insert(QStringLiteral("scope"), scope);
    r.insert(QStringLiteral("fresh"), fresh);
    r.insert(QStringLiteral("phase"), scanView().value(QStringLiteral("phase")).toString());
    return r;
}

// The one pinned button, pressed for what it says now (TribeScanBar action(): the choice - scan / show / connect the
// selected scope; the result - retry / connect; «Остановить» is scan.stop) and only while it is enabled, as a finger
// would; the press itself is the bar's fire(action), the button's own call.
QJsonObject App::cmdScanStart(QString *err)
{
    QObject *s = scanner(err);
    if (!s)
        return {};
    QObject *sp = currentPageName() == QLatin1String("PageScannerTribe") ? currentPage() : nullptr;
    if (!prop(s, "screenOpen").toBool() || !sp) {
        *err = QStringLiteral("scanner_closed: send scan.open first");
        return {};
    }
    QObject *sb = scanBarOf(sp);
    if (!sb || !prop(sb, "visible").toBool()) {
        *err = QStringLiteral("no_button: the screen shows no bar (a blocked or empty state has its own action)");
        return {};
    }
    QVariant a;
    if (!js(sb, "action", {}, &a, err))
        return {};
    const QString action = a.toString();
    if (action == QLatin1String("stop")) {
        *err = QStringLiteral("scanning: the button says «Остановить» (scan.stop)");
        return {};
    }
    QObject *button = sb->findChild<QObject *>(QStringLiteral("scannerActionButton"));
    if (!button || !prop(button, "enabled").toBool()) {
        *err = QStringLiteral("button_disabled: ") + action + QStringLiteral(" (") + prop(sb, "kind").toString()
            + QStringLiteral(", ") + QString::number(prop(sb, "remaining").toInt()) + QStringLiteral(" left)");
        return {};
    }
    const bool choosing = prop(sp, "choosing").toBool();
    if (!js(sb, "fire", {action}, nullptr, err))
        return {};
    QJsonObject r = scanPaneOf(sp);
    r.insert(QStringLiteral("pressed"), action);
    r.insert(QStringLiteral("from"), choosing ? QStringLiteral("choice") : QStringLiteral("result"));
    r.insert(QStringLiteral("phase"), scanView().value(QStringLiteral("phase")).toString());
    return r;
}

// «Остановить»: the same button while it says so.
QJsonObject App::cmdScanStop(QString *err)
{
    QObject *s = scanner(err);
    if (!s)
        return {};
    QObject *sp = currentPageName() == QLatin1String("PageScannerTribe") ? currentPage() : nullptr;
    if (!prop(s, "screenOpen").toBool() || !sp) {
        *err = QStringLiteral("scanner_closed: send scan.open first");
        return {};
    }
    QObject *sb = scanBarOf(sp);
    const QJsonObject notStopped{{QStringLiteral("stopped"), false},
                                 {QStringLiteral("phase"), scanView().value(QStringLiteral("phase")).toString()}};
    if (!sb || !prop(sb, "visible").toBool())
        return notStopped;
    QVariant a;
    if (!js(sb, "action", {}, &a, err))
        return {};
    if (a.toString() != QLatin1String("stop"))
        return notStopped;
    if (!js(sb, "fire", {QStringLiteral("stop")}, nullptr, err))
        return {};
    QJsonObject r = scanPaneOf(sp);
    r.insert(QStringLiteral("stopped"), true);
    r.insert(QStringLiteral("phase"), scanView().value(QStringLiteral("phase")).toString());
    return r;
}

QJsonObject App::cmdScanRows(QString *err)
{
    QObject *s = scanner(err);
    if (!s)
        return {};
    const QVariantMap v = scanView();
    QJsonArray rows;
    const QVariantList list = v.value(QStringLiteral("rows")).toList();
    for (int i = 0; i < list.size(); ++i) {
        const QVariantMap r = list.at(i).toMap();
        QJsonArray flags;
        for (const QVariant &f : r.value(QStringLiteral("flags")).toList())
            flags << f.toString();
        rows << QJsonObject{{QStringLiteral("row"), i + 1},
                            {QStringLiteral("ref"), ref(r.value(QStringLiteral("id")).toString())},
                            {QStringLiteral("id"), publicId(r.value(QStringLiteral("id")).toString())},
                            {QStringLiteral("name"), redact(r.value(QStringLiteral("label")).toString())},
                            {QStringLiteral("country"), r.value(QStringLiteral("cc")).toString()},
                            {QStringLiteral("kind"), r.value(QStringLiteral("transport")).toString()},
                            {QStringLiteral("status"), r.value(QStringLiteral("state")).toString()},
                            {QStringLiteral("speed"), r.value(QStringLiteral("speed")).toString()},
                            {QStringLiteral("bars"), scalar(r.value(QStringLiteral("bars")))},
                            {QStringLiteral("latency_ms"), scalar(r.value(QStringLiteral("ms")))},
                            {QStringLiteral("flags"), flags}};
    }
    QJsonArray slotsOut;
    for (const QVariant &sl : v.value(QStringLiteral("slots")).toList()) {
        const QVariantMap m = sl.toMap();
        slotsOut << QJsonObject{{QStringLiteral("scope"), m.value(QStringLiteral("scope")).toString()},
                                {QStringLiteral("works"), m.value(QStringLiteral("works")).toInt()},
                                {QStringLiteral("ago_min"), m.value(QStringLiteral("ago_min")).toInt()},
                                {QStringLiteral("partial"), m.value(QStringLiteral("partial")).toBool()}};
    }
    QJsonArray scopes;
    const QVariantMap bar = v.value(QStringLiteral("bar")).toMap();
    for (const QVariant &c : bar.value(QStringLiteral("scope_countries")).toList())
        scopes << QJsonObject{{QStringLiteral("scope"), c.toMap().value(QStringLiteral("cc")).toString()},
                              {QStringLiteral("count"), c.toMap().value(QStringLiteral("count")).toInt()}};
    if (bar.value(QStringLiteral("scope_whitelist")).toInt() > 0)
        scopes << QJsonObject{{QStringLiteral("scope"), QStringLiteral("whitelist")},
                              {QStringLiteral("count"), bar.value(QStringLiteral("scope_whitelist")).toInt()}};
    const QString phase = v.value(QStringLiteral("phase")).toString();
    QJsonObject r{{QStringLiteral("rows"), rows}, {QStringLiteral("phase"), phase},
                  {QStringLiteral("scanning"), scanningPhase(phase)},
                  {QStringLiteral("verified"), v.value(QStringLiteral("verified")).toInt()},
                  {QStringLiteral("unverified"), v.value(QStringLiteral("unverified")).toInt()},
                  // the rings' number (view.available) and the stopped scan's mark (view.partial)
                  {QStringLiteral("available"), v.value(QStringLiteral("available")).toInt()},
                  {QStringLiteral("partial"), v.value(QStringLiteral("partial")).toBool()},
                  {QStringLiteral("scope"), bar.value(QStringLiteral("scope")).toString()},
                  {QStringLiteral("scopes"), scopes}, {QStringLiteral("slots"), slotsOut},
                  {QStringLiteral("screen_open"), prop(s, "screenOpen").toBool()}};
    if (currentPageName() == QLatin1String("PageScannerTribe")) {
        const QJsonObject pane = scanPaneOf(currentPage());
        for (auto it = pane.constBegin(); it != pane.constEnd(); ++it)
            r.insert(it.key(), it.value());
    }
    return r;
}

QJsonObject App::cmdScanConnect(const QJsonObject &args, QString *err)
{
    QObject *s = scanner(err);
    if (!s)
        return {};
    if (!prop(s, "screenOpen").toBool()) {
        *err = QStringLiteral("scanner_closed: send scan.open first");
        return {};
    }
    const QVariantList list = scanView().value(QStringLiteral("rows")).toList();
    const int rowNo = args.value(QStringLiteral("row")).toInt(0);
    const QString wantRef = args.value(QStringLiteral("ref")).toString();
    int at = -1;
    for (int i = 0; i < list.size() && at < 0; ++i) {
        const QString id = list.at(i).toMap().value(QStringLiteral("id")).toString();
        if ((rowNo > 0 && rowNo == i + 1 && (wantRef.isEmpty() || wantRef == ref(id))) || (rowNo <= 0 && wantRef == ref(id)))
            at = i;
    }
    if (at < 0) {
        *err = rowNo > 0 && rowNo <= list.size() ? QStringLiteral("row_changed: the row is another server now (scan.rows)")
                                                 : QStringLiteral("no_such_row (see scan.rows)");
        return {};
    }
    const QVariantMap r = list.at(at).toMap();
    for (const QVariant &f : r.value(QStringLiteral("flags")).toList())
        if (f.toString() == QLatin1String("not_tappable")) { // TribeScanRow: enabled: tappable
            *err = QStringLiteral("not_tappable");
            return {};
        }
    if (!cpp(s, "tapRow", {r.value(QStringLiteral("id")).toString()}, err))
        return {};
    return {{QStringLiteral("row"), at + 1}, {QStringLiteral("ref"), ref(r.value(QStringLiteral("id")).toString())},
            {QStringLiteral("name"), redact(r.value(QStringLiteral("label")).toString())}};
}

QJsonObject App::cmdScanBack(QString *err)
{
    if (currentPageName() != QLatin1String("PageScannerTribe")) {
        *err = QStringLiteral("not_on_scanner: ") + currentPageName();
        return {};
    }
    QObject *pc = pages(err);
    if (!pc)
        return {};
    if (!cpp(pc, "keyPressEvent", {QVariant::fromValue(Qt::Key_Escape)}, err)) // the Escape key (main2.qml Keys)
        return {};
    return {{QStringLiteral("page"), currentPageName()}};
}

// ---- window, shot, mark -------------------------------------------------------------------------------------------

QJsonObject App::cmdWindowShow(QString *err)
{
    QObject *pc = pages(err);
    if (!pc)
        return {};
    if (!sig(pc, "raiseMainWindow", {}, err)) // the tray's «Show» (coreSignalHandlers: raiseRequested -> raiseMainWindow)
        return {};
    auto *w = qobject_cast<QWindow *>(window());
    return {{QStringLiteral("visible"), w && w->isVisible()},
            {QStringLiteral("minimized"), w && bool(w->windowStates() & Qt::WindowMinimized)}};
}

QJsonObject App::cmdShot(const QJsonObject &args, QString *err)
{
    auto *w = qobject_cast<QQuickWindow *>(window());
    if (!w) {
        *err = QStringLiteral("not_ready: no main window");
        return {};
    }
    // a relative path under <data dir>/dev/shots: segments of [A-Za-z0-9._-], never "..", ".png" added
    QString rel = args.value(QStringLiteral("path")).toString();
    if (rel.isEmpty())
        rel = QStringLiteral("shot-") + QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMdd-HHmmss-zzz"));
    static const QRegularExpression seg(QStringLiteral("^[A-Za-z0-9._-]{1,80}$"));
    const QStringList parts = rel.split(QLatin1Char('/'));
    for (const QString &p : parts)
        if (!seg.match(p).hasMatch() || p == QLatin1String("..") || p == QLatin1String(".")) {
            *err = QStringLiteral("bad_path: a relative name under dev/shots");
            return {};
        }
    if (parts.size() > 4) {
        *err = QStringLiteral("bad_path: too deep");
        return {};
    }
    if (!rel.endsWith(QLatin1String(".png"), Qt::CaseInsensitive))
        rel += QStringLiteral(".png");
    const QString base = channelDir(m_env.dataDir) + QStringLiteral("/shots");
    const QString path = base + QLatin1Char('/') + rel;
    QDir().mkpath(QFileInfo(path).absolutePath());
    const bool visible = w->isVisible();
    const bool exposed = w->isExposed();
    const bool minimized = bool(w->windowStates() & Qt::WindowMinimized);
    // QQuickWindow renders its own scene: no Screen Recording grant. A hidden or minimised window is rendered
    // offscreen when the scene graph can do it; an empty image means it could not - window.show first.
    const QImage img = w->grabWindow();
    if (img.isNull()) {
        *err = QStringLiteral("grab_failed: the window is not rendered (visible=%1 minimized=%2): send window.show")
                   .arg(visible).arg(minimized);
        return {};
    }
    if (!img.save(path, "PNG")) {
        *err = QStringLiteral("save_failed");
        return {};
    }
    return {{QStringLiteral("path"), path},
            {QStringLiteral("bytes"), double(QFileInfo(path).size())},
            {QStringLiteral("width"), img.width()},
            {QStringLiteral("height"), img.height()},
            {QStringLiteral("visible"), visible},
            {QStringLiteral("exposed"), exposed},
            {QStringLiteral("minimized"), minimized}};
}

QJsonObject App::cmdMark(const QJsonObject &args, QString *err)
{
    QString text = args.value(QStringLiteral("text")).toString();
    if (text.trimmed().isEmpty()) {
        *err = QStringLiteral("bad_text: {\"text\": \"...\"}");
        return {};
    }
    for (QChar &c : text)
        if (c.category() == QChar::Other_Control)
            c = QLatin1Char(' ');
    text = redact(text.left(200));
    if (m_env.log)
        m_env.log(QStringLiteral("[avpn devctl] mark ") + text);
    if (m_env.journal)
        m_env.journal(QStringLiteral("dev_mark"), {{QStringLiteral("text"), text}});
    return {{QStringLiteral("text"), text}, {QStringLiteral("journal"), m_env.journalActive && m_env.journalActive()},
            {QStringLiteral("at"), QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)}};
}

// ---- wait --------------------------------------------------------------------------------------------------------

bool App::wantMet(const QString &what)
{
    if (what == QLatin1String("connected"))
        return face() == QLatin1String("connected");
    if (what == QLatin1String("verified"))
        return verified();
    if (what == QLatin1String("off")) {
        QObject *e = engine();
        return e && face() == QLatin1String("off") && !prop(e, "busy").toBool();
    }
    if (what == QLatin1String("scan_done"))
        return !scanningPhase(scanView().value(QStringLiteral("phase")).toString());
    return false;
}

void App::cmdWait(const QJsonObject &args, QObject *ctx, const Done &done)
{
    const QString what = args.value(QStringLiteral("for")).toString();
    if (what != QLatin1String("connected") && what != QLatin1String("verified") && what != QLatin1String("off")
        && what != QLatin1String("scan_done")) {
        done({}, QStringLiteral("bad_for: connected | verified | off | scan_done"));
        return;
    }
    if (!engine() || (what == QLatin1String("scan_done") && !scanner())) {
        done({}, QStringLiteral("not_ready"));
        return;
    }
    const int timeoutMs = qBound(0, args.value(QStringLiteral("timeout_ms")).toInt(60000), 600000);
    const bool wasScanning = scanningPhase(scanView().value(QStringLiteral("phase")).toString());
    const qint64 t0 = QDateTime::currentMSecsSinceEpoch();
    auto result = [this, what, t0, wasScanning] {
        QJsonObject r = stateBrief();
        r.insert(QStringLiteral("for"), what);
        r.insert(QStringLiteral("after_ms"), double(QDateTime::currentMSecsSinceEpoch() - t0));
        if (what == QLatin1String("scan_done"))
            r.insert(QStringLiteral("was_scanning"), wasScanning);
        return r;
    };
    if (wantMet(what)) {
        done(result(), QString());
        return;
    }
    // signals, not polling: the engine's changed() / dataFlowingChanged() and the Scanner's viewChanged(); all of it
    // lives on ctx, which the server deletes when the client leaves
    auto *timer = new QTimer(ctx);
    auto *relay = new Relay(ctx);
    relay->fn = [this, what, timer, done, result] {
        if (!wantMet(what))
            return;
        timer->stop();
        done(result(), QString());
    };
    QObject *e = engine();
    connect(e, SIGNAL(changed()), relay, SLOT(fire()));
    if (e->metaObject()->indexOfSignal("dataFlowingChanged()") >= 0)
        connect(e, SIGNAL(dataFlowingChanged()), relay, SLOT(fire()));
    if (QObject *s = scanner())
        connect(s, SIGNAL(viewChanged()), relay, SLOT(fire()));
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, relay, [this, what, timeoutMs, done] {
        done({}, QStringLiteral("timeout: %1 not reached in %2 ms (state=%3 face=%4)")
                     .arg(what).arg(timeoutMs).arg(stateBrief().value(QStringLiteral("state")).toString(), face()));
    });
    timer->start(timeoutMs);
}

// ---- quit --------------------------------------------------------------------------------------------------------

void App::cmdQuit(const Done &done)
{
    done({{QStringLiteral("quitting"), true}}, QString());
    // after the reply is out: the same QCoreApplication::quit() as the tray's «Quit»
    QTimer::singleShot(200, this, [this] {
        if (m_env.quit)
            m_env.quit();
    });
}

} // namespace avpn::devctl

#include "DevControlApp.moc"
