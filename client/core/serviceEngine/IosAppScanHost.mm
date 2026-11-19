// client/core/serviceEngine/IosAppScanHost.mm
// AVPN serviceEngine - IosHybridScanHost (IosAppScanHost.h): the Scanner's probe engine called in the APP process,
// next to the extension's host (IosScanHost), routed per scan. Compiled for iOS only and only with the CMake option
// AVPN_IOS_APP_SCAN_HOST (client/cmake/avpn.cmake). MRC like the other platform .mm files of the app.
//
// The engine is the Go package tribescan inside awg-apple's libwg-go.a (patch 0013, ABI libxray-tribe-scan-v1), the
// same archive the extension links; the app target links it too (client/cmake/ios.cmake), and this file is the
// first app code that references it, so the app binary gets exactly one Go runtime (no other Go archive is linked
// into the app: the Android two-runtime crash, BUG-21, has no iOS counterpart). Calls block (a replacing scan_start
// up to 3 s, scan_cancel up to 2 s), so they run on a private concurrent queue; replies come back on the GUI thread.
//
// Nothing here touches the tunnel: no connect, no stop, no route, no protector of the tunnel. Probe sockets are
// bound by the engine itself to the app path's physical interface (IP_BOUND_IF / IPV6_BOUND_IF).
//
// Upstream Amnezia has no counterpart.
#include "IosAppScanHost.h"

#include "IosScanHost.h"
#include "TribeJournal.h"
#include "TribeScanner.h"

#include "platforms/ios/ios_controller.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QGuiApplication>
#include <QHash>
#include <QJsonArray>
#include <QVariantMap>
#include <QPointer>
#include <QStandardPaths>
#include <QTimer>

#include <atomic>
#include <mutex>

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <os/proc.h>
#include <stdlib.h>

extern "C" {
// awg-apple wireguard.h (patch 0013): malloc'd JSON, never NULL; free() it.
char *LibXrayTribeScanMessage(const char *messageJSON, const char *hostOptionsJSON);
}

namespace avpn {

namespace {

double footprintMb()
{
    task_vm_info_data_t info;
    mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) != KERN_SUCCESS)
        return -1;
    return double(info.phys_footprint) / (1024.0 * 1024.0);
}

double availableMb() { return double(os_proc_available_memory()) / (1024.0 * 1024.0); }

dispatch_queue_t engineQueue()
{
    static dispatch_queue_t q = dispatch_queue_create("org.tribe.scan.app-engine", DISPATCH_QUEUE_CONCURRENT);
    return q;
}

// One call of the engine on the private queue; `done` once on the GUI thread: the reply, or an empty one after
// boundMs (a late reply is dropped).
void callEngine(const QByteArray &request, const QByteArray &options, int boundMs, std::function<void(const QByteArray &)> done)
{
    auto answered = std::make_shared<std::atomic<bool>>(false);
    QCoreApplication *app = QCoreApplication::instance();
    QTimer::singleShot(boundMs, app, [answered, done]() {
        if (!answered->exchange(true)) {
            qWarning() << "IosHybridScanHost: no answer from the in-app engine within the bound";
            done(QByteArray());
        }
    });
    const QByteArray req = request;
    const QByteArray opts = options;
    dispatch_async(engineQueue(), ^{
        char *raw = LibXrayTribeScanMessage(req.constData(), opts.isEmpty() ? nullptr : opts.constData());
        QByteArray bytes;
        if (raw) {
            bytes = QByteArray(raw);
            free(raw);
        }
        QMetaObject::invokeMethod(
            app,
            [answered, done, bytes]() {
                if (!answered->exchange(true))
                    done(bytes);
            },
            Qt::QueuedConnection);
    });
}

bool appInFront()
{
    const Qt::ApplicationState st = QGuiApplication::applicationState();
    return st != Qt::ApplicationSuspended && st != Qt::ApplicationHidden;
}

bool tunnelDownState(Vpn::ConnectionState st) { return st == Vpn::Disconnected || st == Vpn::Error; }

// The measurement journal: Documents/tribe-app-probe.jsonl + TribeJournal (event "app_probe") + the Qt log.
void record(QJsonObject o)
{
    o.insert(QStringLiteral("ts"), QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs));
    const QByteArray line = QJsonDocument(o).toJson(QJsonDocument::Compact);
#ifdef AVPN_DEV_TOOLS // the results file in Documents is a development aid: a release build never writes it
    static std::mutex lock;
    {
        std::lock_guard<std::mutex> g(lock);
        QFile f(IosHybridScanHost::resultsPath());
        if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
            f.write(line);
            f.write("\n");
        }
    }
#endif
    TribeJournal::append(QStringLiteral("app_probe"), o);
    qInfo().noquote() << "app_probe" << QString::fromUtf8(line);
}

} // namespace

QString IosHybridScanHost::controlPath()
{
    return QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + QStringLiteral("/tribe-app-probe.json");
}

QString IosHybridScanHost::resultsPath()
{
    return QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + QStringLiteral("/tribe-app-probe.jsonl");
}

IosAppScanControl IosHybridScanHost::readControl()
{
#ifndef AVPN_DEV_TOOLS
    return IosAppScanControl(); // a release build never reads the control file: mode always, no autorun
#endif
    QFile f(controlPath());
    if (!f.open(QIODevice::ReadOnly))
        return IosAppScanControl(); // no file: mode always, no autorun
    return iosAppScanControlFrom(f.read(4096));
}

struct IosHybridScanHost::State
{
    IosHybridScanHost *host = nullptr;
    QObject context;
    IosAppScanMode mode = IosAppScanMode::Always;
    bool awgBesideTunnelRefuse = false;
    bool noLegs = false;
    std::unique_ptr<IosScanHost> ext;
    IosAppScanRoutes routes;
    quint64 epoch = 1;          // host_epoch of the app engine: moves on every stop-all (stale starts are refused)
    bool startedAny = false;    // a start ever reached the app engine
    bool tunnelDown = true;
    struct Journal {
        QElapsedTimer t0;
        QList<QPair<QString, QString>> kinds;
        bool proven = false;
    };
    QHash<QString, Journal> journal; // per app scan (bounded by routes: the last 8)

    IosAppScanState snapshot() const
    {
        IosAppScanState s;
        s.mode = mode;
        s.tunnelDown = tunnelDown;
        s.extensionRunning = IosController::Instance()->scanHostRunning();
        s.foreground = appInFront();
        bool sat = false;
        s.bindIndex = IosScanHost::appBindInterfaceIndex(&sat);
        s.pathSatisfied = sat;
        s.awgBesideTunnelRefuse = awgBesideTunnelRefuse;
        const int own = IosController::Instance()->ownStartLivePeer(nullptr);
        s.livePeer = own == 2 ? IosLivePeer::Known : own == 1 ? IosLivePeer::NotAwg : IosLivePeer::Unknown;
        return s;
    }

    QByteArray options(bool withBind) const
    {
        ScanNetSource g;
        const bool hasGen = IosScanHost::appGeneration(g);
        // beside a tunnel this process started: its AmneziaWG peer with every message (the engine keeps awg_mini off it)
        QJsonObject peer;
        if (!tunnelDown && IosController::Instance()->ownStartLivePeer(&peer) != 2)
            peer = QJsonObject();
        return iosAppScanHostOptions(withBind ? IosScanHost::appBindInterfaceIndex() : 0, hasGen, g, epoch, peer);
    }

    void stopApp(const QString &reason)
    {
        ++epoch;
        if (!startedAny)
            return;
        record(QJsonObject{{QStringLiteral("ev"), QStringLiteral("stop_all")},
                           {QStringLiteral("reason"), reason},
                           {QStringLiteral("epoch"), double(epoch)}});
        const QByteArray opts = QByteArrayLiteral("{\"host_epoch\":") + QByteArray::number(epoch) + "}";
        callEngine(QByteArrayLiteral("{\"action\":\"scan_stop_all\",\"wait_ms\":2000}"), opts, 3000,
                   [reason](const QByteArray &reply) {
                       record(QJsonObject{{QStringLiteral("ev"), QStringLiteral("stop_all_reply")},
                                          {QStringLiteral("reason"), reason},
                                          {QStringLiteral("stopped"),
                                           QJsonDocument::fromJson(reply).object().value(QLatin1String("stopped")).toBool(false)}});
                   });
    }
};

IosHybridScanHost::IosHybridScanHost() : m_state(std::make_shared<State>())
{
    State &s = *m_state;
    s.host = this;
    const IosAppScanControl control = readControl();
    s.mode = control.mode;
    s.awgBesideTunnelRefuse = control.awgBesideTunnelRefuse;
    s.noLegs = control.noLegs;
    s.ext = std::make_unique<IosScanHost>(); // also starts the app path monitor
    s.tunnelDown = !IosController::Instance()->scanHostRunning();
    const std::weak_ptr<State> weak = m_state;
    s.ext->onAvailabilityChanged = [weak]() {
        const auto st = weak.lock();
        if (st && st->host && st->mode == IosAppScanMode::Off && st->host->onAvailabilityChanged)
            st->host->onAvailabilityChanged();
    };
    s.ext->onGenerationChanged = [weak]() {
        const auto st = weak.lock();
        if (st && st->host && st->mode == IosAppScanMode::Off && st->host->onGenerationChanged)
            st->host->onGenerationChanged();
    };
    QObject::connect(IosController::Instance(), &IosController::connectionStateChanged, &s.context,
                     [weak](Vpn::ConnectionState state) {
                         const auto st = weak.lock();
                         if (!st)
                             return;
                         const bool down = tunnelDownState(state);
                         if (down == st->tunnelDown)
                             return;
                         st->tunnelDown = down;
                         record(QJsonObject{{QStringLiteral("ev"), QStringLiteral("tunnel")},
                                            {QStringLiteral("down"), down},
                                            {QStringLiteral("state"), int(state)}});
                         if (!down && iosAppScanStopOnTunnelUp(st->mode) && st->routes.anyApp())
                             st->stopApp(QStringLiteral("tunnel_up"));
                     });
    if (auto *gui = qobject_cast<QGuiApplication *>(QCoreApplication::instance())) {
        QObject::connect(gui, &QGuiApplication::applicationStateChanged, &s.context, [weak](Qt::ApplicationState state) {
            const auto st = weak.lock();
            if (!st || st->mode == IosAppScanMode::Off)
                return;
            if ((state == Qt::ApplicationSuspended || state == Qt::ApplicationHidden) && st->routes.anyApp())
                st->stopApp(QStringLiteral("background"));
        });
    }
    bool sat = false;
    const unsigned bind = IosScanHost::appBindInterfaceIndex(&sat);
    record(QJsonObject{{QStringLiteral("ev"), QStringLiteral("host")},
                       {QStringLiteral("mode"), QLatin1String(iosAppScanModeName(s.mode))},
                       {QStringLiteral("tunnel_down"), s.tunnelDown},
                       {QStringLiteral("bind_if"), double(bind)},
                       {QStringLiteral("path_ok"), sat},
                       {QStringLiteral("footprint_mb"), footprintMb()},
                       {QStringLiteral("avail_mb"), availableMb()}});
    if (s.mode != IosAppScanMode::Off) {
        // The first engine call of the process: proves the Go export is callable in the app and how long it takes.
        QElapsedTimer t;
        t.start();
        callEngine(scanCompact(scanEncodeCaps()), s.options(false), 2000, [t](const QByteArray &reply) {
            record(QJsonObject{{QStringLiteral("ev"), QStringLiteral("engine_caps")},
                               {QStringLiteral("ms"), double(t.elapsed())},
                               {QStringLiteral("reply"), QString::fromUtf8(iosAppScanDecorateCaps(reply)).left(600)},
                               {QStringLiteral("footprint_mb"), footprintMb()}});
        });
    }
}

IosHybridScanHost::~IosHybridScanHost() { m_state->host = nullptr; }

ScanHostCaps IosHybridScanHost::knownCaps() const
{
    return m_state->mode == IosAppScanMode::Off ? iosScanKnownCaps() : iosAppScanKnownCaps();
}

ScanHostAvailability IosHybridScanHost::availability() const
{
    // The app engine runs whenever the app does.
    return m_state->mode == IosAppScanMode::Off ? m_state->ext->availability() : ScanHostAvailability::Available;
}

QString IosHybridScanHost::unavailableReason() const
{
    return m_state->mode == IosAppScanMode::Off ? m_state->ext->unavailableReason() : QString();
}

bool IosHybridScanHost::generation(ScanNetSource &out) const
{
    // In-app: the engine is stamped with the app's own element, which the coordinator's tuple already has.
    return m_state->mode == IosAppScanMode::Off ? m_state->ext->generation(out) : false;
}

void IosHybridScanHost::stopAll()
{
    m_state->stopApp(QStringLiteral("app"));
    m_state->ext->stopAll();
}

void IosHybridScanHost::sendMessage(const QByteArray &request, ReplyFn reply)
{
    if (!reply)
        return;
    State &s = *m_state;
    if (s.mode == IosAppScanMode::Off) {
        s.ext->sendMessage(request, std::move(reply));
        return;
    }
    const IosAppScanRequestFacts f = iosAppScanRequestFacts(request);
    const int bound = iosScanReplyTimeoutMs(request);
    auto queued = [this](const QByteArray &bytes, ReplyFn r) {
        QTimer::singleShot(0, &m_state->context, [bytes, r]() { r(bytes); });
    };
    const std::weak_ptr<State> weak = m_state;

    if (f.action == QLatin1String("scan_caps")) {
        const bool noLegs = s.noLegs;
        callEngine(request, s.options(false), bound,
                   [reply, noLegs](const QByteArray &bytes) { reply(iosAppScanDecorateCaps(bytes, noLegs)); });
        return;
    }

    IosAppScanRoute route;
    if (f.action == QLatin1String("scan_start")) {
        const IosAppScanState st = s.snapshot();
        route = iosAppScanRouteStart(st, f.hasAwgMini);
        s.routes.set(f.scanId, route);
        QHash<QString, int> kinds;
        for (const auto &c : f.candidates)
            ++kinds[c.second];
        QJsonObject k;
        for (auto it = kinds.constBegin(); it != kinds.constEnd(); ++it)
            k.insert(it.key(), it.value());
        record(QJsonObject{{QStringLiteral("ev"), QStringLiteral("start")},
                           {QStringLiteral("scan"), f.scanId},
                           {QStringLiteral("route"), QLatin1String(iosAppScanRouteName(route))},
                           {QStringLiteral("mode"), QLatin1String(iosAppScanModeName(s.mode))},
                           {QStringLiteral("tunnel_down"), st.tunnelDown},
                           {QStringLiteral("ext_running"), st.extensionRunning},
                           {QStringLiteral("bind_if"), double(st.bindIndex)},
                           {QStringLiteral("kinds"), k},
                           {QStringLiteral("footprint_mb"), footprintMb()},
                           {QStringLiteral("avail_mb"), availableMb()}});
        if (route == IosAppScanRoute::App) {
            s.startedAny = true;
            State::Journal j;
            j.t0.start();
            j.kinds = f.candidates;
            s.journal.insert(f.scanId, j);
            while (s.journal.size() > 8)
                s.journal.erase(s.journal.begin());
        }
    } else {
        route = s.routes.of(f.scanId, s.mode);
        if (route == IosAppScanRoute::App && f.action == QLatin1String("scan_add")) {
            const IosAppScanState st = s.snapshot();
            if (iosAppScanAddRefusedAwg(st, f.hasAwgMini)) {
                queued(iosAppScanLivePeerUnknownReply(), std::move(reply));
                return;
            }
            auto it = s.journal.find(f.scanId);
            if (it != s.journal.end())
                it->kinds << f.candidates;
        }
    }

    switch (route) {
    case IosAppScanRoute::Extension:
        s.ext->sendMessage(request, std::move(reply));
        return;
    case IosAppScanRoute::RefuseLivePeerUnknown:
        queued(iosAppScanLivePeerUnknownReply(), std::move(reply));
        return;
    case IosAppScanRoute::RefuseNoPath:
        queued(iosAppScanNoPathReply(), std::move(reply));
        return;
    case IosAppScanRoute::App:
        break;
    }
    const bool isStart = f.action == QLatin1String("scan_start");
    const QString scanId = f.scanId;
    callEngine(request, s.options(isStart), bound, [weak, reply, scanId](const QByteArray &bytes) {
        if (const auto st = weak.lock()) {
            auto it = st->journal.find(scanId);
            if (it != st->journal.end()) {
                const qint64 since = it->t0.elapsed();
                const QJsonObject top = QJsonDocument::fromJson(bytes).object();
                if (top.contains(QLatin1String("error")) || top.value(QLatin1String("type")).toString() != QLatin1String("scan_progress"))
                    record(QJsonObject{{QStringLiteral("ev"), QStringLiteral("reply")},
                                       {QStringLiteral("scan"), scanId},
                                       {QStringLiteral("t_ms"), double(since)},
                                       {QStringLiteral("type"), top.value(QLatin1String("type")).toString()},
                                       {QStringLiteral("error"), top.value(QLatin1String("error")).toString()},
                                       {QStringLiteral("detail"), top.value(QLatin1String("detail")).toString()}});
                for (QJsonObject o : iosAppScanProgressRecords(bytes, since, it->kinds)) {
                    if (!it->proven && iosAppScanItemProven(o)) {
                        it->proven = true;
                        record(QJsonObject{{QStringLiteral("ev"), QStringLiteral("first_proven")},
                                           {QStringLiteral("scan"), scanId},
                                           {QStringLiteral("t_ms"), double(since)},
                                           {QStringLiteral("id"), o.value(QLatin1String("id"))},
                                           {QStringLiteral("kind"), o.value(QLatin1String("kind"))}});
                    }
                    if (o.value(QLatin1String("ev")).toString() == QLatin1String("progress"))
                        o.insert(QStringLiteral("footprint_mb"), footprintMb());
                    record(o);
                }
            }
        }
        reply(bytes);
    });
}

// --- debug autorun (control file autorun_s > 0) -------------------------------------------------------------------

void IosHybridScanHost::installAutorun(TribeScanner *scanner)
{
    const IosAppScanControl c = readControl();
    record(QJsonObject{{QStringLiteral("ev"), QStringLiteral("autorun_armed")},
                       {QStringLiteral("autorun_s"), c.autorunS},
                       {QStringLiteral("mode"), QLatin1String(iosAppScanModeName(c.mode))}});
    if (c.autorunS <= 0 || !scanner)
        return;
    QPointer<TribeScanner> sc(scanner);
    auto tries = std::make_shared<int>(0);
    auto attempt = std::make_shared<std::function<void()>>();
    *attempt = [sc, tries, attempt, c]() {
        if (!sc)
            return;
        if ((!sc->enabled() || !appInFront()) && ++*tries < 60) { // wait for /v1/config and the front, up to 2 min
            QTimer::singleShot(2000, sc.data(), *attempt);
            return;
        }
        record(QJsonObject{{QStringLiteral("ev"), QStringLiteral("autorun_open")},
                           {QStringLiteral("enabled"), sc->enabled()},
                           {QStringLiteral("front"), appInFront()},
                           {QStringLiteral("waited_tries"), *tries}});
        sc->open(false);
        // The view's 1.14.0 parts at each step (the scope menu, more.state, counts) into the measurement journal.
        auto snapshot = [sc](const char *when) {
            if (!sc)
                return;
            const QVariantMap v = sc->view();
            const QVariantMap bar = v.value(QStringLiteral("bar")).toMap();
            record(QJsonObject{{QStringLiteral("ev"), QStringLiteral("autorun_view")},
                               {QStringLiteral("when"), QLatin1String(when)},
                               {QStringLiteral("phase"), v.value(QStringLiteral("phase")).toString()},
                               {QStringLiteral("verified"), v.value(QStringLiteral("verified")).toInt()},
                               {QStringLiteral("unverified"), v.value(QStringLiteral("unverified")).toInt()},
                               {QStringLiteral("batch"), v.value(QStringLiteral("batch")).toInt()},
                               {QStringLiteral("more"), QJsonObject::fromVariantMap(v.value(QStringLiteral("more")).toMap())},
                               {QStringLiteral("scope_countries"), QJsonArray::fromVariantList(bar.value(QStringLiteral("scope_countries")).toList())},
                               {QStringLiteral("scope_whitelist"), bar.value(QStringLiteral("scope_whitelist")).toInt()},
                               {QStringLiteral("scanned_scope"), bar.value(QStringLiteral("scanned_scope")).toString()},
                               {QStringLiteral("rows"), v.value(QStringLiteral("rows")).toList().size()}});
        };
        int at = c.stepS;
        if (!c.autorunScope.isEmpty()) {
            QTimer::singleShot(at * 1000, sc.data(), [sc, c, snapshot]() {
                if (!sc)
                    return;
                snapshot("before_scope");
                record(QJsonObject{{QStringLiteral("ev"), QStringLiteral("autorun_scope")}, {QStringLiteral("scope"), c.autorunScope}});
                sc->chooseCountry(c.autorunScope);
                sc->retry();
            });
            at += c.stepS;
        }
        for (int i = 0; i < c.autorunMore; ++i, at += c.stepS)
            QTimer::singleShot(at * 1000, sc.data(), [sc, snapshot]() {
                if (!sc)
                    return;
                snapshot("before_more");
                record(QJsonObject{{QStringLiteral("ev"), QStringLiteral("autorun_more")}});
                sc->findMore();
            });
        const int closeAt = qMax(c.closeAfterS, at + (c.autorunMore > 0 || !c.autorunScope.isEmpty() ? c.stepS : 0));
        QTimer::singleShot(closeAt * 1000, sc.data(), [sc, snapshot]() {
            if (!sc)
                return;
            snapshot("close");
            record(QJsonObject{{QStringLiteral("ev"), QStringLiteral("autorun_close")}});
            sc->close();
        });
    };
    QTimer::singleShot(c.autorunS * 1000, scanner, *attempt);
}

} // namespace avpn
