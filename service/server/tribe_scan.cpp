// service/server/tribe_scan.cpp - the desktop probe host of the root service (see tribe_scan.h).
#include "tribe_scan.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDebug>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QMetaObject>
#include <QMutexLocker>
#include <QNetworkInterface>
#include <QProcess>
#include <QRandomGenerator>
#include <QSocketNotifier>
#include <QThread>
#include <QTimer>

#include <chrono>

#include <amnezia_xray.h>

#include "core/utils/networkUtilities.h"

#ifdef Q_OS_MACOS
    #include "platforms/macos/daemon/macosfirewall.h"

    #include <cerrno>
    #include <csignal>
    #include <cstring>
    #include <fcntl.h>
    #include <libproc.h>
    #include <net/if.h>
    #include <net/route.h>
    #include <sys/proc.h>
    #include <sys/socket.h>
    #include <sys/sysctl.h>
    #include <unistd.h>
    #include <vector>
#endif

namespace avpn {

namespace {

TribeScanHost *g_host = nullptr; // the service's one host (main thread)

const char kErrJson[] = R"({"error":"bad_request","detail":"json"})";
const char kErrUnknownAction[] = R"({"error":"unknown_action"})";
const char kErrNoUplink[] = R"({"error":"bad_request","detail":"host_options.bind_interface"})";
const char kErrStartRate[] = R"({"error":"rate_limited","detail":"scan_start"})";
const char kErrInternal[] = R"({"error":"internal"})";
const char kErrExemption[] = R"({"error":"internal","detail":"kill_switch_exemption"})";
const char kErrTunnelChanged[] = R"({"error":"tunnel_changed"})";
const char kErrTeardownPending[] = R"({"error":"teardown_pending"})";
const char kErrAwgLivePeerUnknown[] = R"({"error":"internal","detail":"awg_live_peer_unknown"})"; // = the iOS host's

bool plainIfname(const QString &name)
{
    if (name.isEmpty() || name.size() > 15)
        return false;
    for (const QChar c : name) {
        const bool ok = (c >= QLatin1Char('a') && c <= QLatin1Char('z')) || (c >= QLatin1Char('A') && c <= QLatin1Char('Z'))
                        || (c >= QLatin1Char('0') && c <= QLatin1Char('9'));
        if (!ok)
            return false;
    }
    return true;
}

// An id from the client as a log token: plain ids only (the app's are "scan-<ms>-<n>"), nothing else.
QString logId(const QString &id)
{
    if (id.isEmpty() || id.size() > 64)
        return QStringLiteral("-");
    for (const QChar c : id) {
        const bool ok = (c >= QLatin1Char('a') && c <= QLatin1Char('z')) || (c >= QLatin1Char('A') && c <= QLatin1Char('Z'))
                        || (c >= QLatin1Char('0') && c <= QLatin1Char('9')) || c == QLatin1Char('-') || c == QLatin1Char('_')
                        || c == QLatin1Char('.') || c == QLatin1Char(':');
        if (!ok)
            return QStringLiteral("?");
    }
    return id;
}

quint64 randomEpoch()
{
    quint64 e = 0;
    while (e == 0)
        e = QRandomGenerator::system()->generate64();
    return e;
}

qint64 steadyMs()
{
    static QElapsedTimer t = [] {
        QElapsedTimer s;
        s.start();
        return s;
    }();
    return t.elapsed();
}

// --- production dependencies -------------------------------------------------------------------------------

QByteArray engineMessage(const QByteArray &message, const QByteArray &hostOptions)
{
    QByteArray msg = message;     // the C API takes char *: detached copies
    QByteArray opts = hostOptions;
    char *out = amnezia_xray_scan_message(msg.data(), opts.isEmpty() ? nullptr : opts.data());
    if (!out)
        return QByteArray(kErrInternal);
    QByteArray reply(out);
    amnezia_xray_free(out);
    return reply;
}

TribeScanStopResult engineStopAll(int waitMs, qint64 hostEpoch)
{
    // Host-only: never relayed from the app (not one of the six actions).
    const QByteArray msg = QByteArrayLiteral("{\"action\":\"scan_stop_all\",\"wait_ms\":") + QByteArray::number(qMax(0, waitMs)) + "}";
    const QByteArray opts = QByteArrayLiteral("{\"host_epoch\":") + QByteArray::number(qMax<qint64>(0, hostEpoch)) + "}";
    return tribeScanParseStopReply(engineMessage(msg, opts));
}

TribeScanUplink readUplink()
{
    TribeScanUplink u;
    const QPair<QString, QNetworkInterface> gi = NetworkUtilities::getGatewayAndIface();
    const QNetworkInterface &iface = gi.second;
    if (!iface.isValid())
        return u;
    u.name = iface.name();
    u.index = iface.index();
    u.gateway = gi.first;
    const QNetworkInterface::InterfaceFlags f = iface.flags();
    u.up = f.testFlag(QNetworkInterface::IsUp) && f.testFlag(QNetworkInterface::IsRunning);
    u.loopback = f.testFlag(QNetworkInterface::IsLoopBack) || iface.type() == QNetworkInterface::Loopback;
    u.virtualType = iface.type() == QNetworkInterface::Virtual;
    for (const QNetworkAddressEntry &e : iface.addressEntries())
        u.addresses << e.ip().toString();
    return u;
}

#ifdef Q_OS_MACOS
// The service's own amneziawg-go (the one the daemon runs for the live tunnel, wireguardutilsmacos.cpp:94-96),
// checked once per file version (path, size, mtime) - a service update replaces it.
QString checkedServiceAwgProbeBinary()
{
    static QMutex mutex;
    static QString key;
    static QString result;
    const QString path = QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("amneziawg-go"));
    const QFileInfo fi(path);
    const QString now = fi.exists() ? QStringLiteral("%1|%2|%3").arg(path).arg(fi.size()).arg(fi.lastModified().toMSecsSinceEpoch())
                                    : QString();
    QMutexLocker l(&mutex);
    if (now != key) {
        key = now;
        result = now.isEmpty() ? QString() : tribeScanCheckAwgProbeBinary(path, /*requireRootOwned=*/true);
        qInfo() << "[tribescan] awg probe binary" << (result.isEmpty() ? "absent" : "ok");
    }
    return result;
}
#endif

TribeScanKillResult killServiceProbeChildren()
{
#ifdef Q_OS_MACOS
    return tribeScanKillProbeChildren(QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("amneziawg-go")));
#else
    return TribeScanKillResult(); // no AmneziaWG probe children outside macOS
#endif
}

TribeScanAwgLive daemonAwgLive()
{
    TribeScanAwgLive l;
    l.state = tribeScanDaemonLivePeer(&l.publicKey, &l.endpoint);
    return l;
}

} // namespace

// --- pure parts --------------------------------------------------------------------------------------------------

bool TribeScanRateWindow::admit(qint64 nowMs)
{
    while (!m_events.isEmpty() && m_events.first() <= nowMs - m_windowMs)
        m_events.removeFirst();
    if (m_events.size() >= m_max)
        return false;
    m_events.append(nowMs);
    return true;
}

bool tribeScanIsVirtualIfname(const QString &name)
{
    static const char *const prefixes[] = {"utun", "ipsec", "ppp", "gif", "stf", "bridge", "awdl", "llw"};
    for (const char *p : prefixes)
        if (name.startsWith(QLatin1String(p)))
            return true;
    return false;
}

bool tribeScanUplinkUsable(const TribeScanUplink &u)
{
    return u.index > 0 && !u.name.isEmpty() && u.up && !u.loopback && !u.virtualType && !tribeScanIsVirtualIfname(u.name);
}

QByteArray tribeScanUplinkFingerprint(const TribeScanUplink &u)
{
    if (!tribeScanUplinkUsable(u))
        return QByteArray();
    QStringList addrs = u.addresses;
    addrs.sort();
    const QString in = QStringLiteral("tribe-scan-uplink-v1|%1|%2|%3|%4")
                           .arg(QString::number(u.index), u.name, u.gateway, addrs.join(QLatin1Char(',')));
    return QCryptographicHash::hash(in.toUtf8(), QCryptographicHash::Sha256);
}

QByteArray tribeScanGenerationJson(const ScanNetSource &g)
{
    return QJsonDocument(scanNetSourceToJson(g)).toJson(QJsonDocument::Compact);
}

TribeScanAwgOptions tribeScanAwgDecide(const QString &binary, const TribeScanAwgLive &live, bool stale)
{
    TribeScanAwgOptions o;
    if (binary.isEmpty() || stale)
        return o; // no binary, or a tunnel change meanwhile
    if (live.state < 0) {
        o.unavailable = QLatin1String(kTribeAwgLivePeerUnknown); // the daemon's state cannot be told
        return o;
    }
    if (live.state > 0) {
        if (live.publicKey.isEmpty() && live.endpoint.isEmpty()) {
            o.unavailable = QLatin1String(kTribeAwgLivePeerUnknown); // no awg_mini rather than a probe to it
            return o;
        }
        o.livePeer = true;
        o.livePeerKey = live.publicKey;
        o.livePeerEndpoint = live.endpoint;
    }
    o.binary = binary;
    return o;
}

QString tribeScanCheckAwgProbeBinary(const QString &path, bool requireRootOwned, int timeoutMs)
{
    const QFileInfo fi(path);
    if (path.isEmpty() || !fi.isAbsolute() || fi.isSymLink() || !fi.isFile() || !fi.isExecutable())
        return QString();
    if (requireRootOwned) {
        // A root service only runs a binary that only root can have put there.
        if (fi.ownerId() != 0 || (fi.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther)))
            return QString();
    }
    QProcess p;
    p.setProcessChannelMode(QProcess::SeparateChannels);
    p.setStandardInputFile(QProcess::nullDevice());
    p.start(path, {QStringLiteral("probe"), QStringLiteral("--abi")}, QIODevice::ReadOnly);
    if (!p.waitForStarted(timeoutMs))
        return QString();
    if (!p.waitForFinished(timeoutMs)) {
        p.kill();
        p.waitForFinished(500);
        return QString();
    }
    if (p.exitStatus() != QProcess::NormalExit || p.exitCode() != 0)
        return QString();
    const QByteArray out = p.readAllStandardOutput().left(256).trimmed();
    return out == QByteArray(kTribeAwgProbeAbi) ? path : QString();
}

QByteArray tribeScanHostOptions(const ScanNetSource &gen, const TribeScanUplink *bindTo, const TribeScanAwgOptions *awg,
                                qint64 hostEpoch)
{
    QJsonObject o;
    o.insert(QStringLiteral("gen"), scanNetSourceToJson(gen));
    if (hostEpoch >= 0)
        o.insert(QStringLiteral("host_epoch"), double(hostEpoch));
    if (bindTo) {
        o.insert(QStringLiteral("bind_interface_index"), bindTo->index);
        if (plainIfname(bindTo->name))
            o.insert(QStringLiteral("bind_interface"), bindTo->name);
    }
    if (awg && !awg->binary.isEmpty()) {
        o.insert(QStringLiteral("awg_probe_binary"), awg->binary);
        if (awg->livePeer && bindTo) { // scan_start only
            QJsonObject peer;
            if (!awg->livePeerKey.isEmpty())
                peer.insert(QStringLiteral("public_key"), awg->livePeerKey);
            if (!awg->livePeerEndpoint.isEmpty())
                peer.insert(QStringLiteral("endpoint"), awg->livePeerEndpoint);
            o.insert(QStringLiteral("awg_live_peer"), peer);
        }
    }
    return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

QByteArray tribeScanAddAwgUnavailable(const QByteArray &capsReply, const QString &reason)
{
    if (reason.isEmpty())
        return capsReply;
    const QJsonDocument doc = QJsonDocument::fromJson(capsReply);
    if (!doc.isObject() || doc.object().value(QLatin1String("type")).toString() != QLatin1String("scan_caps"))
        return capsReply;
    QJsonObject o = doc.object();
    o.insert(QStringLiteral("awg_unavailable"), reason);
    return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

bool TribeScanGeneration::observe(const QByteArray &fingerprint, bool loss)
{
    const QByteArray f = fingerprint.isEmpty() ? QByteArrayLiteral("none") : fingerprint;
    if (!m_haveBaseline) {
        m_haveBaseline = true;
        m_fingerprint = f;
        return false;
    }
    const bool moved = loss || f != m_fingerprint;
    m_fingerprint = f;
    if (moved)
        ++m_counter;
    return moved;
}

ScanNetSource TribeScanGeneration::now() const
{
    ScanNetSource s;
    s.source = QStringLiteral("service");
    s.epoch = m_epoch;
    s.counter = m_counter;
    return s;
}

bool tribeScanKnownAction(const QString &a)
{
    return a == QLatin1String("scan_caps") || a == QLatin1String("scan_start") || a == QLatin1String("scan_add")
           || a == QLatin1String("scan_poll") || a == QLatin1String("scan_freeze") || a == QLatin1String("scan_cancel");
}

TribeScanRequestInfo tribeScanInspectRequest(const QByteArray &message)
{
    TribeScanRequestInfo r;
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(message, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject())
        return r;
    const QJsonObject o = doc.object();
    r.object = true;
    r.action = o.value(QLatin1String("action")).toString().left(32);
    r.scanId = o.value(QLatin1String("scan_id")).toString().left(64);
    const QJsonValue d = o.value(QLatin1String("deadline_ms"));
    if (d.isDouble())
        r.deadlineMs = qint64(d.toDouble());
    for (const QJsonValue &c : o.value(QLatin1String("candidates")).toArray())
        r.hasAwgMini = r.hasAwgMini || c.toObject().value(QLatin1String("kind")).toString() == QLatin1String("awg_mini");
    return r;
}

TribeScanReplyInfo tribeScanInspectReply(const QByteArray &reply)
{
    TribeScanReplyInfo r;
    const QJsonDocument doc = QJsonDocument::fromJson(reply);
    if (!doc.isObject())
        return r;
    const QJsonObject o = doc.object();
    if (o.contains(QLatin1String("error"))) {
        r.error = o.value(QLatin1String("error")).toString().left(64);
        return r;
    }
    r.type = o.value(QLatin1String("type")).toString().left(32);
    r.scanId = o.value(QLatin1String("scan_id")).toString().left(64);
    r.finalTotals = o.value(QLatin1String("final")).toBool();
    return r;
}

TribeScanRouteEvent tribeScanRouteEvent(const char *msg, qsizetype len, int uplinkIndex)
{
    TribeScanRouteEvent ev;
#ifdef Q_OS_MACOS
    // Every routing message starts with u_short msglen, u_char version, u_char type.
    if (!msg || len < 4 || quint8(msg[2]) != RTM_VERSION)
        return ev;
    const int type = quint8(msg[3]);
    switch (type) {
    case RTM_ADD:
    case RTM_DELETE:
    case RTM_CHANGE: {
        if (len < qsizetype(sizeof(rt_msghdr)))
            return ev;
        rt_msghdr h;
        std::memcpy(&h, msg, sizeof(h));
        // Cloned per-destination routes and host routes (exclusions, the Xray /32s) churn all the time and
        // say nothing about the uplink; only gateway routes do (the default route among them).
        if ((h.rtm_flags & (RTF_HOST | RTF_WASCLONED | RTF_LLINFO)) || !(h.rtm_flags & RTF_GATEWAY))
            return ev;
        ev.resample = true;
        ev.loss = type == RTM_DELETE && uplinkIndex > 0 && h.rtm_index == uplinkIndex;
        return ev;
    }
    case RTM_NEWADDR:
    case RTM_DELADDR: {
        if (len < qsizetype(sizeof(ifa_msghdr)))
            return ev;
        ifa_msghdr h;
        std::memcpy(&h, msg, sizeof(h));
        ev.resample = true;
        ev.loss = type == RTM_DELADDR && uplinkIndex > 0 && h.ifam_index == uplinkIndex;
        return ev;
    }
    case RTM_IFINFO: {
        if (len < qsizetype(sizeof(if_msghdr)))
            return ev;
        if_msghdr h;
        std::memcpy(&h, msg, sizeof(h));
        ev.resample = true;
        ev.loss = uplinkIndex > 0 && h.ifm_index == uplinkIndex && !((h.ifm_flags & IFF_UP) && (h.ifm_flags & IFF_RUNNING));
        return ev;
    }
    default:
        return ev;
    }
#else
    Q_UNUSED(msg)
    Q_UNUSED(len)
    Q_UNUSED(uplinkIndex)
    return ev;
#endif
}

QStringList tribeScanParseProcArgs(const QByteArray &b)
{
    QStringList argv;
    int argc = 0;
    if (b.size() < int(sizeof(int)))
        return argv;
    std::memcpy(&argc, b.constData(), sizeof(int));
    if (argc <= 0 || argc > 4096)
        return argv;
    qsizetype i = sizeof(int);
    while (i < b.size() && b.at(i) != '\0') // the exec path
        ++i;
    while (i < b.size() && b.at(i) == '\0') // its padding
        ++i;
    for (int k = 0; k < argc && i < b.size(); ++k) {
        const qsizetype start = i;
        while (i < b.size() && b.at(i) != '\0')
            ++i;
        argv << QString::fromLocal8Bit(b.constData() + start, i - start);
        ++i;
    }
    if (argv.size() != argc)
        return QStringList(); // truncated: never a match
    return argv;
}

bool tribeScanIsProbeChild(const QString &exePath, const QStringList &argv, const QString &binaryPath)
{
    return !binaryPath.isEmpty() && exePath == binaryPath && argv.size() == 2 && argv.at(1) == QLatin1String("probe");
}

QList<qint64> tribeScanProbeChildPids(const QString &binaryPath)
{
    QList<qint64> out;
#ifdef Q_OS_MACOS
    const QString canon = binaryPath.isEmpty() ? QString() : QFileInfo(binaryPath).canonicalFilePath();
    if (canon.isEmpty())
        return out;
    std::vector<pid_t> pids(1024);
    const int n = proc_listchildpids(::getpid(), pids.data(), int(pids.size() * sizeof(pid_t)));
    if (n <= 0)
        return out;
    int argmax = 0;
    size_t len = sizeof(argmax);
    int argmaxMib[2] = {CTL_KERN, KERN_ARGMAX};
    if (::sysctl(argmaxMib, 2, &argmax, &len, nullptr, 0) != 0 || argmax <= 0)
        argmax = 256 * 1024;
    QByteArray args(argmax, Qt::Uninitialized);
    for (int k = 0; k < n && k < int(pids.size()); ++k) {
        const pid_t pid = pids[size_t(k)];
        if (pid <= 0)
            continue;
        char path[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(pid, path, sizeof(path)) <= 0)
            continue; // a zombie has no path any more: it can neither send nor be confused with a live one
        int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
        size_t size = size_t(args.size());
        if (::sysctl(mib, 3, args.data(), &size, nullptr, 0) != 0)
            continue;
        const QStringList argv = tribeScanParseProcArgs(QByteArray::fromRawData(args.constData(), qsizetype(size)));
        if (tribeScanIsProbeChild(QFileInfo(QString::fromUtf8(path)).canonicalFilePath(), argv, canon))
            out << qint64(pid); // never the live tunnel's `amneziawg-go -f utun`, never anything else
    }
#else
    Q_UNUSED(binaryPath)
#endif
    return out;
}

int tribeScanAwaitDeath(const QList<qint64> &pids, int waitMs, const std::function<bool(qint64)> &dead,
                        const std::function<qint64()> &clockMs, const std::function<void()> &pause)
{
    const qint64 start = clockMs();
    QList<qint64> left = pids;
    for (;;) {
        for (int i = int(left.size()) - 1; i >= 0; --i)
            if (dead(left.at(i)))
                left.removeAt(i);
        if (left.isEmpty() || clockMs() - start >= waitMs)
            return int(left.size());
        pause();
    }
}

TribeScanStopResult tribeScanParseStopReply(const QByteArray &reply)
{
    TribeScanStopResult r;
    const QJsonObject o = QJsonDocument::fromJson(reply).object();
    r.stopped = o.value(QLatin1String("stopped")).toBool();
    QStringList live;
    for (auto it = o.constBegin(); it != o.constEnd(); ++it) // QJsonObject keys are sorted
        if (it.key() != QLatin1String("stopped") && it.value().isDouble() && it.key().size() <= 32)
            live << QStringLiteral("%1=%2").arg(it.key()).arg(qint64(it.value().toDouble()));
    r.live = live.join(QLatin1Char(' '));
    return r;
}

TribeScanKillResult tribeScanKillProbeChildren(const QString &binaryPath, int deathWaitMs)
{
    TribeScanKillResult res;
#ifdef Q_OS_MACOS
    QList<qint64> killed;
    for (const qint64 p : tribeScanProbeChildPids(binaryPath))
        if (::kill(pid_t(p), SIGKILL) == 0)
            killed << p;
    res.killed = int(killed.size());
    // Dead = gone or a zombie (no fd, no packet). The engine's exec.Cmd reaps it (see the header).
    const auto dead = [](qint64 p) {
        const pid_t pid = pid_t(p);
        if (::kill(pid, 0) != 0 && errno == ESRCH)
            return true; // gone (reaped)
        // A zombie still answers kill(pid, 0); proc_pidinfo fails for it, KERN_PROC_PID reports SZOMB.
        struct kinfo_proc kp;
        size_t kpLen = sizeof(kp);
        int kpMib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
        return ::sysctl(kpMib, 4, &kp, &kpLen, nullptr, 0) == 0 && kpLen == sizeof(kp) && kp.kp_proc.p_stat == SZOMB;
    };
    QElapsedTimer t;
    t.start();
    res.alive = tribeScanAwaitDeath(killed, deathWaitMs, dead, [&t]() { return t.elapsed(); }, []() { QThread::msleep(2); });
#else
    Q_UNUSED(binaryPath)
    Q_UNUSED(deathWaitMs)
#endif
    return res;
}

TribeScanDeps tribeScanServiceDeps()
{
    TribeScanDeps d;
    d.message = engineMessage;
    d.stopAll = engineStopAll;
    d.uplink = readUplink;
#ifdef Q_OS_MACOS
    d.armFirewall = [](const QString &ifname) { return MacOSFirewall::setScanExemption(ifname); };
    d.disarmFirewall = [] { MacOSFirewall::clearScanExemption(); };
    d.awgProbeBinary = checkedServiceAwgProbeBinary;
#else
    // Windows: the WFP kill switch already permits the service executable (IPv4 and IPv6 ALE layers,
    // client/platforms/windows/daemon/windowsfirewall.cpp), probes included. Linux: not a Scanner target.
    d.armFirewall = [](const QString &) { return 0; };
    d.disarmFirewall = [] {};
    // No awg_mini: the AmneziaWG probe needs a per-socket interface binding the Windows build of the
    // runner does not have (recipes/awg-go: tribe_probe removed on Windows); Linux is not a target.
    d.awgProbeBinary = [] { return QString(); };
#endif
    d.awgLive = daemonAwgLive;
    d.killProbeChildren = killServiceProbeChildren;
    return d;
}

// --- the host ----------------------------------------------------------------------------------------------------

TribeScanHost::TribeScanHost(TribeScanDeps deps, QObject *parent)
    : IpcScanInterfaceSimpleSource(parent), m_deps(std::move(deps)), m_clock(steadyMs), m_gen(randomEpoch())
{
    setScanIpcVersion(kTribeScanIpcVersion);
    // Crash recovery: an exemption a previous service instance left behind (it died mid-scan).
    if (m_deps.disarmFirewall)
        m_deps.disarmFirewall();
    sample(m_deps.uplink ? m_deps.uplink() : TribeScanUplink(), false); // the baseline, published

    m_thread = new QThread;
    m_thread->setObjectName(QStringLiteral("tribe-scan"));
    m_workerContext = new QObject;
    m_workerContext->moveToThread(m_thread);
    QObject::connect(m_thread, &QThread::finished, m_workerContext, &QObject::deleteLater);
    m_thread->start();

#ifdef Q_OS_MACOS
    if (m_deps.routeMonitor) {
        // Read-only: no message is ever written to this socket.
        m_routeSocket = ::socket(PF_ROUTE, SOCK_RAW, 0);
        if (m_routeSocket >= 0) {
            ::fcntl(m_routeSocket, F_SETFL, ::fcntl(m_routeSocket, F_GETFL) | O_NONBLOCK);
            m_routeNotifier = new QSocketNotifier(m_routeSocket, QSocketNotifier::Read, this);
            QObject::connect(m_routeNotifier, &QSocketNotifier::activated, this, [this]() { readRouteSocket(); });
        } else {
            qWarning() << "[tribescan] route monitor unavailable, errno" << errno;
        }
    }
#endif
    if (QCoreApplication::instance())
        QObject::connect(QCoreApplication::instance(), &QCoreApplication::aboutToQuit, this, [this]() { shutdown(); });
    g_host = this;
}

TribeScanHost::~TribeScanHost()
{
    shutdown();
    if (g_host == this)
        g_host = nullptr;
}

qint64 TribeScanHost::nowMs() const
{
    return m_clock ? m_clock() : steadyMs();
}

int TribeScanHost::scanSubmit(quint64 requestId, const QString &message)
{
    if (m_shuttingDown.load())
        return int(TribeScanSubmit::ShuttingDown);
    if (message.size() > kTribeScanMaxMessageBytes) {
        qInfo() << "[tribescan] refused too_large chars" << message.size();
        return int(TribeScanSubmit::TooLarge);
    }
    if (!m_rate.admit(nowMs()))
        return int(TribeScanSubmit::RateLimited);
    if (m_pending.load() >= kTribeScanMaxPending)
        return int(TribeScanSubmit::QueueFull);
    QByteArray bytes = message.toUtf8();
    if (bytes.size() > kTribeScanMaxMessageBytes) {
        qInfo() << "[tribescan] refused too_large bytes" << bytes.size();
        return int(TribeScanSubmit::TooLarge);
    }
    // The live AmneziaWG tunnel is the daemon's state: read here, on its (main) thread, with the count of
    // tunnel changes it belongs to.
    const quint64 changes = m_tunnelChanges.load();
    const TribeScanAwgLive live = m_deps.awgLive ? m_deps.awgLive() : TribeScanAwgLive();
    ++m_pending;
    QMetaObject::invokeMethod(
        m_workerContext,
        [this, requestId, bytes = std::move(bytes), live, changes]() {
            const QByteArray reply = process(bytes, live, changes);
            QMetaObject::invokeMethod(
                this,
                [this, requestId, reply]() {
                    --m_pending;
                    emit scanReply(requestId, QString::fromUtf8(reply));
                },
                Qt::QueuedConnection);
        },
        Qt::QueuedConnection);
    return int(TribeScanSubmit::Accepted);
}

int TribeScanHost::scanStopAll()
{
    if (m_shuttingDown.load())
        return int(TribeScanSubmit::ShuttingDown);
    if (!m_rate.admit(nowMs())) // the same bound as every message
        return int(TribeScanSubmit::RateLimited);
    if (m_stopAllQueued.exchange(true))
        return int(TribeScanSubmit::Accepted); // one pending stop-all already covers this call
    QMetaObject::invokeMethod(
        m_workerContext,
        [this]() {
            m_stopAllQueued.store(false);
            if (!m_everStarted.load())
                return;
            QMutexLocker st(&m_startMutex);
            teardown("app_stop_all", kTribeScanStopForAppMs);
        },
        Qt::QueuedConnection);
    return int(TribeScanSubmit::Accepted);
}

// Worker thread: one message, start to end.
QByteArray TribeScanHost::process(const QByteArray &message, const TribeScanAwgLive &live, quint64 tunnelChanges)
{
    const TribeScanRequestInfo req = tribeScanInspectRequest(message);
    if (!req.object)
        return QByteArray(kErrJson);
    if (!tribeScanKnownAction(req.action))
        return QByteArray(kErrUnknownAction);
    const bool start = req.action == QLatin1String("scan_start");

    TribeScanUplink up;
    if (start || req.action == QLatin1String("scan_poll")) { // a fresh path sample for the generation
        up = m_deps.uplink ? m_deps.uplink() : TribeScanUplink();
        sample(up, false);
    }
    ScanNetSource gen;
    {
        QMutexLocker l(&m_mutex);
        gen = m_gen.now();
    }

    const qint64 epoch = qint64(tunnelChanges); // host_epoch: the tunnel-change count this message belongs to
    if (req.action == QLatin1String("scan_caps")) { // the engine offers awg_mini only with the binary
        const TribeScanAwgOptions awg = tribeScanAwgDecide(m_deps.awgProbeBinary ? m_deps.awgProbeBinary() : QString(), live,
                                                           m_tunnelChanges.load() != tunnelChanges);
        const QByteArray reply = m_deps.message ? m_deps.message(message, tribeScanHostOptions(gen, nullptr, &awg, epoch))
                                                : QByteArray(kErrInternal);
        // The same reason the iOS host gives, for the coordinator to mark the AWG rows of this scan.
        return tribeScanAddAwgUnavailable(reply, awg.unavailable);
    }
    const bool add = req.action == QLatin1String("scan_add");
    if (!start && !add) { // poll / freeze / cancel: they start nothing
        const QByteArray reply = m_deps.message ? m_deps.message(message, tribeScanHostOptions(gen, nullptr, nullptr, epoch))
                                                : QByteArray(kErrInternal);
        const TribeScanReplyInfo r = tribeScanInspectReply(reply);
        if (r.finalTotals && !r.scanId.isEmpty())
            endActive(r.scanId, "final"); // the host scan is over: its exemption goes
        return reply;
    }

    if (start) {
        if (!m_startRate.admit(nowMs())) {
            qInfo() << "[tribescan] scan_start refused rate_limited";
            return QByteArray(kErrStartRate);
        }
        if (!tribeScanUplinkUsable(up)) {
            qInfo() << "[tribescan] scan_start refused no_physical_uplink";
            return QByteArray(kErrNoUplink);
        }
    }
    const QString awgBinary = (start || req.hasAwgMini) && m_deps.awgProbeBinary ? m_deps.awgProbeBinary() : QString(); // may run the check once
    if (req.hasAwgMini && tribeScanAwgDecide(awgBinary, live, false).unavailable == QLatin1String(kTribeAwgLivePeerUnknown)) {
        // As the iOS host: AmneziaWG sessions are refused while the live peer cannot be told; the coordinator
        // sends the start / add again without them and marks those rows with this reason.
        qInfo().noquote() << "[tribescan]" << req.action << "refused awg_live_peer_unknown";
        return QByteArray(kErrAwgLivePeerUnknown);
    }

    // From here to the engine's answer: one step against stopAllBeforeTunnelChange, which holds the same
    // mutex while it moves the tunnel-change count and stops the engine. A start or add queued before a tunnel
    // change is dropped here and never reaches the engine; one already in the engine completes first and is
    // then stopped by the hook.
    QMutexLocker st(&m_startMutex);
    if (m_tunnelChanges.load() != tunnelChanges) {
        qInfo().noquote() << "[tribescan]" << req.action << "refused tunnel_changed";
        return QByteArray(kErrTunnelChanged);
    }
    if (m_teardownPending) {
        // The last stop was not confirmed: nothing new until the engine says nothing of it is alive.
        if (m_deps.stopAll && m_deps.stopAll(0, qint64(m_tunnelChanges.load())).stopped) { // the engine's truth
            m_teardownPending = false;
            qInfo() << "[tribescan] teardown complete";
        } else {
            qInfo().noquote() << "[tribescan]" << req.action << "refused teardown_pending";
            return QByteArray(kErrTeardownPending);
        }
    }
    if (add) {
        const QByteArray reply = m_deps.message ? m_deps.message(message, tribeScanHostOptions(gen, nullptr, nullptr, epoch))
                                                : QByteArray(kErrInternal);
        const TribeScanReplyInfo r = tribeScanInspectReply(reply);
        if (r.finalTotals && !r.scanId.isEmpty())
            endActive(r.scanId, "final");
        return reply;
    }

    quint64 serial = 0;
    bool exemptionFailed = false;
    {
        QMutexLocker fw(&m_fwMutex);
        const int arm = m_deps.armFirewall ? m_deps.armFirewall(up.name) : 0;
        QMutexLocker l(&m_mutex);
        if (arm < 0) {
            exemptionFailed = true;
            m_active = Active(); // the attempt flushed a previous scan's rule too
        } else {
            m_active.scanId = req.scanId;
            m_active.serial = ++m_serial;
            m_active.armed = arm > 0;
            serial = m_active.serial;
        }
    }
    if (exemptionFailed) {
        // The kill switch is ours and blocks the uplink, and its exemption did not load: fail closed. A scan
        // still running in the engine lost its rule as well, so it ends too.
        if (m_everStarted.load())
            teardown("kill_switch_exemption", kTribeScanStopForAppMs);
        qInfo() << "[tribescan] scan_start refused kill_switch_exemption";
        return QByteArray(kErrExemption);
    }
    m_everStarted.store(true);
    const TribeScanAwgOptions awg = tribeScanAwgDecide(awgBinary, live, false);
    const QByteArray reply = m_deps.message ? m_deps.message(message, tribeScanHostOptions(gen, &up, &awg, epoch))
                                            : QByteArray(kErrInternal);
    const TribeScanReplyInfo r = tribeScanInspectReply(reply);
    if (r.type == QLatin1String("scan_ack")) {
        // deadline_ms is bounded by the contract (1 s .. 120 s); an out-of-range value was refused above
        // by the engine, never acked.
        const qint64 deadline = qBound(qint64(1000), req.deadlineMs < 0 ? qint64(120000) : req.deadlineMs, qint64(120000));
        scheduleDisarm(serial, deadline + kTribeScanDisarmGraceMs);
    } else {
        endActive(req.scanId, "start_refused");
    }
    qInfo().noquote() << "[tribescan] scan_start scan=" + logId(req.scanId) << "bytes" << message.size() << "->"
                      << logId(r.type.isEmpty() ? r.error : r.type);
    return reply;
}

void TribeScanHost::sample(const TribeScanUplink &up, bool loss)
{
    const QByteArray fp = tribeScanUplinkFingerprint(up);
    ScanNetSource g;
    bool publish = false;
    {
        QMutexLocker l(&m_mutex);
        m_gen.observe(fp, loss);
        m_lastUplinkIndex = tribeScanUplinkUsable(up) ? up.index : 0;
        g = m_gen.now();
        publish = !m_havePublished || g != m_published;
        m_published = g;
        m_havePublished = true;
    }
    if (publish)
        publishGeneration(g);
}

void TribeScanHost::publishGeneration(const ScanNetSource &g)
{
    const QString json = QString::fromUtf8(tribeScanGenerationJson(g));
    if (QThread::currentThread() == thread()) {
        setScanGeneration(json);
        return;
    }
    QMetaObject::invokeMethod(this, [this, json]() { setScanGeneration(json); }, Qt::QueuedConnection);
}

bool TribeScanHost::endActive(const QString &scanId, const char *why)
{
    QMutexLocker fw(&m_fwMutex);
    bool armed = false;
    {
        QMutexLocker l(&m_mutex);
        if (m_active.serial == 0 || (!scanId.isEmpty() && m_active.scanId != scanId))
            return false;
        armed = m_active.armed;
        m_active = Active();
    }
    if (armed && m_deps.disarmFirewall) {
        m_deps.disarmFirewall();
        qInfo() << "[tribescan] exemption removed:" << why;
        return true;
    }
    return false;
}

void TribeScanHost::scheduleDisarm(quint64 serial, qint64 afterMs)
{
    QMetaObject::invokeMethod(
        this,
        [this, serial, afterMs]() {
            // A single shot that removes a firewall exemption of a scan the app never closed (it quit or
            // crashed); it never acts on a tunnel. Precise: a coarse timer may fire 5 % early, which for a
            // 120 s deadline would be before the scan itself ends.
            auto fire = [this, serial]() {
                QString id;
                {
                    QMutexLocker l(&m_mutex);
                    if (m_active.serial != serial)
                        return;
                    id = m_active.scanId;
                }
                endActive(id, "deadline");
            };
            if (m_disarmTimer)
                m_disarmTimer(afterMs, fire);
            else
                QTimer::singleShot(std::chrono::milliseconds(afterMs), Qt::PreciseTimer, this, fire);
        },
        Qt::QueuedConnection);
}

void TribeScanHost::stopAllBeforeTunnelChange(const char *reason)
{
    // Held through the whole stop: no scan_start / scan_add between the count moving and the engine stopping.
    QMutexLocker st(&m_startMutex);
    ++m_tunnelChanges;
    if (!m_everStarted.load())
        return; // the engine never ran a scan in this process
    teardown(reason, kTribeScanStopBeforeTunnelMs);
}

bool TribeScanHost::teardown(const char *reason, int waitMs)
{
    // The epoch of the stop: the engine refuses every later start / add of a lower epoch (stale_epoch).
    const TribeScanStopResult stop =
        m_deps.stopAll ? m_deps.stopAll(waitMs, qint64(m_tunnelChanges.load())) : TribeScanStopResult{true, QString()};
    // "stopped" = the engine killed and reaped its probe children itself. Only after a stop it did not
    // confirm does the service kill the `amneziawg-go probe` children (the belt; never the live tunnel's
    // amneziawg-go) and wait until each is dead. The two cannot double-signal a reused pid: the engine's
    // exec.Cmd is the only reaper, the service never reaps, so a pid this kill sees is not free; a pid the
    // engine reaps between this listing and kill(2) is handed out again only after the pid counter wraps (99999
    // new processes in between).
    const TribeScanKillResult kill = !stop.stopped && m_deps.killProbeChildren ? m_deps.killProbeChildren() : TribeScanKillResult();
    const bool exemptionRemoved = endActive(QString(), reason); // the pf exemption
    if (!stop.stopped || kill.alive > 0)
        m_teardownPending = true;
    if (!stop.stopped || kill.alive > 0) {
        // One line, for a field report to show whether this path ever happens and what it left.
        qWarning().noquote() << QStringLiteral("[tribescan] stop-all reason=%1 stopped=%2 engine_live=%3 probe_children_killed=%4 "
                                               "probe_children_alive=%5 exemption_removed=%6; new scans refused until the engine "
                                               "confirms the teardown")
                                    .arg(QLatin1String(reason), stop.stopped ? QStringLiteral("true") : QStringLiteral("false"),
                                         stop.live.isEmpty() ? QStringLiteral("not_reported") : QString(stop.live).replace(QLatin1Char(' '), QLatin1Char(',')))
                                    .arg(kill.killed)
                                    .arg(kill.alive)
                                    .arg(exemptionRemoved ? QStringLiteral("yes") : QStringLiteral("none_armed"));
    } else {
        qInfo() << "[tribescan] stop-all reason=" << reason << "stopped= true";
    }
    return stop.stopped && kill.alive == 0;
}

void TribeScanHost::notePathEvent(bool loss)
{
    sample(m_deps.uplink ? m_deps.uplink() : TribeScanUplink(), loss);
}

void TribeScanHost::readRouteSocket()
{
#ifdef Q_OS_MACOS
    int index = 0;
    {
        QMutexLocker l(&m_mutex);
        index = m_lastUplinkIndex;
    }
    bool resample = false;
    bool loss = false;
    char buf[2048];
    for (int i = 0; i < 64; ++i) { // bounded: the notifier fires again for the rest
        const ssize_t n = ::recv(m_routeSocket, buf, sizeof(buf), MSG_DONTWAIT);
        if (n <= 0)
            break;
        const TribeScanRouteEvent ev = tribeScanRouteEvent(buf, qsizetype(n), index);
        resample = resample || ev.resample;
        loss = loss || ev.loss;
    }
    if (resample || loss)
        notePathEvent(loss);
#endif
}

void TribeScanHost::shutdown()
{
    if (m_shuttingDown.exchange(true))
        return;
    if (m_everStarted.load()) {
        QMutexLocker st(&m_startMutex);
        teardown("shutdown", kTribeScanStopOnQuitMs);
    } else {
        endActive(QString(), "shutdown");
    }
#ifdef Q_OS_MACOS
    if (m_routeNotifier) {
        m_routeNotifier->setEnabled(false);
        delete m_routeNotifier;
        m_routeNotifier = nullptr;
    }
    if (m_routeSocket >= 0) {
        ::close(m_routeSocket);
        m_routeSocket = -1;
    }
#endif
    if (m_thread) {
        m_thread->quit();
        // Every engine call is bounded (a replacing scan_start waits up to 3 s); a worker that still runs
        // after this is left to the process exit instead of being destroyed while running.
        if (m_thread->wait(10000))
            delete m_thread;
        else
            qWarning() << "[tribescan] worker did not stop in time";
        m_thread = nullptr;
        m_workerContext = nullptr;
    }
}

void tribeScanBeforeTunnelChange(const char *reason)
{
    if (g_host)
        g_host->stopAllBeforeTunnelChange(reason);
}

} // namespace avpn
