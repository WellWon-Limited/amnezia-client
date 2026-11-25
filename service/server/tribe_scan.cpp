// service/server/tribe_scan.cpp - the desktop probe host of the root service (see tribe_scan.h).
#include "tribe_scan.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDebug>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QMetaObject>
#include <QMutexLocker>
#include <QNetworkInterface>
#include <QProcess>
#include <QRandomGenerator>
#include <QSaveFile>
#include <QSocketNotifier>
#include <QThread>
#include <QTimer>

#include <cerrno>
#include <chrono>

#include <amnezia_xray.h>

#include "core/utils/networkUtilities.h"

#ifdef Q_OS_MACOS
    #include "platforms/macos/daemon/macosfirewall.h"

    #include <arpa/inet.h>
    #include <csignal>
    #include <cstring>
    #include <fcntl.h>
    #include <libproc.h>
    #include <net/if.h>
    #include <net/route.h>
    #include <netinet/in.h>
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

// The facts of one interface (index, name, flags, addresses) with the given gateway.
TribeScanUplink uplinkOf(const QNetworkInterface &iface, const QString &gateway)
{
    TribeScanUplink u;
    if (!iface.isValid())
        return u;
    u.name = iface.name();
    u.index = iface.index();
    u.gateway = gateway;
    const QNetworkInterface::InterfaceFlags f = iface.flags();
    u.up = f.testFlag(QNetworkInterface::IsUp) && f.testFlag(QNetworkInterface::IsRunning);
    u.loopback = f.testFlag(QNetworkInterface::IsLoopBack) || iface.type() == QNetworkInterface::Loopback;
    u.virtualType = iface.type() == QNetworkInterface::Virtual;
    for (const QNetworkAddressEntry &e : iface.addressEntries())
        u.addresses << e.ip().toString();
    return u;
}

TribeScanUplink readUplinkByHelper()
{
    const QPair<QString, QNetworkInterface> gi = NetworkUtilities::getGatewayAndIface();
    return uplinkOf(gi.second, gi.first);
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

// --- the uplink's half routes: the kernel side (tribe_scan.h) ---

// A socket pinned to `ifindex` has a route to `dst`: a UDP connect does the route lookup the probes' connects do and
// sends nothing (ENETUNREACH when no route serves the pinned scope).
bool pinnedRouteExists(int ifindex, quint32 dst)
{
    const int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return false;
    const int idx = ifindex;
    bool ok = ::setsockopt(s, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx)) == 0;
    if (ok) {
        sockaddr_in a{};
        a.sin_len = sizeof(a);
        a.sin_family = AF_INET;
        a.sin_port = htons(443);
        a.sin_addr.s_addr = htonl(dst);
        ok = ::connect(s, reinterpret_cast<const sockaddr *>(&a), sizeof(a)) == 0;
    }
    ::close(s);
    return ok;
}

// One RTM_ADD / RTM_DELETE on a fresh routing socket (root only). 0 or errno.
int writeHalfRoute(bool add, const TribeScanHalfRoute &r)
{
    static std::atomic<int> seq{1};
    const QByteArray m = tribeScanHalfRouteMessage(add, r, seq++);
    if (m.isEmpty())
        return EINVAL;
    const int s = ::socket(PF_ROUTE, SOCK_RAW, AF_INET);
    if (s < 0)
        return errno ? errno : EIO;
    const int off = 0; // no echo of our own message to this socket
    ::setsockopt(s, SOL_SOCKET, SO_USELOOPBACK, &off, sizeof(off));
    const ssize_t n = ::write(s, m.constData(), size_t(m.size()));
    const int e = n == ssize_t(m.size()) ? 0 : (errno ? errno : EIO);
    ::close(s);
    return e;
}

// The AF_INET route table (read-only). The table may grow between the size query and the dump (an AmneziaWG start
// adds thousands of routes): retried with the new size, as route(8) does.
QByteArray dumpInetRoutes()
{
    int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0};
    for (int attempt = 0; attempt < 8; ++attempt) {
        size_t len = 0;
        if (::sysctl(mib, 6, nullptr, &len, nullptr, 0) < 0 || len == 0)
            return QByteArray();
        len += len / 8 + 4096;
        QByteArray buf(qsizetype(len), Qt::Uninitialized);
        if (::sysctl(mib, 6, buf.data(), &len, nullptr, 0) == 0) {
            buf.truncate(qsizetype(len));
            return buf;
        }
        if (errno != ENOMEM)
            return QByteArray();
    }
    return QByteArray();
}

// The ownership record (tribe_scan.h): read whole; written durably - a temporary file, fsync, rename, then the
// directory synced - so a record that says "about to add" is on disk before the RTM_ADD (review N3). "" removes it.
QByteArray readRecordAt(const char *file)
{
    QFile f(QString::fromLatin1(file));
    return f.open(QIODevice::ReadOnly) ? f.read(4096) : QByteArray();
}

bool writeRecordAt(const char *file, const QByteArray &bytes)
{
    const QString path = QString::fromLatin1(file);
    const QString dir = QFileInfo(path).absolutePath();
    auto syncDir = [&dir]() {
        const int d = ::open(QFile::encodeName(dir).constData(), O_RDONLY);
        if (d < 0)
            return false;
        const bool ok = ::fsync(d) == 0;
        ::close(d);
        return ok;
    };
    if (bytes.isEmpty()) {
        if (QFile::exists(path) && !QFile::remove(path))
            return false;
        syncDir();
        return true;
    }
    if (!QDir().mkpath(dir))
        return false;
    const QString tmp = path + QStringLiteral(".tmp");
    QFile f(tmp);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return false;
    const bool written = f.write(bytes) == bytes.size() && f.flush() && ::fsync(f.handle()) == 0;
    f.close();
    if (!written || ::rename(QFile::encodeName(tmp).constData(), QFile::encodeName(path).constData()) != 0) {
        QFile::remove(tmp);
        return false;
    }
    return syncDir();
}

TribeScanRouteOps systemRouteOps(const char *record = kTribeScanRoutesRecord)
{
    TribeScanRouteOps ops;
    ops.pinned = pinnedRouteExists;
    ops.write = writeHalfRoute;
    ops.table = dumpInetRoutes;
    ops.recordRead = [record]() { return readRecordAt(record); };
    ops.recordWrite = [record](const QByteArray &bytes) { return writeRecordAt(record, bytes); };
    return ops;
}

TribeScanRouteArm armUplinkRoutes(const TribeScanUplink &u)
{
    quint32 router = 0;
    in_addr a{};
    if (::inet_pton(AF_INET, u.gateway.toLatin1().constData(), &a) == 1)
        router = ntohl(a.s_addr);
    const TribeScanRouteArm r = tribeScanArmHalfRoutes(u, router, systemRouteOps());
    if (r.result > 0)
        qInfo() << "[tribescan] uplink routes for pinned probes added:" << r.added.size();
    else if (r.result < 0)
        qWarning() << "[tribescan] uplink routes for pinned probes: needed, not in force";
    return r;
}

void disarmUplinkRoutes(const QList<TribeScanHalfRoute> &added)
{
    const QList<TribeScanHalfRoute> left = tribeScanRemoveHalfRoutes(added, systemRouteOps());
    if (!left.isEmpty())
        qWarning() << "[tribescan] uplink routes not removed, kept for a retry:" << left.size();
}

void clearLeftoverUplinkRoutes()
{
    const int removed = tribeScanRecoverHalfRoutes(systemRouteOps());
    if (removed > 0)
        qInfo() << "[tribescan] uplink routes of an earlier service instance removed:" << removed;
    // Round mac-D3: the same recovery for an Xray session's pair (tribe_scan.h kTribeXrayRoutesRecord) - a service
    // killed under own Xray never ran the Xray session stop, and its routes waited for a later Xray session to end.
    const int xray = tribeScanRecoverHalfRoutes(systemRouteOps(kTribeXrayRoutesRecord));
    if (xray > 0)
        qInfo() << "[xray] uplink routes of an earlier service instance's Xray session removed:" << xray;
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
    for (const QJsonValue &c : o.value(QLatin1String("candidates")).toArray()) {
        r.hasAwgMini = r.hasAwgMini || c.toObject().value(QLatin1String("kind")).toString() == QLatin1String("awg_mini");
        const QHostAddress entry(c.toObject().value(QLatin1String("entry")).toObject().value(QLatin1String("ip")).toString());
        if (entry.protocol() == QAbstractSocket::IPv4Protocol && !r.entryIps.contains(entry.toIPv4Address()))
            r.entryIps << entry.toIPv4Address();
    }
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

#ifdef Q_OS_MACOS
namespace {
inline qsizetype saRoundUp(qsizetype len) { return len > 0 ? (1 + ((len - 1) | qsizetype(sizeof(uint32_t) - 1))) : qsizetype(sizeof(uint32_t)); }

// The IPv4 address bytes of a routing sockaddr (the kernel trims masks to their last non-zero byte), host order.
quint32 saInet(const char *sa, qsizetype room)
{
    if (room < 2)
        return 0;
    const qsizetype saLen = qMin<qsizetype>(quint8(sa[0]), room);
    quint8 b[4] = {0, 0, 0, 0};
    for (qsizetype i = 4; i < saLen && i < 8; ++i)
        b[i - 4] = quint8(sa[i]);
    return (quint32(b[0]) << 24) | (quint32(b[1]) << 16) | (quint32(b[2]) << 8) | quint32(b[3]);
}

struct DumpRoute {
    rt_msghdr h;
    quint32 dst = 0;
    bool haveMask = false;
    quint32 mask = 0;
    bool gwInet = false;
    quint32 gw = 0;
};

template <typename F>
void forEachDumpRoute(const QByteArray &dump, F f)
{
    const char *p = dump.constData();
    const char *end = p + dump.size();
    while (end - p >= qsizetype(sizeof(rt_msghdr))) {
        DumpRoute r;
        std::memcpy(&r.h, p, sizeof(r.h));
        if (r.h.rtm_msglen < sizeof(rt_msghdr) || p + r.h.rtm_msglen > end)
            return;
        const char *sa = p + sizeof(rt_msghdr);
        const char *next = p + r.h.rtm_msglen;
        p = next;
        bool haveDst = false;
        for (int i = 0; i < RTAX_MAX && sa < next; ++i) {
            if (!(r.h.rtm_addrs & (1 << i)))
                continue;
            const qsizetype room = next - sa;
            const quint8 family = room >= 2 ? quint8(sa[1]) : 0;
            if (i == RTAX_DST && family == AF_INET) {
                r.dst = saInet(sa, room);
                haveDst = true;
            } else if (i == RTAX_GATEWAY && family == AF_INET) {
                r.gwInet = true;
                r.gw = saInet(sa, room);
            } else if (i == RTAX_NETMASK) {
                r.haveMask = true;
                r.mask = saInet(sa, room);
            }
            sa += saRoundUp(quint8(sa[0]));
        }
        if (haveDst)
            f(r);
    }
}

// One routing message (an rt_msghdr and its sockaddrs) about 0.0.0.0/1 or 128.0.0.0/1 with an IPv4 gateway.
bool isHalfRouteMessage(const char *msg, qsizetype len)
{
    bool half = false;
    forEachDumpRoute(QByteArray::fromRawData(msg, len), [&](const DumpRoute &r) {
        half = half || (r.gwInet && r.haveMask && r.mask == 0x80000000u && (r.dst == kTribeScanHalfLow || r.dst == kTribeScanHalfHigh));
    });
    return half;
}
} // namespace
#endif

TribeScanRouteEvent tribeScanRouteEvent(const char *msg, qsizetype len, int uplinkIndex, qint64 ownPid)
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
        // The scoped half routes this process writes itself (the scan's, an Xray session's): never a path fact.
        if (ownPid >= 0 && qint64(h.rtm_pid) == ownPid && (h.rtm_flags & RTF_IFSCOPE) && isHalfRouteMessage(msg, len))
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
    Q_UNUSED(ownPid)
    return ev;
#endif
}

namespace {
// The special ranges a probe never dials: loopback, link-local, multicast and above (a route of another interface
// there hides nothing a probe needs).
bool halfSpecial(quint32 dst)
{
    return (dst >> 24) == 127 || (dst >> 16) == 0xA9FE || dst >= 0xE0000000u;
}

// The ownership record, edited as a set: += before an add, -= after a delete (tribe_scan.h).
QList<TribeScanHalfRoute> recordNow(const TribeScanRouteOps &ops)
{
    return ops.recordRead ? tribeScanParseHalfRoutesRecord(ops.recordRead()) : QList<TribeScanHalfRoute>();
}

bool recordAdd(const TribeScanRouteOps &ops, const QList<TribeScanHalfRoute> &routes)
{
    if (!ops.recordWrite)
        return false;
    QList<TribeScanHalfRoute> rec = recordNow(ops);
    for (const TribeScanHalfRoute &r : routes)
        if (!rec.contains(r))
            rec << r;
    return ops.recordWrite(tribeScanHalfRoutesRecord(rec));
}

bool recordDrop(const TribeScanRouteOps &ops, const QList<TribeScanHalfRoute> &routes)
{
    if (!ops.recordWrite || routes.isEmpty())
        return true;
    QList<TribeScanHalfRoute> rec = recordNow(ops);
    for (const TribeScanHalfRoute &r : routes)
        rec.removeAll(r);
    return ops.recordWrite(tribeScanHalfRoutesRecord(rec));
}
} // namespace

TribeScanHalfNeed tribeScanHalvesNeeded(const QByteArray &dump, int uplinkIndex)
{
    TribeScanHalfNeed hidden;
    TribeScanHalfNeed served;
#ifdef Q_OS_MACOS
    forEachDumpRoute(dump, [&](const DumpRoute &r) {
        if (!(r.h.rtm_flags & RTF_UP) || (r.h.rtm_flags & (RTF_WASCLONED | RTF_LLINFO)))
            return;
        const quint32 mask = r.haveMask ? r.mask : ((r.h.rtm_flags & RTF_HOST) ? 0xFFFFFFFFu : 0u);
        if (r.h.rtm_flags & RTF_IFSCOPE) {
            // a route scoped to the uplink that serves a whole half: the half itself, or a scoped default
            if (int(r.h.rtm_index) != uplinkIndex || !r.gwInet)
                return;
            if (mask == 0 && r.dst == 0) {
                served.low = served.high = true;
            } else if (mask == 0x80000000u && r.dst == kTribeScanHalfLow) {
                served.low = true;
            } else if (mask == 0x80000000u && r.dst == kTribeScanHalfHigh) {
                served.high = true;
            }
            return;
        }
        if (int(r.h.rtm_index) == uplinkIndex || mask == 0 || halfSpecial(r.dst))
            return; // the uplink's own routes, the default, the special ranges
        ((r.dst & 0x80000000u) ? hidden.high : hidden.low) = true; // a /1 or longer lies in one half
    });
#else
    Q_UNUSED(dump)
    Q_UNUSED(uplinkIndex)
#endif
    TribeScanHalfNeed need;
    need.low = hidden.low && !served.low;
    need.high = hidden.high && !served.high;
    return need;
}

QList<TribeScanHalfRoute> tribeScanScopedHalfRoutes(const QByteArray &dump)
{
    QList<TribeScanHalfRoute> out;
#ifdef Q_OS_MACOS
    forEachDumpRoute(dump, [&](const DumpRoute &r) {
        if (!(r.h.rtm_flags & RTF_IFSCOPE) || !r.gwInet || !r.haveMask || r.mask != 0x80000000u)
            return;
        if (r.dst != kTribeScanHalfLow && r.dst != kTribeScanHalfHigh)
            return;
        TribeScanHalfRoute h;
        h.dst = r.dst;
        h.gateway = r.gw;
        h.ifindex = r.h.rtm_index;
        out << h;
    });
#else
    Q_UNUSED(dump)
#endif
    return out;
}

TribeScanRouteArm tribeScanArmHalfRoutes(const TribeScanUplink &u, quint32 router, const TribeScanRouteOps &ops)
{
    TribeScanRouteArm r;
    if (!tribeScanUplinkUsable(u) || !ops.write || !ops.table || !ops.recordWrite)
        return r;
    tribeScanRecoverHalfRoutes(ops); // an earlier crash or a failed delete: ours go first
    const QByteArray table = ops.table();
    const TribeScanHalfNeed need = tribeScanHalvesNeeded(table, u.index);
    if (!need.any())
        return r; // pinned sockets route through the table (VPN off: the primary default; Xray: its own scoped pair)
    if (router == 0) // getGatewayAndIface may hand an IPv6 gateway: the IPv4 one of the same interface
        router = tribeScanDefaultRouter(table, u.index);
    if (router == 0) {
        r.result = -1; // needed, and no IPv4 router to route through
        return r;
    }
    QList<TribeScanHalfRoute> intent;
    for (const quint32 half : {kTribeScanHalfLow, kTribeScanHalfHigh}) {
        if (half == kTribeScanHalfLow ? !need.low : !need.high)
            continue;
        TribeScanHalfRoute route;
        route.dst = half;
        route.gateway = router;
        route.ifindex = u.index;
        intent << route;
    }
    if (!recordAdd(ops, intent)) { // the intent is on disk before the first add, or nothing is added
        r.result = -1;
        return r;
    }
    bool failed = false;
    QList<TribeScanHalfRoute> notOurs;
    for (const TribeScanHalfRoute &route : intent) {
        const int e = ops.write(true, route);
        if (e == 0)
            r.added << route;
        else if (e == EEXIST)
            notOurs << route; // someone's route arrived since the table read: never ours to delete
        else
            failed = true;
    }
    recordDrop(ops, notOurs);
    if (!failed)
        failed = tribeScanHalvesNeeded(ops.table(), u.index).any()
                 || (ops.pinned && (!ops.pinned(u.index, kTribeScanTestLow) || !ops.pinned(u.index, kTribeScanTestHigh)));
    if (failed) {
        tribeScanRemoveHalfRoutes(r.added, ops); // what is deleted leaves the record; a failed delete stays for a retry
        QList<TribeScanHalfRoute> neverAdded;
        for (const TribeScanHalfRoute &route : intent)
            if (!r.added.contains(route) && !notOurs.contains(route))
                neverAdded << route;
        recordDrop(ops, neverAdded);
        r.added.clear();
        r.result = -1;
        return r;
    }
    r.result = r.added.isEmpty() ? 0 : 1;
    return r;
}

QList<TribeScanHalfRoute> tribeScanRemoveHalfRoutes(const QList<TribeScanHalfRoute> &routes, const TribeScanRouteOps &ops)
{
    QList<TribeScanHalfRoute> gone;
    QList<TribeScanHalfRoute> left;
    for (const TribeScanHalfRoute &route : routes) {
        const int e = ops.write ? ops.write(false, route) : EINVAL;
        if (e == 0 || e == ESRCH)
            gone << route;
        else
            left << route; // stays recorded: the next recover retries it
    }
    recordDrop(ops, gone);
    return left;
}

int tribeScanRecoverHalfRoutes(const TribeScanRouteOps &ops)
{
    const QList<TribeScanHalfRoute> rec = recordNow(ops);
    if (rec.isEmpty()) {
        if (ops.recordRead && ops.recordWrite && !ops.recordRead().isEmpty())
            ops.recordWrite(QByteArray()); // unreadable leftovers: nothing of them can be told ours
        return 0;
    }
    const QList<TribeScanHalfRoute> live = ops.table ? tribeScanScopedHalfRoutes(ops.table()) : QList<TribeScanHalfRoute>();
    QList<TribeScanHalfRoute> forget;
    QList<TribeScanHalfRoute> ours;
    for (const TribeScanHalfRoute &r : rec) {
        bool present = false;
        bool same = false;
        for (const TribeScanHalfRoute &l : live) {
            if (l.dst == r.dst && l.ifindex == r.ifindex) {
                present = true;
                same = same || l.gateway == r.gateway;
            }
        }
        if (!present || !same)
            forget << r; // gone (a reboot, a removal), or someone else's via another gateway: never deleted
        else
            ours << r;
    }
    recordDrop(ops, forget);
    const int before = int(ours.size());
    const QList<TribeScanHalfRoute> left = tribeScanRemoveHalfRoutes(ours, ops);
    return before - int(left.size());
}

QByteArray tribeScanHalfRouteMessage(bool add, const TribeScanHalfRoute &r, int seq)
{
#ifdef Q_OS_MACOS
    rt_msghdr h;
    std::memset(&h, 0, sizeof(h));
    h.rtm_version = RTM_VERSION;
    h.rtm_type = add ? RTM_ADD : RTM_DELETE;
    h.rtm_index = u_short(r.ifindex);
    h.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC | RTF_IFSCOPE;
    h.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
    h.rtm_seq = seq;
    const auto inet = [](quint32 hostOrder) {
        sockaddr_in s{};
        s.sin_len = sizeof(s);
        s.sin_family = AF_INET;
        s.sin_addr.s_addr = htonl(hostOrder);
        return QByteArray(reinterpret_cast<const char *>(&s), sizeof(s));
    };
    const QByteArray body = inet(r.dst) + inet(r.gateway) + inet(0x80000000u); // a /1 mask
    h.rtm_msglen = u_short(sizeof(h) + size_t(body.size()));
    return QByteArray(reinterpret_cast<const char *>(&h), sizeof(h)) + body;
#else
    Q_UNUSED(add)
    Q_UNUSED(r)
    Q_UNUSED(seq)
    return QByteArray();
#endif
}

QByteArray tribeScanHalfRoutesRecord(const QList<TribeScanHalfRoute> &routes)
{
    QByteArray out;
    for (const TribeScanHalfRoute &r : routes)
        out += QByteArray("half ") + QByteArray::number(r.dst, 16) + ' ' + QByteArray::number(r.gateway, 16) + ' '
               + QByteArray::number(r.ifindex) + '\n';
    return out;
}

QList<TribeScanHalfRoute> tribeScanParseHalfRoutesRecord(const QByteArray &record)
{
    QList<TribeScanHalfRoute> out;
    for (const QByteArray &line : record.split('\n')) {
        const QList<QByteArray> f = line.trimmed().split(' ');
        if (f.size() != 4 || f.at(0) != "half")
            continue;
        bool ok1 = false, ok2 = false, ok3 = false;
        TribeScanHalfRoute r;
        r.dst = f.at(1).toUInt(&ok1, 16);
        r.gateway = f.at(2).toUInt(&ok2, 16);
        r.ifindex = f.at(3).toInt(&ok3);
        if (ok1 && ok2 && ok3 && (r.dst == kTribeScanHalfLow || r.dst == kTribeScanHalfHigh) && r.gateway != 0
            && r.ifindex > 0 && r.ifindex < 65536 && !out.contains(r) && out.size() < 16)
            out << r;
    }
    return out;
}

quint32 tribeScanDefaultRouter(const QByteArray &dump, int ifindex)
{
    quint32 scoped = 0;
    quint32 primary = 0;
#ifdef Q_OS_MACOS
    forEachDumpRoute(dump, [&](const DumpRoute &r) {
        if (!(r.h.rtm_flags & RTF_GATEWAY) || !r.gwInet || r.gw == 0 || r.dst != 0 || (r.haveMask && r.mask != 0)
            || int(r.h.rtm_index) != ifindex)
            return;
        if (r.h.rtm_flags & RTF_IFSCOPE) {
            if (!scoped)
                scoped = r.gw;
        } else if (!primary) {
            primary = r.gw;
        }
    });
#else
    Q_UNUSED(dump)
    Q_UNUSED(ifindex)
#endif
    return primary ? primary : scoped;
}

TribeScanDefaultRoute tribeScanPrimaryDefault(const QByteArray &dump)
{
    TribeScanDefaultRoute primary;
    TribeScanDefaultRoute scoped;
#ifdef Q_OS_MACOS
    forEachDumpRoute(dump, [&](const DumpRoute &r) {
        if (!(r.h.rtm_flags & RTF_GATEWAY) || !r.gwInet || r.gw == 0 || r.dst != 0 || (r.haveMask && r.mask != 0)
            || r.h.rtm_index <= 0)
            return;
        TribeScanDefaultRoute &slot = (r.h.rtm_flags & RTF_IFSCOPE) ? scoped : primary;
        if (slot.ifindex == 0) {
            slot.ifindex = int(r.h.rtm_index);
            slot.gateway = r.gw;
        }
    });
#else
    Q_UNUSED(dump)
#endif
    return primary.ifindex ? primary : scoped;
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

namespace {
// The path the probes bind to: the interface of the primary IPv4 default route and its router.
// macOS (round mac-D2, 25.11.2026): read from the retried route-table dump (dumpInetRoutes). The upstream helper
// (NetworkUtilities::getGatewayAndIface) sizes its buffer once; when the table grows between the size query and
// the dump - an AmneziaWG session and a scan add routes all the time - it gives up and answers "no gateway", and the
// host took that as a lost uplink: the scan's routes went ("uplink_changed") and the generation moved twice
// (device round D: 1 AmneziaWG scan of 3). A table that cannot be read is unknown, not "no uplink" (unreadable).
TribeScanUplink readUplink()
{
#ifdef Q_OS_MACOS
    const QByteArray table = dumpInetRoutes();
    if (table.isEmpty()) {
        TribeScanUplink u;
        u.unreadable = true;
        return u;
    }
    const TribeScanDefaultRoute d = tribeScanPrimaryDefault(table);
    if (d.ifindex > 0)
        return uplinkOf(QNetworkInterface::interfaceFromIndex(d.ifindex), QHostAddress(d.gateway).toString());
    // No IPv4 default route: an IPv6-only uplink, as the helper reports it (its gateway is IPv6).
#endif
    return readUplinkByHelper();
}
} // namespace

TribeScanDeps tribeScanServiceDeps()
{
    TribeScanDeps d;
    d.message = engineMessage;
    d.stopAll = engineStopAll;
    d.uplink = readUplink;
#ifdef Q_OS_MACOS
    d.armFirewall = [](const QString &ifname) { return MacOSFirewall::setScanExemption(ifname); };
    d.disarmFirewall = [] { MacOSFirewall::clearScanExemption(); };
    d.armRoutes = armUplinkRoutes;
    d.disarmRoutes = disarmUplinkRoutes;
    d.clearLeftoverRoutes = clearLeftoverUplinkRoutes;
    d.pinnedRoute = pinnedRouteExists;
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
    // Crash recovery: an exemption and half routes a previous service instance left behind (it died mid-scan).
    if (m_deps.disarmFirewall)
        m_deps.disarmFirewall();
    if (m_deps.clearLeftoverRoutes)
        m_deps.clearLeftoverRoutes();
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
        int index = 0;
        {
            QMutexLocker l(&m_mutex);
            index = m_active.serial != 0 ? m_active.uplinkIndex : 0;
        }
        if (const int unrouted = index > 0 ? unroutedTargets(req, index) : 0) {
            // Review N2: the same rule as a start - never a probe of a target the scan cannot reach (the app ends
            // those candidates «Не проверено»).
            qInfo() << "[tribescan] scan_add refused: targets without a pinned route:" << unrouted;
            return QByteArray(kErrNoUplink);
        }
        const QByteArray reply = m_deps.message ? m_deps.message(message, tribeScanHostOptions(gen, nullptr, nullptr, epoch))
                                                : QByteArray(kErrInternal);
        const TribeScanReplyInfo r = tribeScanInspectReply(reply);
        if (r.finalTotals && !r.scanId.isEmpty())
            endActive(r.scanId, "final");
        return reply;
    }

    quint64 serial = 0;
    bool exemptionFailed = false;
    bool routesFailed = false;
    {
        QMutexLocker fw(&m_fwMutex);
        const int arm = m_deps.armFirewall ? m_deps.armFirewall(up.name) : 0;
        // The half routes of a scan this one replaces go first, as its pf rule did above: the new scan takes the
        // uplink as it is now.
        QList<TribeScanHalfRoute> previous;
        {
            QMutexLocker l(&m_mutex);
            previous = m_active.routes;
            m_active.routes.clear();
        }
        if (!previous.isEmpty() && m_deps.disarmRoutes)
            m_deps.disarmRoutes(previous);
        TribeScanRouteArm routes = arm >= 0 && m_deps.armRoutes ? m_deps.armRoutes(up) : TribeScanRouteArm();
        // Review N2: every candidate's entry must have a route for a socket pinned to the uplink - a probe of a
        // target the scan cannot reach would come back "dial" and be stored as "not working".
        const int unrouted = arm >= 0 && routes.result >= 0 ? unroutedTargets(req, up.index) : 0;
        if (unrouted > 0) {
            if (!routes.added.isEmpty() && m_deps.disarmRoutes)
                m_deps.disarmRoutes(routes.added);
            routes = TribeScanRouteArm();
            routes.result = -1;
            qInfo() << "[tribescan] scan_start targets without a pinned route:" << unrouted << "of" << req.entryIps.size();
        }
        if (routes.result < 0 && arm > 0 && m_deps.disarmFirewall)
            m_deps.disarmFirewall(); // fail closed below: the exemption armed for it goes too
        QMutexLocker l(&m_mutex);
        if (arm < 0 || routes.result < 0) {
            exemptionFailed = arm < 0;
            routesFailed = !exemptionFailed;
            m_active = Active(); // the attempt flushed a previous scan's rule (and routes) too
        } else {
            m_active.scanId = req.scanId;
            m_active.serial = ++m_serial;
            m_active.armed = arm > 0;
            m_active.routes = routes.added;
            m_active.uplinkIndex = up.index;
            serial = m_active.serial;
        }
    }
    if (exemptionFailed || routesFailed) {
        // The kill switch is ours and blocks the uplink, and its exemption did not load - or a socket pinned to the
        // uplink has no route and the half routes did not come into force: fail closed (a probe there could only
        // fail, read as "nothing works"). A scan still running in the engine lost its rule as well, so it ends too.
        if (m_everStarted.load())
            teardown(exemptionFailed ? "kill_switch_exemption" : "uplink_routes", kTribeScanStopForAppMs);
        if (exemptionFailed) {
            qInfo() << "[tribescan] scan_start refused kill_switch_exemption";
            return QByteArray(kErrExemption);
        }
        qInfo() << "[tribescan] scan_start refused uplink_routes";
        return QByteArray(kErrNoUplink);
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
    if (up.unreadable) { // a failed table read says nothing about the path: the generation and the routes stay
        // Review of 25fc28096 (round mac-D3): ... but a loss the routing socket confirmed is a fact - deferred to the
        // next readable sample, never erased (the uplink may come back with the same fingerprint).
        if (loss) {
            QMutexLocker l(&m_mutex);
            m_lossPending = true;
        }
        qInfo() << "[tribescan] uplink not readable (route table read failed) - no path fact" << (loss ? "(a loss is kept)" : "");
        return;
    }
    const QByteArray fp = tribeScanUplinkFingerprint(up);
    ScanNetSource g;
    bool publish = false;
    bool moved = false;
    {
        QMutexLocker l(&m_mutex);
        loss = loss || std::exchange(m_lossPending, false);
        moved = m_gen.observe(fp, loss);
        m_lastUplinkIndex = tribeScanUplinkUsable(up) ? up.index : 0;
        g = m_gen.now();
        publish = !m_havePublished || g != m_published;
        m_published = g;
        m_havePublished = true;
    }
    if (publish)
        publishGeneration(g);
    if (moved)
        dropRoutes("uplink_changed");
}

int TribeScanHost::unroutedTargets(const TribeScanRequestInfo &req, int uplinkIndex) const
{
    if (!m_deps.pinnedRoute)
        return 0;
    int n = 0;
    for (const quint32 ip : req.entryIps)
        n += m_deps.pinnedRoute(uplinkIndex, ip) ? 0 : 1;
    return n;
}

void TribeScanHost::dropRoutes(const char *why)
{
    QMutexLocker fw(&m_fwMutex);
    QList<TribeScanHalfRoute> routes;
    {
        QMutexLocker l(&m_mutex);
        routes = m_active.routes;
        m_active.routes.clear();
    }
    if (routes.isEmpty() || !m_deps.disarmRoutes)
        return;
    m_deps.disarmRoutes(routes);
    qInfo() << "[tribescan] uplink routes removed:" << why;
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
    QList<TribeScanHalfRoute> routes;
    {
        QMutexLocker l(&m_mutex);
        if (m_active.serial == 0 || (!scanId.isEmpty() && m_active.scanId != scanId))
            return false;
        armed = m_active.armed;
        routes = m_active.routes;
        m_active = Active();
    }
    if (!routes.isEmpty() && m_deps.disarmRoutes) {
        m_deps.disarmRoutes(routes);
        qInfo() << "[tribescan] uplink routes removed:" << why;
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
        const TribeScanRouteEvent ev = tribeScanRouteEvent(buf, qsizetype(n), index, qint64(::getpid()));
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

// ---- round mac-D3: the ownership record of an Xray session's pinned-socket routes (tribe_scan.h) -------------------
namespace avpn {
QList<TribeScanHalfRoute> tribeXrayHalfRoutes(int ifindex, const QString &gatewayV4)
{
    const QHostAddress gw(gatewayV4);
    if (ifindex <= 0 || gw.protocol() != QAbstractSocket::IPv4Protocol)
        return {};
    const quint32 g = gw.toIPv4Address();
    return { TribeScanHalfRoute { kTribeScanHalfLow, g, ifindex }, TribeScanHalfRoute { kTribeScanHalfHigh, g, ifindex } };
}

bool tribeXrayRoutesWillBeAdded(const QString &ifname, const QString &gateway)
{
#ifdef Q_OS_MACOS
    const QList<TribeScanHalfRoute> routes = tribeXrayHalfRoutes(QNetworkInterface::interfaceIndexFromName(ifname), gateway);
    if (routes.isEmpty())
        return false;
    return writeRecordAt(kTribeXrayRoutesRecord, tribeScanHalfRoutesRecord(routes));
#else
    (void)ifname;
    (void)gateway;
    return false;
#endif
}

void tribeXrayRoutesDeleted()
{
#ifdef Q_OS_MACOS
    writeRecordAt(kTribeXrayRoutesRecord, QByteArray());
#endif
}
} // namespace avpn
