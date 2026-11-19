// client/core/serviceEngine/tests/scan_lab_e2e.cpp
// AVPN Scanner: the local end-to-end lab. ONE real scan through real components on this Mac: the REAL
// TribeScanner + ScanApiClient over real HTTP (QNetworkAccessManager) to a local backend, the REAL desktop host
// chain (DaemonScanHost -> QtRO on a local socket -> the service's TribeScanHost, tribe_scan.cpp) and the REAL
// Go probe engine (amnezia_xray_scan_message) probing through local Xray servers to the backend's /v1/probe.
// Fakes: only IScanEngine (no tunnel: desktop, VPN off) - built like the app's ScanEngineAdapter from the real
// /v1/config (ConfigTypes.h parseConfig + Ed25519 verify), the real /v1/subscription (SubscriptionParser) and the
// real XrayConfigBuilder - and the service's uplink reader (lo0, see LAB SHIM below).
//
// Never part of an ordinary gate: without TRIBE_SCAN_LAB=1 it prints "skipped" and exits 0. The lab around it
// (backend, redis, edge fronts, Xray servers, subscription) is ~/avpn-build/scan-lab (lab.sh, run-lab.sh);
// nothing here leaves 127.0.0.1: every app request is refused unless its host is loopback (LoopbackOnlyNam)
// and every probe socket of the engine is bound to lo0.
//
//   scan_lab_e2e register                 POST /v1/trial (as the app: WG public key, device id, platform macos)
//                                         + GET /v1/subscription?app_version=..., writes $LAB/device.json
//   scan_lab_e2e scan A|B|C|D|S           one scenario (A Wi-Fi, B cellular budget, C stop mid-scan,
//                                         D server switch off mid-run, S = A's single scan, used with a
//                                         server-side number override); journal on stdout, evidence JSON
//                                         in $LAB/runs/<scenario>.json
// Env: TRIBE_SCAN_LAB=1, SCAN_LAB_DIR (default ~/avpn-build/scan-lab), SCAN_LAB_API (http://127.0.0.1:48481),
//      SCAN_LAB_SWITCH_OFF (scenario D: a command that turns v1_scanner off), TRIBE_SCAN_LAB_ROOTS (the
//      engine's lab CA, read by the lab-built engine archive).
#include "tribe_scan.h"

#include "core/serviceEngine/ConfigTypes.h"
#include "core/serviceEngine/DaemonScanHost.h"
#include "core/serviceEngine/DoctorReport.h"
#include "core/serviceEngine/Ed25519Verify.h"
#include "core/serviceEngine/ScanHostContract.h"
#include "core/serviceEngine/SubscriptionParser.h"
#include "core/serviceEngine/TribeScanner.h"
#include "core/serviceEngine/TuningStore.h"
#include "core/serviceEngine/XrayConfigBuilder.h"

#include "rep_ipc_interface_source.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QProcess>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QRemoteObjectHost>
#include <QSet>
#include <QSettings>
#include <QStandardPaths>
#include <QThread>
#include <QTimer>
#include <QUrl>
#include <QUrlQuery>

#include <amnezia_xray.h>

#include <cstdio>
#include <functional>
#include <memory>
#include <net/if.h>

using namespace avpn;

namespace {

const char kDevConfigKey[] = "95da1bd9062653d9c185c3ca5cae995516a8e353abccd3cf98cd12cd2f3a075a"; // APP_ENV=dev seed
const char kAppVersion[] = "5.1.109.139"; // tribe_version.cmake of this branch
const char kProbeHost[] = "probe.scanlab.test";

QString g_lab;
QString g_api;
QJsonArray g_events; // the run's evidence (redacted)
qint64 g_t0 = 0;
int g_failed = 0;
int g_checks = 0;

qint64 nowMs() { return QDateTime::currentMSecsSinceEpoch(); }

void out(const QString &line)
{
    std::printf("%7.3f %s\n", double(nowMs() - g_t0) / 1000.0, qPrintable(line));
    std::fflush(stdout);
}

void evt(const QString &kind, const QJsonObject &o)
{
    QJsonObject e = o;
    e.insert(QStringLiteral("ev"), kind);
    e.insert(QStringLiteral("t_ms"), double(nowMs() - g_t0));
    g_events.append(e);
}

void check(bool ok, const QString &what)
{
    ++g_checks;
    if (!ok)
        ++g_failed;
    out(QStringLiteral("%1 %2").arg(ok ? QStringLiteral("CHECK ok  ") : QStringLiteral("CHECK FAIL"), what));
    evt(QStringLiteral("check"), {{QStringLiteral("ok"), ok}, {QStringLiteral("what"), what}});
}

template <typename P>
bool waitFor(P pred, int ms)
{
    QElapsedTimer t;
    t.start();
    while (!pred()) {
        if (t.elapsed() > ms)
            return false;
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(2);
    }
    return true;
}

void spin(int ms)
{
    waitFor([] { return false; }, ms);
}

// ---- the app's network access: loopback only, every reply journalled -----------------------------------------

class LoopbackOnlyNam : public QNetworkAccessManager
{
public:
    explicit LoopbackOnlyNam(QObject *parent = nullptr) : QNetworkAccessManager(parent)
    {
        connect(this, &QNetworkAccessManager::finished, this, [](QNetworkReply *r) {
            const int status = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            const QString path = r->request().url().path();
            const qint64 len = r->header(QNetworkRequest::ContentLengthHeader).toLongLong();
            out(QStringLiteral("[http] %1 %2 -> %3 (content-length %4)").arg(opName(r->operation()), path).arg(status).arg(len));
            evt(QStringLiteral("http"), {{QStringLiteral("op"), opName(r->operation())}, {QStringLiteral("path"), path},
                                           {QStringLiteral("status"), status}, {QStringLiteral("content_length"), double(len)}});
        });
    }
    int blocked = 0;

protected:
    QNetworkReply *createRequest(Operation op, const QNetworkRequest &req, QIODevice *data) override
    {
        const QString host = req.url().host();
        if (host != QLatin1String("127.0.0.1") && host != QLatin1String(kProbeHost)) {
            ++blocked;
            out(QStringLiteral("[http] BLOCKED a request to a non-loopback host (%1)").arg(host));
            evt(QStringLiteral("blocked"), {{QStringLiteral("host"), host}});
            QNetworkRequest dead(QUrl(QStringLiteral("http://127.0.0.1:9/blocked")));
            return QNetworkAccessManager::createRequest(op, dead, data);
        }
        return QNetworkAccessManager::createRequest(op, req, data);
    }

private:
    static QString opName(Operation op)
    {
        switch (op) {
        case GetOperation: return QStringLiteral("GET");
        case PostOperation: return QStringLiteral("POST");
        case DeleteOperation: return QStringLiteral("DELETE");
        case PutOperation: return QStringLiteral("PUT");
        default: return QStringLiteral("OTHER");
        }
    }
};

struct HttpResult {
    int status = 0;
    QByteArray body;
    QByteArray sig;
};

HttpResult httpCall(QNetworkAccessManager &nam, const QString &method, const QString &path, const QByteArray &body,
                    const QString &token)
{
    QNetworkRequest rq(QUrl(g_api + path));
    if (!token.isEmpty())
        rq.setRawHeader("Authorization", "Bearer " + token.toUtf8());
    rq.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    QNetworkReply *r = method == QLatin1String("POST") ? nam.post(rq, body) : nam.get(rq);
    waitFor([r] { return r->isFinished(); }, 20000);
    HttpResult h;
    h.status = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    h.body = r->readAll();
    h.sig = r->rawHeader("X-Tribe-Sig");
    r->deleteLater();
    return h;
}

// ---- the service's existing interface (witness replica only; never called) ------------------------------------

class WitnessSource : public IpcInterfaceSource
{
public:
    int createPrivilegedProcess() override { return -1; }
    int routeAddList(const QString &, const QStringList &) override { return 0; }
    bool clearSavedRoutes() override { return false; }
    bool routeDeleteList(const QString &, const QStringList &) override { return false; }
    bool flushDns() override { return false; }
    void resetIpStack() override {}
    bool checkAndInstallDriver() override { return false; }
    QStringList getTapList() override { return {}; }
    void cleanUp() override {}
    void setLogsEnabled(bool) override {}
    void clearLogs() override {}
    bool createTun(const QString &, const QString &) override { return false; }
    bool deleteTun(const QString &) override { return false; }
    bool StartRoutingIpv6() override { return false; }
    bool StopRoutingIpv6() override { return false; }
    bool disableKillSwitch() override { return false; }
    bool disableAllTraffic() override { return false; }
    bool refreshKillSwitch(bool) override { return false; }
    bool addKillSwitchAllowedRange(const QStringList) override { return false; }
    bool resetKillSwitchAllowedRange(const QStringList) override { return false; }
    bool enablePeerTraffic(const QJsonObject &) override { return false; }
    bool enableKillSwitch(const QJsonObject &, int) override { return false; }
    bool updateResolvers(const QString &, const QList<QHostAddress> &) override { return false; }
    bool restoreResolvers() override { return false; }
    bool xrayStart(const QString &) override { return false; }
    bool xrayStop() override { return false; }
    QJsonObject xrayRuntimeStatus(const QString &) override { return {}; }
    bool startNetworkCheck(const QString &, const QString &) override { return false; }
    bool stopNetworkCheck() override { return false; }
};

// The service's production glue to the real engine (tribeScanServiceDeps) with the platform readers replaced.
// LAB SHIM (test only): the uplink is lo0, reported as a usable physical uplink (loopback=false) - the service
// refuses a loopback uplink by design (tribeScanUplinkUsable), and the lab's whole network is lo0. No pf, no
// AmneziaWG probe binary, no live tunnel.
TribeScanDeps labServiceDeps()
{
    TribeScanDeps d = tribeScanServiceDeps();
    d.uplink = []() {
        TribeScanUplink u;
        u.name = QStringLiteral("lo0");
        u.index = int(if_nametoindex("lo0"));
        u.gateway = QStringLiteral("127.0.0.1");
        u.addresses = {QStringLiteral("127.0.0.1")};
        u.up = true;
        u.loopback = false; // LAB SHIM
        return u;
    };
    d.armFirewall = [](const QString &) { return 0; };
    d.disarmFirewall = []() {};
    d.awgProbeBinary = []() { return QString(); };
    d.awgLive = []() {
        TribeScanAwgLive l;
        l.state = 0;
        return l;
    };
    d.killProbeChildren = []() { return TribeScanKillResult(); };
    d.routeMonitor = false;
    return d;
}

// ---- a pure relay around the real host that journals what crossed (redacted) ----------------------------------

QJsonObject redactedRequest(const QJsonObject &o)
{
    QJsonObject r;
    for (const QString &k : {QStringLiteral("action"), QStringLiteral("scan_id"), QStringLiteral("since"),
                             QStringLiteral("deadline_ms"), QStringLiteral("max_bytes"), QStringLiteral("limits")})
        if (o.contains(k))
            r.insert(k, o.value(k));
    if (o.contains(QStringLiteral("probe"))) {
        QJsonObject p = o.value(QStringLiteral("probe")).toObject();
        p.remove(QStringLiteral("token"));
        if (p.contains(QStringLiteral("access_net_token")))
            p.insert(QStringLiteral("access_net_token"), p.value(QStringLiteral("access_net_token")).isNull() ? QJsonValue() : QJsonValue(QStringLiteral("<set>")));
        r.insert(QStringLiteral("probe"), p);
    }
    QJsonArray cands;
    for (const QJsonValue &v : o.value(QStringLiteral("candidates")).toArray()) {
        const QJsonObject c = v.toObject();
        QJsonObject x;
        for (const QString &k : {QStringLiteral("id"), QStringLiteral("kind"), QStringLiteral("profile_id"),
                                 QStringLiteral("cost_bytes"), QStringLiteral("reach_at_ms"), QStringLiteral("bytes"),
                                 QStringLiteral("total_ms"), QStringLiteral("early_retry"), QStringLiteral("dns_plan")})
            if (c.contains(k))
                x.insert(k, c.value(k));
        x.insert(QStringLiteral("config_bytes"), c.value(QStringLiteral("config")).toString().size());
        x.insert(QStringLiteral("entry"), c.value(QStringLiteral("entry")).isObject() ? QStringLiteral("<set>") : QStringLiteral("null"));
        cands.append(x);
    }
    if (!cands.isEmpty())
        r.insert(QStringLiteral("candidates"), cands);
    return r;
}

QJsonObject redactedReply(const QJsonObject &o)
{
    QJsonObject r = o;
    const QString accessTok = o.value(QStringLiteral("access")).toObject().value(QStringLiteral("net_token")).toString();
    if (o.contains(QStringLiteral("access"))) {
        QJsonObject a = o.value(QStringLiteral("access")).toObject();
        if (a.contains(QStringLiteral("net_token")))
            a.insert(QStringLiteral("net_token"), a.value(QStringLiteral("net_token")).isString() ? QStringLiteral("<set>") : QJsonValue());
        r.insert(QStringLiteral("access"), a);
    }
    if (o.contains(QStringLiteral("access_close"))) {
        QJsonObject a = o.value(QStringLiteral("access_close")).toObject();
        if (a.contains(QStringLiteral("net_token")))
            a.insert(QStringLiteral("net_token"), a.value(QStringLiteral("net_token")).isString() ? QStringLiteral("<set>") : QJsonValue());
        r.insert(QStringLiteral("access_close"), a);
    }
    QJsonArray items;
    for (const QJsonValue &v : o.value(QStringLiteral("items")).toArray()) {
        QJsonObject it = v.toObject();
        if (it.contains(QStringLiteral("net_token"))) {
            const QString t = it.value(QStringLiteral("net_token")).toString();
            it.insert(QStringLiteral("net_token"), t.isEmpty() ? QStringLiteral("<none>")
                                                    : (t == accessTok ? QStringLiteral("<equals access>") : QStringLiteral("<differs>")));
        }
        items.append(it);
    }
    if (o.contains(QStringLiteral("items")))
        r.insert(QStringLiteral("items"), items);
    return r;
}

class JournalHost : public IScanHost
{
public:
    explicit JournalHost(IScanHost *inner) : m_in(inner)
    {
        m_in->onAvailabilityChanged = [this]() {
            if (onAvailabilityChanged)
                onAvailabilityChanged();
        };
        m_in->onGenerationChanged = [this]() {
            if (onGenerationChanged)
                onGenerationChanged();
        };
    }
    ScanHostCaps knownCaps() const override { return m_in->knownCaps(); }
    ScanHostAvailability availability() const override { return m_in->availability(); }
    QString unavailableReason() const override { return m_in->unavailableReason(); }
    bool generation(ScanNetSource &o) const override { return m_in->generation(o); }
    void stopAll() override
    {
        out(QStringLiteral("[host] stopAll"));
        evt(QStringLiteral("host_stop_all"), {});
        m_in->stopAll();
    }
    void sendMessage(const QByteArray &request, ReplyFn reply) override
    {
        const QJsonObject rq = QJsonDocument::fromJson(request).object();
        const QString action = rq.value(QStringLiteral("action")).toString();
        const bool poll = action == QLatin1String("scan_poll");
        const QJsonObject rr = redactedRequest(rq);
        if (!poll)
            out(QStringLiteral("[host] -> %1 %2").arg(action, QString::fromUtf8(QJsonDocument(rr).toJson(QJsonDocument::Compact)).left(1500)));
        evt(QStringLiteral("host_request"), rr);
        m_in->sendMessage(request, [action, poll, reply](const QByteArray &b) {
            const QJsonObject o = QJsonDocument::fromJson(b).object();
            const QJsonObject red = redactedReply(o);
            const bool quietPoll = poll && o.value(QStringLiteral("items")).toArray().isEmpty() && !o.value(QStringLiteral("final")).toBool()
                                   && !o.value(QStringLiteral("done")).toBool();
            if (!quietPoll)
                out(QStringLiteral("[host] <- %1 %2").arg(action, b.isEmpty() ? QStringLiteral("<no answer>")
                                                                              : QString::fromUtf8(QJsonDocument(red).toJson(QJsonDocument::Compact)).left(3000)));
            QJsonObject e = red;
            e.insert(QStringLiteral("action"), action);
            e.insert(QStringLiteral("empty"), b.isEmpty());
            evt(QStringLiteral("host_reply"), e);
            reply(b);
        });
    }

private:
    IScanHost *m_in;
};

// ---- the engine side (fake: no tunnel), built like the app's ScanEngineAdapter --------------------------------

struct LabEngine : IScanEngine {
    Subscription sub;
    ScanNetFacts net;
    QNetworkAccessManager *nam = nullptr;
    QString token;
    TribeScanner *scanner = nullptr;
    int userConnects = 0, cancels = 0, rowCalls = 0;
    QStringList reportIds;
    QJsonObject lastBenchBody;
    int lastBenchStatus = 0;

    ScanCurrent current() const override { return ScanCurrent(); } // desktop, VPN off
    ScanNetFacts network() const override { return net; }
    void fillManifestInput(ScanManifestInput &in) const override
    {
        for (const SubscriptionNode &n : sub.nodes) {
            if (n.upstream.has_value()) {
                const QString pid = n.nodeId.startsWith(QLatin1String("up:")) ? n.nodeId.mid(3) : n.nodeId;
                in.upstreamNames.insert(pid, n.name.isEmpty() ? QStringLiteral("Сервер") : n.name);
                continue;
            }
            ScanOwnNode o;
            o.nodeId = n.nodeId;
            o.label = n.name;
            o.countryCode = n.countryCode;
            const bool xray = n.proto == QLatin1String("xray");
            o.transport = xray ? ScanTransport::Xray : ScanTransport::Awg;
            const int colon = n.endpoint.lastIndexOf(QLatin1Char(':'));
            o.entryIp = n.endpoint.left(colon);
            o.entryPort = n.endpoint.mid(colon + 1).toInt();
            o.manualOnly = n.manualOnly;
            o.ru = n.countryCode.compare(QLatin1String("RU"), Qt::CaseInsensitive) == 0;
            if (xray)
                o.configAvailable = n.xray.has_value() && !XrayConfigBuilder::coreConfig(n).isEmpty();
            in.ownNodes << o;
        }
        in.awgAddressKnown = !sub.address.isEmpty();
        in.awgProbeIpKnown = true;
    }
    QString ownProbeConfig(const ScanCandidate &c) const override
    {
        // As AvpnEngineQml.cpp ScanEngineAdapter::ownProbeConfig.
        for (const SubscriptionNode &n : sub.nodes) {
            if (n.nodeId != c.id || n.upstream.has_value() || !n.xray.has_value())
                continue;
            if (c.kind == ScanProbeKind::XrayFull)
                return XrayConfigBuilder::coreConfigText(n);
            if (c.kind == ScanProbeKind::XrayLeg) {
                const QJsonArray outs = XrayConfigBuilder::coreConfig(n).value(QStringLiteral("outbounds")).toArray();
                if (outs.isEmpty() || !outs.first().isObject())
                    return {};
                return QString::fromUtf8(QJsonDocument(QJsonObject{{QStringLiteral("outbound"), outs.first().toObject()},
                                                                   {QStringLiteral("dns"), QJsonArray()}})
                                             .toJson(QJsonDocument::Compact));
            }
        }
        return {};
    }
    QString liveProbeBase(const ScanCurrent &) const override { return {}; }
    bool reportQueueFull() const override { return false; }
    QString uiLanguage() const override { return QStringLiteral("ru"); }
    QStringList knownHostIps(const QString &host) const override
    {
        return host == QLatin1String(kProbeHost) ? QStringList{QStringLiteral("127.0.0.1")} : QStringList();
    }
    void userConnectForScan() override
    {
        ++userConnects;
        out(QStringLiteral("[engine] userConnectForScan (must not happen on desktop)"));
    }
    void cancelPendingConnect() override { ++cancels; }
    void connectRow(const QString &nodeId, const QStringList &, qint64, bool, bool) override
    {
        ++rowCalls;
        out(QStringLiteral("[engine] connectRow %1").arg(nodeId));
    }
    // FAKE of the engine's full check: the schema-5 report is built with the app's real builder and validator
    // (DoctorReport.h buildCheckReport / fitCheckReport / checkReportValid) around the machine's own summary, and
    // POSTed to /v1/bench/report as the bench copy (the support queue of TribeSupportChat is not in the lab).
    void startReportCheck(const QString &reportId, const QJsonObject &report, bool withConnection) override
    {
        reportIds << reportId;
        out(QStringLiteral("[engine] startReportCheck id=%1 with_connection=%2 keys=%3")
                .arg(reportId).arg(int(withConnection)).arg(QStringList(report.keys()).join(QLatin1Char(','))));
        evt(QStringLiteral("report_check_machine_report"), report);
        QTimer::singleShot(0, [this, reportId, report, withConnection]() {
            scanner->reportCheckStarted();
            QList<doctor::StageResult> stages;
            stages << doctor::StageResult{QStringLiteral("network"), doctor::Ok, QStringLiteral("Wi-Fi"), QJsonObject{{QStringLiteral("net_type"), QStringLiteral("wifi")}}};
            stages << doctor::StageResult{QStringLiteral("connect"), doctor::Skip, QStringLiteral("VPN выключен"), {}};
            QJsonObject extra{{QStringLiteral("doctor_mode"), QStringLiteral("check")},
                              {QStringLiteral("lab"), QStringLiteral("scan-lab-e2e")},
                              {QStringLiteral("check"), QJsonObject{{QStringLiteral("id"), report.value(QStringLiteral("id"))},
                                                                    {QStringLiteral("created_at_ms"), report.value(QStringLiteral("created_at_ms"))},
                                                                    {QStringLiteral("with_connection"), withConnection},
                                                                    {QStringLiteral("scan_stats"), report.value(QStringLiteral("scan_stats"))}}}};
            QJsonObject rep = doctor::fitCheckReport(doctor::buildCheckReport(stages, extra, report.value(QStringLiteral("scan")).toObject()));
            QString why;
            const bool valid = doctor::checkReportValid(rep, &why);
            out(QStringLiteral("[engine] doctor report schema=%1 client-valid=%2 %3 scan=%4")
                    .arg(rep.value(QStringLiteral("schema")).toInt()).arg(int(valid)).arg(why)
                    .arg(QString::fromUtf8(QJsonDocument(rep.value(QStringLiteral("scan")).toObject()).toJson(QJsonDocument::Compact)).left(1500)));
            lastBenchBody = rep;
            const HttpResult h = httpCall(*nam, QStringLiteral("POST"), QStringLiteral("/v1/bench/report"),
                                          QJsonDocument(rep).toJson(QJsonDocument::Compact), token);
            lastBenchStatus = h.status;
            out(QStringLiteral("[engine] POST /v1/bench/report -> %1 %2").arg(h.status).arg(QString::fromUtf8(h.body).left(300)));
            evt(QStringLiteral("bench_report"), {{QStringLiteral("status"), h.status}, {QStringLiteral("client_valid"), valid},
                                                   {QStringLiteral("why"), why}, {QStringLiteral("body"), rep}});
            scanner->reportCheckDone(h.status == 201, reportId);
        });
    }
};

// ---- view journal -----------------------------------------------------------------------------------------------

QString rowsLine(const QVariantMap &view)
{
    QStringList parts;
    for (const QVariant &v : view.value(QStringLiteral("rows")).toList()) {
        const QVariantMap r = v.toMap();
        parts << QStringLiteral("%1[%2 %3 %4ms %5]").arg(r.value(QStringLiteral("id")).toString(), r.value(QStringLiteral("state")).toString(),
                                                        r.value(QStringLiteral("speed")).toString(), r.value(QStringLiteral("ms")).toString(),
                                                        r.value(QStringLiteral("flags")).toStringList().join(QLatin1Char('|')));
    }
    return parts.join(QLatin1Char(' '));
}

QString phaseOf(TribeScanner &s) { return s.view().value(QStringLiteral("phase")).toString(); }

QJsonObject readJson(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return {};
    return QJsonDocument::fromJson(f.readAll()).object();
}

void writeJson(const QString &path, const QJsonObject &o)
{
    QFile f(path);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        f.write(QJsonDocument(o).toJson(QJsonDocument::Indented));
    f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
}

// ---- register -------------------------------------------------------------------------------------------------

int doRegister(QNetworkAccessManager &nam)
{
    QByteArray pk(32, Qt::Uninitialized);
    for (int i = 0; i < 32; ++i)
        pk[i] = char(QRandomGenerator::system()->bounded(256));
    const QString publicKey = QString::fromLatin1(pk.toBase64());
    const QString deviceId = QStringLiteral("scanlab-") + QString::fromLatin1(QCryptographicHash::hash(pk, QCryptographicHash::Sha256).toHex().left(24));
    const QJsonObject body{{QStringLiteral("public_key"), publicKey}, {QStringLiteral("device_id"), deviceId},
                           {QStringLiteral("platform"), QStringLiteral("macos")}, {QStringLiteral("model"), QStringLiteral("scan-lab")}};
    const HttpResult t = httpCall(nam, QStringLiteral("POST"), QStringLiteral("/v1/trial"), QJsonDocument(body).toJson(QJsonDocument::Compact), QString());
    out(QStringLiteral("POST /v1/trial -> %1 %2").arg(t.status).arg(QString::fromUtf8(t.body).replace(QRegularExpression(QStringLiteral("\"subscription_token\":\"[^\"]+\"")), QStringLiteral("\"subscription_token\":\"<redacted>\"")).left(300)));
    if (t.status != 200)
        return 1;
    const QString token = QJsonDocument::fromJson(t.body).object().value(QStringLiteral("subscription_token")).toString();
    const HttpResult s = httpCall(nam, QStringLiteral("GET"), QStringLiteral("/v1/subscription?app_version=%1").arg(QLatin1String(kAppVersion)), {}, token);
    out(QStringLiteral("GET /v1/subscription -> %1 (%2 bytes)").arg(s.status).arg(s.body.size()));
    writeJson(g_lab + QStringLiteral("/device.json"), {{QStringLiteral("token"), token}, {QStringLiteral("device_id"), deviceId},
                                                      {QStringLiteral("public_key"), publicKey}});
    out(QStringLiteral("device registered: %1/device.json").arg(g_lab));
    return 0;
}

// ---- scan -------------------------------------------------------------------------------------------------------

bool applyConfig(QNetworkAccessManager &nam)
{
    const HttpResult c = httpCall(nam, QStringLiteral("GET"), QStringLiteral("/v1/config"), {}, QString());
    const bool sigOk = verifyDetached(QLatin1String(kDevConfigKey), c.body, c.sig);
    RemoteConfig rc;
    QString err;
    const bool parsed = parseConfig(c.body, rc, err);
    check(c.status == 200 && sigOk && parsed, QStringLiteral("/v1/config signed by the dev key and parsed (status %1, sig %2, parse %3)")
                                                  .arg(c.status).arg(int(sigOk)).arg(parsed ? QStringLiteral("ok") : err));
    TuningStore::set(rc.numbers, rc.features, rc.lists, rc.urls);
    QStringList scanNums;
    for (auto it = rc.numbers.cbegin(); it != rc.numbers.cend(); ++it)
        if (it.key().startsWith(QLatin1String("scan")))
            scanNums << QStringLiteral("%1=%2").arg(it.key()).arg(it.value());
    out(QStringLiteral("features: scanner=%1 scanner_connect_on_open=%2 upstream_nodes=%3; scan numbers: %4")
            .arg(int(TuningStore::flag(QStringLiteral("scanner"), false)))
            .arg(int(TuningStore::flag(QStringLiteral("scanner_connect_on_open"), true)))
            .arg(int(TuningStore::flag(QStringLiteral("upstream_nodes"), false)))
            .arg(scanNums.join(QLatin1Char(' '))));
    return sigOk && parsed;
}

// The probe side's TCP connections of this process still open: remote ports of the lab's proxies (link relays) and
// of the probe host's fronts (every front but the app's API front). The engine runs in this process.
int probeSocketsLeft(QString *detail)
{
    const QJsonObject w = readJson(g_lab + QStringLiteral("/world/world.json"));
    QSet<int> ports;
    for (const QJsonValue &v : w.value(QStringLiteral("servers")).toArray())
        ports.insert(v.toObject().value(QStringLiteral("port")).toInt());
    for (const QJsonValue &v : w.value(QStringLiteral("fronts")).toArray())
        if (v.toObject().value(QStringLiteral("name")).toString() != QLatin1String("app"))
            ports.insert(v.toObject().value(QStringLiteral("port")).toInt());
    QProcess p;
    p.start(QStringLiteral("/usr/sbin/lsof"), {QStringLiteral("-nP"), QStringLiteral("-a"), QStringLiteral("-p"),
                                               QString::number(QCoreApplication::applicationPid()), QStringLiteral("-iTCP")});
    p.waitForFinished(10000);
    int n = 0;
    QStringList lines;
    for (const QString &line : QString::fromUtf8(p.readAllStandardOutput()).split(QLatin1Char('\n'))) {
        const int arrow = line.indexOf(QLatin1String("->"));
        if (arrow < 0)
            continue;
        const QString remote = line.mid(arrow + 2).section(QLatin1Char(' '), 0, 0);
        const int port = remote.section(QLatin1Char(':'), -1).toInt();
        if (ports.contains(port)) {
            ++n;
            lines << line.simplified();
        }
    }
    if (detail)
        *detail = lines.join(QStringLiteral(" | "));
    return n;
}

// Tries the machine's report paths in the current state; returns true when a schema-5 report reached the server.
bool reportPath(TribeScanner &scanner, LabEngine &engine, const QString &when)
{
    const int before = engine.reportIds.size();
    scanner.checkFromSupport();
    const bool viaCheck = waitFor([&]() { return engine.reportIds.size() > before; }, 2000);
    if (!viaCheck)
        scanner.tapReportLink();
    const bool started = viaCheck || waitFor([&]() { return engine.reportIds.size() > before; }, 2000);
    const QString phase = scanner.view().value(QStringLiteral("phase")).toString();
    if (!started) {
        out(QStringLiteral("REPORT: no report path %1 (phase %2; Support's check needs a live connection, the link exists in empty / no_scan / done without one)").arg(when, phase));
        evt(QStringLiteral("report_path"), {{QStringLiteral("when"), when}, {QStringLiteral("phase"), phase}, {QStringLiteral("started"), false}});
        return false;
    }
    engine.lastBenchStatus = 0;
    waitFor([&]() { return engine.lastBenchStatus != 0; }, 10000);
    check(engine.lastBenchStatus == 201, QStringLiteral("report %1 via %2 in phase %3: POST /v1/bench/report (doctor schema 5) -> %4")
                                             .arg(when, viaCheck ? QStringLiteral("checkFromSupport") : QStringLiteral("tapReportLink"), phase)
                                             .arg(engine.lastBenchStatus));
    evt(QStringLiteral("report_path"), {{QStringLiteral("when"), when}, {QStringLiteral("phase"), phase}, {QStringLiteral("started"), true},
                                        {QStringLiteral("status"), engine.lastBenchStatus}});
    spin(1500);
    return engine.lastBenchStatus == 201;
}

int doScan(QNetworkAccessManager &nam, const QString &scenario)
{
    const QJsonObject dev = readJson(g_lab + QStringLiteral("/device.json"));
    const QString token = dev.value(QStringLiteral("token")).toString();
    if (token.isEmpty()) {
        out(QStringLiteral("no device: run 'register' first"));
        return 2;
    }
    applyConfig(nam);

    LabEngine engine;
    engine.nam = &nam;
    engine.token = token;
    {
        const HttpResult s = httpCall(nam, QStringLiteral("GET"), QStringLiteral("/v1/subscription?app_version=%1").arg(QLatin1String(kAppVersion)), {}, token);
        QString err;
        const bool ok = SubscriptionParser::parse(s.body, engine.sub, err);
        QStringList ids;
        for (const SubscriptionNode &n : engine.sub.nodes)
            ids << QStringLiteral("%1(%2%3)").arg(n.nodeId, n.proto, n.upstream.has_value() ? QStringLiteral(",stub") : (n.xray.has_value() ? QStringLiteral(",xray") : QString()));
        check(s.status == 200 && ok, QStringLiteral("/v1/subscription parsed by SubscriptionParser: %1 nodes [%2] %3").arg(engine.sub.nodes.size()).arg(ids.join(QLatin1Char(' ')), err));
    }
    ScanNetSource app;
    app.source = QStringLiteral("app");
    app.epoch = 0x5ca71ab000000001ULL + quint64(QRandomGenerator::global()->bounded(1 << 20));
    app.counter = 0;
    engine.net.appSources << app;
    if (scenario == QLatin1String("B")) {
        engine.net.kind = ScanNetKind::Cellular;
        engine.net.reportingKey = QStringLiteral("cell:250-02:4g");
    } else {
        engine.net.kind = ScanNetKind::Wifi;
        engine.net.reportingKey = QStringLiteral("wifi");
    }

    // The desktop host chain: DaemonScanHost -> QtRO local socket -> TribeScanHost (the service) -> the engine.
    const QUrl url(QStringLiteral("local:%1/run/ipc-%2").arg(g_lab).arg(QCoreApplication::applicationPid()));
    QDir().mkpath(g_lab + QStringLiteral("/run"));
    auto node = std::make_unique<QRemoteObjectHost>(url);
    WitnessSource witness;
    auto service = std::make_unique<TribeScanHost>(labServiceDeps());
    check(node->enableRemoting(&witness) && node->enableRemoting(service.get()), QStringLiteral("service sources remoted on a local socket"));
    DaemonScanHost daemonHost(DaemonScanHost::serviceTransport(url));
    check(waitFor([&]() { return daemonHost.availability() == ScanHostAvailability::Available; }, 8000),
          QStringLiteral("DaemonScanHost Available (reason '%1')").arg(daemonHost.unavailableReason()));
    JournalHost host(&daemonHost);

    TribeScanner::Deps deps;
    deps.engine = &engine;
    deps.host = &host;
    TribeScanner scanner(deps);
    engine.scanner = &scanner;
    scanner.log = [](const QString &line) {
        out(QStringLiteral("[scanner] ") + line);
        evt(QStringLiteral("journal"), {{QStringLiteral("line"), line}});
    };
    scanner.configureApi(&nam, []() { return g_api; }, []() { return QString::fromLatin1(kDevConfigKey); }, [token]() { return token; });
    QString lastView;
    QObject::connect(&scanner, &TribeScanner::viewChanged, [&]() {
        const QVariantMap v = scanner.view();
        const QString line = QStringLiteral("phase=%1 stage=%2 progress=%3 verified=%4 unverified=%5 rows=%6 empty=%7")
                                 .arg(v.value(QStringLiteral("phase")).toString(), v.value(QStringLiteral("stage")).toString(),
                                      v.value(QStringLiteral("progress")).toString(), v.value(QStringLiteral("verified")).toString(),
                                      v.value(QStringLiteral("unverified")).toString(), rowsLine(v),
                                      QString::fromUtf8(QJsonDocument(QJsonObject::fromVariantMap(v.value(QStringLiteral("empty")).toMap())).toJson(QJsonDocument::Compact)));
        if (line != lastView) {
            lastView = line;
            out(QStringLiteral("[view] ") + line);
            evt(QStringLiteral("view"), QJsonObject::fromVariantMap(v));
        }
    });
    QObject::connect(&scanner, &TribeScanner::shadeChanged, [&]() {
        const QVariantMap s = scanner.shade();
        if (s.value(QStringLiteral("visible")).toBool())
            out(QStringLiteral("[shade] %1 %2").arg(s.value(QStringLiteral("tone")).toString(), s.value(QStringLiteral("text_key")).toString()));
    });
    QObject::connect(&scanner, &TribeScanner::serverSwitchedOff, []() { out(QStringLiteral("[scanner] signal serverSwitchedOff")); });
    check(scanner.enabled(), QStringLiteral("TribeScanner enabled by features.scanner from the real /v1/config"));
    spin(500); // the constructor's scan_caps

    const auto terminal = [&]() {
        const QString p = phaseOf(scanner);
        return p == QLatin1String("done") || p == QLatin1String("empty") || p == QLatin1String("no_scan");
    };
    QJsonObject result;
    if (scenario == QLatin1String("A") || scenario == QLatin1String("B") || scenario == QLatin1String("S")) {
        scanner.open();
        check(waitFor(terminal, 60000), QStringLiteral("scan reached a final phase: %1").arg(phaseOf(scanner)));
        spin(3000); // outcomes, release, final totals
        out(QStringLiteral("final view: ") + lastView);
        result.insert(QStringLiteral("final_view"), QJsonObject::fromVariantMap(scanner.view()));
        // The full check («Проверить и отправить отчёт») needs the card (a live connection); without one the report
        // link is offered in Empty, NoScan and Done (lab seam S7): desktop with the VPN off sends through the link.
        reportPath(scanner, engine, QStringLiteral("after the scan"));
        if (scenario == QLatin1String("A")) {
            // A second scan on the same network after the manual cooldown: the stored manifest is revalidated
            // (If-None-Match -> 304) and the token comes from POST /v1/scan/token.
            const qint64 cd = scanner.view().value(QStringLiteral("cooldown_ends_at_ms")).toLongLong();
            if (cd > nowMs())
                spin(int(qMin<qint64>(cd - nowMs() + 300, 35000)));
            int mark = g_events.size();
            out(QStringLiteral("SECOND SCAN (retry after the cooldown)"));
            scanner.retry();
            spin(300);
            check(waitFor(terminal, 60000), QStringLiteral("second scan reached a final phase: %1").arg(phaseOf(scanner)));
            spin(3000);
            bool m304 = false, tok = false;
            for (int i = mark; i < g_events.size(); ++i) {
                const QJsonObject e = g_events.at(i).toObject();
                if (e.value(QStringLiteral("ev")).toString() != QLatin1String("http"))
                    continue;
                if (e.value(QStringLiteral("path")).toString() == QLatin1String("/v1/scan/manifest") && e.value(QStringLiteral("status")).toInt() == 304)
                    m304 = true;
                if (e.value(QStringLiteral("path")).toString() == QLatin1String("/v1/scan/token") && e.value(QStringLiteral("status")).toInt() == 200)
                    tok = true;
            }
            check(m304 && tok, QStringLiteral("second scan: manifest revalidated 304 (%1) and token from /v1/scan/token (%2)").arg(int(m304)).arg(int(tok)));
            result.insert(QStringLiteral("second_view"), QJsonObject::fromVariantMap(scanner.view()));
        }
        scanner.close();
        spin(2000);
    } else if (scenario == QLatin1String("C")) {
        scanner.open();
        const bool probing = waitFor([&]() {
            const QString p = phaseOf(scanner);
            return p == QLatin1String("data") || p == QLatin1String("reach");
        }, 30000);
        check(probing, QStringLiteral("scan is probing before the stop (%1)").arg(phaseOf(scanner)));
        spin(700);
        out(QStringLiteral("STOP pressed in phase %1").arg(phaseOf(scanner)));
        evt(QStringLiteral("stop_pressed"), {{QStringLiteral("phase"), phaseOf(scanner)}});
        scanner.stop();
        // «Остановить» ends the scan and closes the screen (closeScreenRequested): the machine goes idle.
        check(waitFor([&]() { return terminal() || phaseOf(scanner) == QLatin1String("idle"); }, 15000),
              QStringLiteral("after stop: phase %1, screen open %2").arg(phaseOf(scanner)).arg(int(scanner.screenOpen())));
        spin(4000); // freeze ack, drain, final totals, release
        result.insert(QStringLiteral("final_view"), QJsonObject::fromVariantMap(scanner.view()));
        reportPath(scanner, engine, QStringLiteral("after the stop"));
        scanner.close();
        spin(1500);
    } else if (scenario == QLatin1String("D")) {
        scanner.open();
        const bool probing = waitFor([&]() {
            const QString p = phaseOf(scanner);
            return p == QLatin1String("data") || p == QLatin1String("reach");
        }, 30000);
        check(probing, QStringLiteral("scan is probing before the switch goes off (%1)").arg(phaseOf(scanner)));
        const QString cmd = qEnvironmentVariable("SCAN_LAB_SWITCH_OFF");
        out(QStringLiteral("SERVER SWITCH OFF (v1_scanner=false) in phase %1").arg(phaseOf(scanner)));
        evt(QStringLiteral("switch_off"), {{QStringLiteral("phase"), phaseOf(scanner)}});
        QProcess p;
        p.start(QStringLiteral("/bin/bash"), {QStringLiteral("-c"), cmd});
        waitFor([&]() { return p.state() == QProcess::NotRunning; }, 20000);
        out(QStringLiteral("switch command exit %1: %2").arg(p.exitCode()).arg(QString::fromUtf8(p.readAllStandardOutput()).trimmed()));
        check(waitFor(terminal, 60000), QStringLiteral("the running scan ended: %1").arg(phaseOf(scanner)));
        spin(3000);
        result.insert(QStringLiteral("view_after_running_scan"), QJsonObject::fromVariantMap(scanner.view()));
        // The next scan: «Повторить» (after the cooldown the machine may refuse; wait it out).
        const qint64 cd = scanner.view().value(QStringLiteral("cooldown_ends_at_ms")).toLongLong();
        if (cd > nowMs())
            spin(int(qMin<qint64>(cd - nowMs() + 300, 35000)));
        scanner.retry();
        spin(500);
        if (phaseOf(scanner) != QLatin1String("no_scan")) {
            scanner.close();
            spin(300);
            scanner.open();
        }
        waitFor([&]() { return phaseOf(scanner) == QLatin1String("no_scan"); }, 20000);
        const QString reason = scanner.view().value(QStringLiteral("empty")).toMap().value(QStringLiteral("reason")).toString();
        check(phaseOf(scanner) == QLatin1String("no_scan") && reason == QLatin1String("scanner_off"),
              QStringLiteral("after the switch: NoScan scanner_off (phase %1, reason '%2')").arg(phaseOf(scanner), reason));
        result.insert(QStringLiteral("view_after_switch"), QJsonObject::fromVariantMap(scanner.view()));
        // open / retry request nothing more while the switch is off.
        int before = 0, after = 0;
        for (const QJsonValue &e : g_events)
            if (e.toObject().value(QStringLiteral("ev")).toString() == QLatin1String("http"))
                ++before;
        scanner.retry();
        scanner.close();
        scanner.open();
        spin(2000);
        for (const QJsonValue &e : g_events)
            if (e.toObject().value(QStringLiteral("ev")).toString() == QLatin1String("http"))
                ++after;
        check(after == before, QStringLiteral("while scanner_off, open/retry made no request (%1 -> %2)").arg(before).arg(after));
        // The server switch back on (the operator); the screen still shows NoScan scanner_off: its report link
        // sends the check to a server that validates schema 5 again.
        const QString on = qEnvironmentVariable("SCAN_LAB_SWITCH_ON");
        QProcess p2;
        p2.start(QStringLiteral("/bin/bash"), {QStringLiteral("-c"), on});
        waitFor([&]() { return p2.state() == QProcess::NotRunning; }, 20000);
        out(QStringLiteral("SERVER SWITCH ON again: exit %1").arg(p2.exitCode()));
        reportPath(scanner, engine, QStringLiteral("in NoScan scanner_off"));
        scanner.close();
        spin(500);
    }

    // The ledger as stored (avpn/scanBudget) and the machine's view of it.
    QSettings st;
    const QVariant ledger = st.value(QLatin1String(kScanBudgetStoreKey));
    out(QStringLiteral("ledger avpn/scanBudget = %1").arg(ledger.toString().left(2000)));
    result.insert(QStringLiteral("ledger"), QJsonValue::fromVariant(ledger));
    result.insert(QStringLiteral("blocked_requests"), static_cast<LoopbackOnlyNam &>(nam).blocked);
    result.insert(QStringLiteral("user_connects"), engine.userConnects);
    result.insert(QStringLiteral("row_connects"), engine.rowCalls);
    check(static_cast<LoopbackOnlyNam &>(nam).blocked == 0, QStringLiteral("no app request went to a non-loopback host"));
    check(engine.userConnects == 0 && engine.rowCalls == 0, QStringLiteral("the scan never asked the engine to connect (desktop, VPN off)"));

    // Nothing of the probes left alive: no probe-side connection of this process, and the engine's own stop
    // answers stopped=true.
    QString left;
    const int leftN = probeSocketsLeft(&left);
    check(leftN == 0, QStringLiteral("no probe connection left open after the scan (%1) %2").arg(leftN).arg(left));
    result.insert(QStringLiteral("probe_sockets_left"), leftN);
    char *stop = amnezia_xray_scan_stop_all(3000);
    const QString stopReply = QString::fromUtf8(stop);
    amnezia_xray_free(stop);
    out(QStringLiteral("engine stop_all after the run: %1").arg(stopReply));
    result.insert(QStringLiteral("engine_stop_all"), stopReply);
    result.insert(QStringLiteral("events"), g_events);
    result.insert(QStringLiteral("checks"), g_checks);
    result.insert(QStringLiteral("failed"), g_failed);
    QDir().mkpath(g_lab + QStringLiteral("/runs"));
    writeJson(g_lab + QStringLiteral("/runs/%1.json").arg(scenario), result);
    out(QStringLiteral(">>> scenario %1: %2 checks, %3 failed; evidence %4/runs/%1.json").arg(scenario).arg(g_checks).arg(g_failed).arg(g_lab));
    return g_failed == 0 ? 0 : 1;
}

} // namespace

int main(int argc, char **argv)
{
    if (qEnvironmentVariable("TRIBE_SCAN_LAB") != QLatin1String("1")) {
        std::printf("scan_lab_e2e: skipped (TRIBE_SCAN_LAB is not 1)\n");
        return 0;
    }
    // The app's QSettings and data stay in the lab: an INI file in the lab dir, never the real app's preferences.
    g_lab = qEnvironmentVariable("SCAN_LAB_DIR", QDir::homePath() + QStringLiteral("/avpn-build/scan-lab"));
    g_api = qEnvironmentVariable("SCAN_LAB_API", QStringLiteral("http://127.0.0.1:48481"));
    QCoreApplication::setOrganizationName(QStringLiteral("TribeScanLab"));
    QCoreApplication::setApplicationName(QStringLiteral("TribeScanLab"));
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, g_lab + QStringLiteral("/settings"));
    QCoreApplication app(argc, argv);
    g_t0 = nowMs();
    const QString mode = argc > 1 ? QString::fromLocal8Bit(argv[1]) : QString();
    LoopbackOnlyNam nam;
    if (mode == QLatin1String("register"))
        return doRegister(nam);
    if (mode == QLatin1String("scan") && argc > 2)
        return doScan(nam, QString::fromLocal8Bit(argv[2]));
    std::printf("usage: scan_lab_e2e register | scan A|B|C|D|S\n");
    return 2;
}
