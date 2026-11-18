// AVPN Scanner tests: the artboard's demo scenarios (vpn-scanner.js SCENARIOS) and the full-scope cases as
// worlds for the Driver of scan_world.h, each with its own expectations, plus the invariants every recorded
// step must keep. scan_core_check.cpp asserts them; scan_vectors_check.cpp --record refuses to write a vector
// file when any of them fails.
#pragma once

#include <QRegularExpression>

#include "scan_world.h"

#include <QStringList>

namespace scantest {

// --- hosts (capabilities only: the machine never knows the platform) -----------------------------------------

inline ScanHostCaps hostIosMinimal()
{
    ScanHostCaps c;
    c.maxFullConcurrent = 1;
    c.needsVpn = true;
    c.platform = QStringLiteral("ios");
    return c;
}

inline ScanHostCaps hostIosFull()
{
    ScanHostCaps c = hostIosMinimal();
    c.maxLegConcurrent = 4;
    c.dnsPlan = true;
    c.maxAwgConcurrent = 2;
    return c;
}

inline ScanHostCaps hostMac()
{
    ScanHostCaps c;
    c.maxFullConcurrent = 2;
    c.canVerifyComposite = true;
    c.maxLegConcurrent = 6;
    c.dnsPlan = true;
    c.maxAwgConcurrent = 4;
    c.platform = QStringLiteral("macos");
    return c;
}

inline ScanHostCaps hostMacMinimal()
{
    ScanHostCaps c;
    c.maxFullConcurrent = 2;
    c.canVerifyComposite = true;
    c.platform = QStringLiteral("macos");
    return c;
}

// --- the artboard's nodes ----------------------------------------------------------------------------------

inline QString up(int n) { return QStringLiteral("up:00000000000000a") + QString::number(n); }

inline QList<NodeSpec> artboardNodes()
{
    const auto own = [](const char *id, const char *label, const char *cc, ScanTransport t, const char *ip, int port, int rank) {
        NodeSpec n;
        n.id = QLatin1String(id);
        n.label = QString::fromUtf8(label);
        n.cc = QLatin1String(cc);
        n.transport = t;
        n.version = t == ScanTransport::Awg ? QStringLiteral("3.1") : QString();
        n.entryIp = QLatin1String(ip);
        n.entryPort = port;
        n.rank = rank;
        return n;
    };
    const auto prov = [](int k, const char *label, const char *cc, bool composite, bool dnsLeg, const char *ip, int rank) {
        NodeSpec n;
        n.id = up(k);
        n.label = QString::fromUtf8(label);
        n.cc = QLatin1String(cc);
        n.provider = true;
        n.tier = 1;
        n.rank = rank;
        n.composite = composite;
        n.dnsThroughLeg = dnsLeg;
        n.entryIp = QLatin1String(ip);
        n.entryPort = 443;
        return n;
    };
    QList<NodeSpec> l;
    l << own("1", "Германия 1", "DE", ScanTransport::Awg, "10.0.1.1", 585, 0)
      << own("2", "Эстония 2", "EE", ScanTransport::Awg, "10.0.1.2", 585, 1)
      << own("2:xray", "Эстония 2", "EE", ScanTransport::Xray, "10.0.0.1", 443, 2)
      << own("3", "Финляндия 1", "FI", ScanTransport::Awg, "10.0.1.3", 585, 3)
      << own("4:xray", "Германия 2", "DE", ScanTransport::Xray, "10.0.0.1", 443, 4)
      << own("5:xray", "Финляндия 2", "FI", ScanTransport::Xray, "10.0.0.2", 443, 5)
      << own("6", "США 1", "US", ScanTransport::Awg, "10.0.1.6", 585, 6)
      << own("7:xray", "Германия 3", "DE", ScanTransport::Xray, "10.0.0.1", 8443, 7)
      << own("8:xray", "Латвия 1", "LV", ScanTransport::Xray, "10.0.0.3", 443, 8)
      << own("9:xray", "Германия 4", "DE", ScanTransport::Xray, "10.0.0.2", 8443, 9)
      << own("10:xray", "Польша 1", "PL", ScanTransport::Xray, "10.0.0.4", 443, 10);
    NodeSpec nl1 = prov(1, "Нидерланды 1", "NL", false, true, "203.0.113.10", 0);
    nl1.crowd = true;
    l << nl1 << prov(2, "Швеция 1", "SE", true, false, "203.0.113.20", 1)
      << prov(3, "Нидерланды 2", "NL", false, false, "203.0.113.11", 2)
      << prov(4, "Польша 2", "PL", true, false, "203.0.113.21", 3);
    return l;
}

// Fast, working outcomes for every node (each one a little different so the order is visible).
inline QMap<QString, Outcome> allWork(const QList<NodeSpec> &nodes)
{
    QMap<QString, Outcome> m;
    int k = 0;
    for (const NodeSpec &n : nodes) {
        Outcome o;
        o.rtt = 38 + 7 * k;
        o.t64 = 120 + 25 * k;
        o.durMs = 420 + 30 * (k % 4);
        m.insert(n.id, o);
        ++k;
    }
    return m;
}

inline QJsonObject openArgs(const World &w, const QString &current, bool working, const ScanCachedResult &cached = ScanCachedResult(),
                            bool withCheck = false)
{
    return QJsonObject{{QStringLiteral("network"), netJson(w.net)},
                       {QStringLiteral("current"), currentJson(liveOf(w, current, working))},
                       {QStringLiteral("cached"), scanCachedResultToJson(cached)},
                       {QStringLiteral("with_check"), withCheck}};
}

inline std::function<QJsonObject(qint64)> at(const char *name, QJsonObject args = {})
{
    const QString n = QLatin1String(name);
    return [n, args](qint64 t) { return ev(n.toUtf8().constData(), t, args); };
}

// --- invariants of every step --------------------------------------------------------------------------------

struct Fail {
    QStringList list;
    void check(bool ok, const QString &what)
    {
        if (!ok)
            list << what;
    }
};

inline bool isScanRequestEvent(const QString &e)
{
    return e == QLatin1String("opened") || e == QLatin1String("retry") || e == QLatin1String("network_changed")
           || e == QLatin1String("app_foreground") || e == QLatin1String("connect_and_scan_tapped");
}

// Checks one recorded step. prevPhase = the phase before this step (from the previous view).
inline void checkStepInvariants(const Recorded &r, const QString &prevPhase, const ScanMachine &m, const QString &currentId,
                                Fail &f, const QString &where)
{
    const QString e = r.event.value(QLatin1String("event")).toString();
    const ScanTunables &t = m.tunables();
    for (const ScanAction &a : r.step.actions) {
        if (!scanActionTouchesTunnel(a.kind))
            continue;
        if (a.kind == ScanActionKind::ConnectRow)
            f.check(e == QLatin1String("row_tapped"), where + QStringLiteral(": ConnectRow outside a tap"));
        if (a.kind == ScanActionKind::UserConnectForScan)
            f.check(isScanRequestEvent(e) && m.caps().needsVpn, where + QStringLiteral(": UserConnectForScan outside a scan request of a VPN-required host"));
        if (a.kind == ScanActionKind::CancelPendingConnect)
            f.check((e == QLatin1String("stop") || e == QLatin1String("closed")) && prevPhase == QLatin1String("connecting"),
                    where + QStringLiteral(": CancelPendingConnect outside Stop/close during the scan's own connect"));
        if (a.kind == ScanActionKind::ConnectRow)
            f.check(a.userOrigin && a.forceConnect, where + QStringLiteral(": ConnectRow without user origin / force"));
    }
    for (const ScanAction &a : r.step.actions)
        if (a.kind == ScanActionKind::StartHostScan || a.kind == ScanActionKind::AddHostCandidates)
            for (const ScanCandidate &c : a.candidates)
                f.check(currentId.isEmpty() || c.id != currentId, where + QStringLiteral(": the current node scheduled"));
    const QJsonArray rows = r.view.value(QLatin1String("rows")).toArray();
    const int verified = r.view.value(QLatin1String("verified")).toInt();
    const int unverified = r.view.value(QLatin1String("unverified")).toInt();
    f.check(verified <= t.listTargetWorks, where + QStringLiteral(": more than the cap of verified rows"));
    f.check(unverified <= t.unverifiedRowsMax, where + QStringLiteral(": more than the cap of unverified rows"));
    f.check(unverified == 0 || verified < t.listTargetWorks, where + QStringLiteral(": unverified rows next to a full list"));
    QSet<QString> ids;
    int lastRank = -1, lastMs = -1;
    bool seenUnverified = false;
    for (const QJsonValue &v : rows) {
        const QJsonObject row = v.toObject();
        const QString id = row.value(QLatin1String("id")).toString();
        f.check(!ids.contains(id), where + QStringLiteral(": a row twice ") + id);
        ids.insert(id);
        const bool unv = row.value(QLatin1String("flags")).toArray().contains(QStringLiteral("unverified"));
        if (unv) {
            seenUnverified = true;
            continue;
        }
        f.check(!seenUnverified, where + QStringLiteral(": a verified row after an unverified one"));
        const int rank = scanSpeedRank(scanSpeedFrom(row.value(QLatin1String("speed")).toString()));
        const int rawMs = row.value(QLatin1String("ms")).toInt();
        const int ms = rawMs < 0 ? INT_MAX : rawMs; // no figure sorts last inside its speed class
        // The current row shows its live ms but keeps the place of its own facts: it is skipped here.
        const bool current = row.value(QLatin1String("flags")).toArray().contains(QStringLiteral("current"));
        f.check(rank >= lastRank, where + QStringLiteral(": rows out of speed order"));
        if (rank != lastRank)
            lastMs = -1;
        if (!current && rank == lastRank && lastMs >= 0)
            f.check(ms >= lastMs, where + QStringLiteral(": rows out of ms order inside a speed class"));
        lastRank = rank;
        if (!current)
            lastMs = ms;
    }
    const double prog = r.view.value(QLatin1String("progress")).toDouble();
    f.check(prog >= -1 && prog <= 1.0001, where + QStringLiteral(": progress out of range"));
    f.check(r.spent >= 0 && r.reserved >= 0, where + QStringLiteral(": negative bytes"));
    for (const ScanLedgerEntry &le : m.ledger().entries())
        f.check(le.bytes > 0, where + QStringLiteral(": a ledger entry <= 0"));
    bool providerAdded = false;
    for (const ScanAction &a : r.step.actions)
        if (a.kind == ScanActionKind::AddHostCandidates)
            for (const ScanCandidate &c : a.candidates)
                providerAdded = providerAdded || c.needsLease;
    if (providerAdded && r.cap >= 0)
        f.check(r.spent + r.reserved <= r.cap, where + QStringLiteral(": provider probes past the byte cap"));
    // F7: a scan still settling its host bytes always has a wake (draining terminates)
    f.check(!r.draining || r.step.wakeAtMs >= 0, where + QStringLiteral(": draining without a wake"));
    // F6: admission never passes the allowance; only real bytes reported above their reservation (a reply cut
    // one transport chunk late) may - by at most one chunk + headers per such report - and they are recorded
    if (r.allowance >= 0)
        f.check(r.allowanceUsed <= r.allowance + r.overrunBound, where + QStringLiteral(": the allowance passed beyond the reported overruns"));
    for (const ScanAction &a : r.step.actions) {
        // the host's grant fits the allowance; every app request carries its reservation
        if (a.kind == ScanActionKind::StartHostScan && r.allowance >= 0)
            f.check(a.maxBytes >= 0 && a.maxBytes <= r.allowance, where + QStringLiteral(": host grant above the allowance"));
        const bool app = a.kind == ScanActionKind::RequestManifest || a.kind == ScanActionKind::RequestProbeBatch
                         || a.kind == ScanActionKind::ReleaseProbeLeases || a.kind == ScanActionKind::ProbeLiveTunnel
                         || a.kind == ScanActionKind::StartLightChecks || a.kind == ScanActionKind::SendOutcomes;
        if (app)
            f.check(!a.requestId.isEmpty() && a.costBytes >= 0, where + QStringLiteral(": an app request without its reservation"));
        if (a.kind == ScanActionKind::RequestProbeBatch)
            f.check(!(a.includeConfig && r.view.value(QLatin1String("net")).toString() == QLatin1String("cellular")),
                    where + QStringLiteral(": configs asked on cellular"));
    }
    for (const ScanAction &a : r.step.actions) {
        if (a.kind == ScanActionKind::RequestProbeBatch)
            f.check(a.ids.size() >= 1 && a.ids.size() <= kScanProbeBatchMax, where + QStringLiteral(": batch size"));
        if (a.kind == ScanActionKind::ReleaseProbeLeases)
            f.check(a.ids.size() >= 1 && a.ids.size() <= kScanProbeBatchMax, where + QStringLiteral(": release size"));
    }
}

inline QString phaseOf(const QJsonObject &view) { return view.value(QLatin1String("phase")).toString(); }

// --- the server's strict schemas (api/openapi.yaml 1.7.0, additionalProperties false) ------------------------
// What a server that rejects unknown fields and bad values says about our JSON: "" = accepted, else why not.

inline bool intIn(const QJsonValue &v, qint64 lo, qint64 hi)
{
    return v.isDouble() && v.toDouble() == double(qint64(v.toDouble())) && v.toDouble() >= double(lo) && v.toDouble() <= double(hi);
}

inline bool keyLike(const QString &k)
{
    static const QRegularExpression re(QStringLiteral("^[a-z][a-z0-9_]{0,31}$"));
    return re.match(k).hasMatch();
}

// PathOutcomeItem
inline QString outcomeItemRejects(const QJsonObject &o)
{
    static const QStringList keys{QStringLiteral("kind"), QStringLiteral("id"), QStringLiteral("network_key"), QStringLiteral("outcome"),
                                  QStringLiteral("stage"), QStringLiteral("ttfb_ms"), QStringLiteral("bytes"), QStringLiteral("duration_ms"),
                                  QStringLiteral("probe"), QStringLiteral("rtt_ms"), QStringLiteral("evidence")};
    for (const QString &k : o.keys())
        if (!keys.contains(k))
            return QStringLiteral("unknown key ") + k;
    for (const char *k : {"kind", "id", "network_key", "outcome", "stage"})
        if (!o.contains(QLatin1String(k)))
            return QStringLiteral("missing ") + QLatin1String(k);
    const auto in = [&o](const char *k, const QStringList &vals) { return !o.contains(QLatin1String(k)) || vals.contains(o.value(QLatin1String(k)).toString()); };
    if (!in("kind", {QStringLiteral("node"), QStringLiteral("upstream")}) || o.value(QLatin1String("id")).toString().size() > 64)
        return QStringLiteral("kind/id");
    if (!scanNetworkKeyValid(o.value(QLatin1String("network_key")).toString()))
        return QStringLiteral("network_key");
    if (!in("outcome", {QStringLiteral("works"), QStringLiteral("slow"), QStringLiteral("no_data"), QStringLiteral("unreachable"), QStringLiteral("leak"),
                        QStringLiteral("not_verified")})
        || !in("stage", {QStringLiteral("cache"), QStringLiteral("reach"), QStringLiteral("data"), QStringLiteral("connect")})
        || !in("probe", {QStringLiteral("tunnel"), QStringLiteral("full"), QStringLiteral("leg"), QStringLiteral("awg_mini")})
        || !in("evidence", {QStringLiteral("direct"), QStringLiteral("exclusion")}))
        return QStringLiteral("enum");
    if ((o.contains(QLatin1String("ttfb_ms")) && !intIn(o.value(QLatin1String("ttfb_ms")), 0, 600000))
        || (o.contains(QLatin1String("bytes")) && !intIn(o.value(QLatin1String("bytes")), 0, 1073741824))
        || (o.contains(QLatin1String("duration_ms")) && !intIn(o.value(QLatin1String("duration_ms")), 0, 3600000))
        || (o.contains(QLatin1String("rtt_ms")) && !intIn(o.value(QLatin1String("rtt_ms")), 0, 600000)))
        return QStringLiteral("range");
    return QString();
}

// PathOutcomeBatch {items: 1..128 PathOutcomeItem}
inline QString outcomeBatchRejects(const QJsonObject &b)
{
    if (b.keys() != QStringList{QStringLiteral("items")})
        return QStringLiteral("batch keys");
    const QJsonArray items = b.value(QLatin1String("items")).toArray();
    if (items.isEmpty() || items.size() > 128)
        return QStringLiteral("batch size");
    for (const QJsonValue &v : items) {
        const QString why = outcomeItemRejects(v.toObject());
        if (!why.isEmpty())
            return why;
    }
    return QString();
}

// DoctorScanSummary (with DoctorScanRow)
inline QString summaryRejects(const QJsonObject &o)
{
    static const QStringList keys{QStringLiteral("schema"), QStringLiteral("network_key"), QStringLiteral("manifest_revision"), QStringLiteral("candidates"),
                                  QStringLiteral("counts"), QStringLiteral("top"), QStringLiteral("not_verified_reasons"), QStringLiteral("stop_reason"),
                                  QStringLiteral("duration_ms"), QStringLiteral("bytes_spent"), QStringLiteral("caps"), QStringLiteral("seats_requested")};
    for (const QString &k : o.keys())
        if (!keys.contains(k))
            return QStringLiteral("unknown key ") + k;
    for (const char *k : {"schema", "network_key", "candidates", "counts"})
        if (!o.contains(QLatin1String(k)))
            return QStringLiteral("missing ") + QLatin1String(k);
    if (o.value(QLatin1String("schema")).toInt() != 1 || !scanNetworkKeyValid(o.value(QLatin1String("network_key")).toString())
        || !intIn(o.value(QLatin1String("candidates")), 0, 1024))
        return QStringLiteral("head");
    if (o.contains(QLatin1String("seats_requested")) && !intIn(o.value(QLatin1String("seats_requested")), 0, 48))
        return QStringLiteral("seats_requested");
    static const QStringList classes{QStringLiteral("works"), QStringLiteral("slow"), QStringLiteral("no_data"), QStringLiteral("unreachable"),
                                     QStringLiteral("leak"), QStringLiteral("not_verified")};
    const QJsonObject counts = o.value(QLatin1String("counts")).toObject();
    for (auto it = counts.constBegin(); it != counts.constEnd(); ++it)
        if (!classes.contains(it.key()) || !intIn(it.value(), 0, 1024))
            return QStringLiteral("counts");
    const QJsonArray top = o.value(QLatin1String("top")).toArray();
    if (top.size() > 20)
        return QStringLiteral("top size");
    static const QRegularExpression nodeId(QStringLiteral("^[0-9]{1,10}(:[a-z0-9_]{1,16}){0,2}$")), pid(QStringLiteral("^[0-9a-f]{16}$"));
    for (const QJsonValue &v : top) {
        const QJsonObject r = v.toObject();
        for (const QString &k : r.keys())
            if (!QStringList{QStringLiteral("kind"), QStringLiteral("id"), QStringLiteral("class"), QStringLiteral("ms"), QStringLiteral("probe"),
                             QStringLiteral("evidence")}.contains(k))
                return QStringLiteral("row key ") + k;
        const bool up = r.value(QLatin1String("kind")).toString() == QLatin1String("upstream");
        if ((!up && r.value(QLatin1String("kind")).toString() != QLatin1String("node")) || !classes.contains(r.value(QLatin1String("class")).toString())
            || !(up ? pid : nodeId).match(r.value(QLatin1String("id")).toString()).hasMatch())
            return QStringLiteral("row");
        if (r.contains(QLatin1String("evidence"))
            && !QStringList{QStringLiteral("direct"), QStringLiteral("exclusion")}.contains(r.value(QLatin1String("evidence")).toString()))
            return QStringLiteral("row evidence");
        if (r.contains(QLatin1String("ms")) && !intIn(r.value(QLatin1String("ms")), 0, 600000))
            return QStringLiteral("row ms");
    }
    const QJsonObject nv = o.value(QLatin1String("not_verified_reasons")).toObject();
    if (nv.size() > 16)
        return QStringLiteral("reasons size");
    for (auto it = nv.constBegin(); it != nv.constEnd(); ++it)
        if (!keyLike(it.key()) || !intIn(it.value(), 0, 1024))
            return QStringLiteral("reasons");
    if (o.contains(QLatin1String("stop_reason")) && !keyLike(o.value(QLatin1String("stop_reason")).toString()))
        return QStringLiteral("stop_reason");
    if ((o.contains(QLatin1String("duration_ms")) && !intIn(o.value(QLatin1String("duration_ms")), 0, 600000))
        || (o.contains(QLatin1String("bytes_spent")) && !intIn(o.value(QLatin1String("bytes_spent")), 0, 1073741824)))
        return QStringLiteral("range");
    const QJsonObject caps = o.value(QLatin1String("caps")).toObject();
    if (caps.size() > 8)
        return QStringLiteral("caps size");
    for (auto it = caps.constBegin(); it != caps.constEnd(); ++it)
        if (!keyLike(it.key()) || !it.value().isBool())
            return QStringLiteral("caps");
    return QString();
}

// Lab seam S4 (16.11): every candidate of a finished scan is in exactly one bucket of its summary - the counts
// sum to `candidates`, the not_verified_reasons to counts.not_verified - and the strict schema accepts it.
// "" = holds, else why not.
inline QString summaryBucketsWhy(const QJsonObject &sum)
{
    if (sum.isEmpty())
        return QString();
    int total = 0, reasons = 0;
    const QJsonObject counts = sum.value(QLatin1String("counts")).toObject();
    for (auto it = counts.constBegin(); it != counts.constEnd(); ++it)
        total += it.value().toInt();
    const QJsonObject nv = sum.value(QLatin1String("not_verified_reasons")).toObject();
    for (auto it = nv.constBegin(); it != nv.constEnd(); ++it)
        reasons += it.value().toInt();
    if (total != sum.value(QLatin1String("candidates")).toInt())
        return QStringLiteral("counts sum %1 != candidates %2").arg(total).arg(sum.value(QLatin1String("candidates")).toInt());
    if (reasons != counts.value(QLatin1String("not_verified")).toInt())
        return QStringLiteral("reasons sum %1 != not_verified %2").arg(reasons).arg(counts.value(QLatin1String("not_verified")).toInt());
    const QString schema = summaryRejects(sum);
    return schema.isEmpty() ? QString() : QStringLiteral("schema: ") + schema;
}

inline void checkAllSteps(const Driver &d, Fail &f, const QString &name)
{
    QString prev = QStringLiteral("idle");
    QString currentId;
    for (int i = 0; i < d.steps.size(); ++i) {
        const Recorded &r = d.steps.at(i);
        const QString buckets = summaryBucketsWhy(r.summary);
        f.check(buckets.isEmpty(), name + QStringLiteral("#") + QString::number(i) + QStringLiteral(": summary ") + buckets);
        if (r.event.value(QLatin1String("event")).toString() == QLatin1String("vpn_state")) {
            const ScanCurrent c = currentFrom(r.event.value(QLatin1String("args")).toObject().value(QLatin1String("current")).toObject());
            currentId = c.working() ? c.nodeId : QString();
        }
        if (r.event.value(QLatin1String("event")).toString() == QLatin1String("opened")) {
            const ScanCurrent c = currentFrom(r.event.value(QLatin1String("args")).toObject().value(QLatin1String("current")).toObject());
            currentId = c.working() ? c.nodeId : QString();
        }
        checkStepInvariants(r, prev, d.m, currentId, f, name + QStringLiteral("#") + QString::number(i));
        prev = phaseOf(r.view);
    }
}

// --- helpers for expectations ------------------------------------------------------------------------------

inline int countActions(const Driver &d, ScanActionKind k)
{
    int n = 0;
    for (const Recorded &r : d.steps)
        n += r.step.count(k);
    return n;
}

inline QList<ScanAction> actionsOf(const Driver &d, ScanActionKind k)
{
    QList<ScanAction> out;
    for (const Recorded &r : d.steps)
        for (const ScanAction &a : r.step.actions)
            if (a.kind == k)
                out << a;
    return out;
}

inline QJsonObject lastView(const Driver &d) { return d.steps.isEmpty() ? QJsonObject() : d.steps.last().view; }

inline QStringList rowIds(const QJsonObject &view)
{
    QStringList ids;
    for (const QJsonValue &v : view.value(QLatin1String("rows")).toArray())
        ids << v.toObject().value(QLatin1String("id")).toString();
    return ids;
}

inline QJsonObject rowOf(const QJsonObject &view, const QString &id)
{
    for (const QJsonValue &v : view.value(QLatin1String("rows")).toArray())
        if (v.toObject().value(QLatin1String("id")).toString() == id)
            return v.toObject();
    return QJsonObject();
}

inline bool hasShade(const Driver &d, const char *key)
{
    for (const ScanAction &a : actionsOf(d, ScanActionKind::ShowShade))
        if (a.shade.textKey == QLatin1String(key))
            return true;
    return false;
}

inline int shadeCount(const Driver &d, const char *key)
{
    int n = 0;
    for (const ScanAction &a : actionsOf(d, ScanActionKind::ShowShade))
        n += a.shade.textKey == QLatin1String(key) ? 1 : 0;
    return n;
}

// The view right after the first step at or after offset ms.
inline QJsonObject viewAt(const Driver &d, qint64 offsetMs)
{
    QJsonObject v;
    for (const Recorded &r : d.steps) {
        if (qint64(r.event.value(QLatin1String("now_ms")).toDouble()) - kT0 > offsetMs)
            break;
        v = r.view;
    }
    return v;
}

// --- the scenarios ----------------------------------------------------------------------------------------

struct Scenario {
    QString name;
    QStringList rules;
    std::function<World()> world;
    std::function<void(const Driver &, Fail &)> expect;
};

// Own nodes only (a world where the providers' seats and configs do not matter).
inline QList<NodeSpec> ownOnly(const QList<NodeSpec> &nodes)
{
    QList<NodeSpec> out;
    for (const NodeSpec &n : nodes)
        if (!n.provider)
            out << n;
    return out;
}

inline World baseWorld(const char *name, const ScanHostCaps &caps, ScanNetKind kind)
{
    World w;
    w.name = QLatin1String(name);
    w.caps = caps;
    w.net = kind == ScanNetKind::Cellular ? scanNet(ScanNetKind::Cellular, QStringLiteral("cell:250-02:4g"))
                                          : scanNet(ScanNetKind::Wifi, QStringLiteral("wifi:asn:64500"));
    w.nodes = artboardNodes();
    w.out = allWork(w.nodes);
    return w;
}

inline QList<Scenario> scenarios()
{
    QList<Scenario> l;

    // 1. Wi-Fi, everything works, parallel legs (macOS host): 10 rows quickly, then «Ваше подключение».
    l << Scenario{QStringLiteral("wifi_all_works_legs"),
                  {QStringLiteral("stop at scan_stop_works"), QStringLiteral("list cap 10"), QStringLiteral("shade scan_found"),
                   QStringLiteral("card filled after S4"), QStringLiteral("no tunnel action")},
                  [] {
                      World w = baseWorld("wifi_all_works_legs", hostMac(), ScanNetKind::Wifi);
                      w.current = QStringLiteral("1");
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.runMs = 12000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject v = lastView(d);
                      f.check(phaseOf(v) == QLatin1String("done"), QStringLiteral("phase done"));
                      f.check(v.value(QLatin1String("verified")).toInt() == 10, QStringLiteral("10 verified rows"));
                      f.check(countActions(d, ScanActionKind::StopHostScan) == 1, QStringLiteral("host stopped once"));
                      f.check(shadeCount(d, "scan_found") == 1, QStringLiteral("one found shade"));
                      f.check(v.value(QLatin1String("card")).toObject().value(QLatin1String("mode")).toString() == QLatin1String("filled"),
                              QStringLiteral("card filled"));
                      f.check(rowOf(v, QStringLiteral("1")).value(QLatin1String("state")).toString() == QLatin1String("connected"),
                              QStringLiteral("current row connected"));
                      int tunnel = 0;
                      for (const Recorded &r : d.steps)
                          for (const ScanAction &a : r.step.actions)
                              tunnel += scanActionTouchesTunnel(a.kind) ? 1 : 0;
                      f.check(tunnel == 0, QStringLiteral("no tunnel action"));
                      const qint64 stopAt = qint64(actionsOf(d, ScanActionKind::StopHostScan).isEmpty() ? 0 : 0);
                      Q_UNUSED(stopAt);
                      f.check(v.value(QLatin1String("bar")).toObject().value(QLatin1String("button")).toString() == QLatin1String("retry_in_s"),
                              QStringLiteral("cooldown button after the scan"));
                  }};

    // 2. Wi-Fi, everything works, minimal iPhone host (full probes only): full probes one at a time, composites «Не проверено».
    l << Scenario{QStringLiteral("wifi_all_works_minimal_host"),
                  {QStringLiteral("a minimal host gets a complete scan"), QStringLiteral("composites not verified on a host that cannot run them"),
                   QStringLiteral("own AWG absent without awg_mini"), QStringLiteral("one full probe at a time")},
                  [] {
                      World w = baseWorld("wifi_all_works_minimal_host", hostIosMinimal(), ScanNetKind::Wifi);
                      w.current = QStringLiteral("1");
                      for (auto it = w.out.begin(); it != w.out.end(); ++it)
                          it.value().durMs = 700;
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.runMs = 14000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject v = lastView(d);
                      f.check(phaseOf(v) == QLatin1String("done"), QStringLiteral("phase done"));
                      const QStringList ids = rowIds(v);
                      f.check(!ids.contains(QStringLiteral("2")) && !ids.contains(QStringLiteral("3")) && !ids.contains(QStringLiteral("6")),
                              QStringLiteral("own AWG absent"));
                      const ScanAction start = actionsOf(d, ScanActionKind::StartHostScan).value(0);
                      f.check(start.limits.concurrency == 1 && start.limits.legConcurrency == 0, QStringLiteral("one full probe at a time"));
                      bool composite = false;
                      for (const QJsonValue &r : v.value(QLatin1String("rows")).toArray())
                          composite = composite || r.toObject().value(QLatin1String("id")).toString() == up(2);
                      f.check(v.value(QLatin1String("verified")).toInt() < 10 ? composite : true,
                              QStringLiteral("composite shown as not verified while fewer than 10"));
                      f.check(countActions(d, ScanActionKind::UserConnectForScan) == 0, QStringLiteral("VPN already on: no connect"));
                  }};

    // 3. Cellular, part of the nodes do not carry data: the scan runs to the deadline.
    l << Scenario{QStringLiteral("cellular_dead_nodes"),
                  {QStringLiteral("stop at scan_stop_ms"), QStringLiteral("failures never shown, reported"), QStringLiteral("cellular hint"),
                   QStringLiteral("budget ledger gets the actual bytes")},
                  [] {
                      World w = baseWorld("cellular_dead_nodes", hostIosFull(), ScanNetKind::Cellular);
                      w.current = QStringLiteral("2");
                      w.out[QStringLiteral("4:xray")].reachOk = false;
                      w.out[QStringLiteral("5:xray")].works = false;
                      w.out[QStringLiteral("7:xray")].reachOk = false;
                      w.out[QStringLiteral("9:xray")].works = false;
                      w.out[QStringLiteral("3")].works = false;
                      w.out[QStringLiteral("6")].handshake = false;
                      w.out[up(1)].works = false;
                      for (auto it = w.out.begin(); it != w.out.end(); ++it)
                          it.value().durMs += 900;
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.runMs = 14000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject v = lastView(d);
                      const QStringList ids = rowIds(v);
                      for (const char *dead : {"4:xray", "5:xray", "7:xray", "9:xray", "3", "6"})
                          f.check(!ids.contains(QLatin1String(dead)), QStringLiteral("dead row hidden ") + QLatin1String(dead));
                      f.check(v.value(QLatin1String("bar")).toObject().value(QLatin1String("hint")).toString() == QLatin1String("cellular_cost"),
                              QStringLiteral("cellular hint"));
                      bool unreachable = false, noData = false;
                      for (const ScanAction &a : actionsOf(d, ScanActionKind::SendOutcomes))
                          for (const ScanOutcomeItem &it : a.outcomes) {
                              unreachable = unreachable || it.outcome == ScanClass::Unreachable;
                              noData = noData || it.outcome == ScanClass::NoData;
                          }
                      f.check(unreachable && noData, QStringLiteral("failures reported"));
                      f.check(!d.m.ledger().entries().isEmpty() && d.m.ledger().entries().last().cellular, QStringLiteral("cellular bytes in the ledger"));
                      f.check(countActions(d, ScanActionKind::PersistBudget) >= 1, QStringLiteral("budget persisted"));
                  }};

    // 4. Whitelist window: only two nodes carry data, both Xray.
    l << Scenario{QStringLiteral("whitelist_two_working"),
                  {QStringLiteral("rows = only what carries data"), QStringLiteral("slow badge")},
                  [] {
                      World w = baseWorld("whitelist_two_working", hostIosFull(), ScanNetKind::Cellular);
                      w.current = QStringLiteral("2:xray");
                      for (auto it = w.out.begin(); it != w.out.end(); ++it)
                          it.value().reachOk = false, it.value().handshake = false, it.value().works = false;
                      w.out[QStringLiteral("2:xray")].reachOk = true;
                      w.out[up(3)].reachOk = true;
                      w.out[up(3)].works = true;
                      w.out[up(3)].ttfb1 = 1900;
                      w.out[up(3)].fullWorks = 1;
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.runMs = 14000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject v = lastView(d);
                      f.check(phaseOf(v) == QLatin1String("done"), QStringLiteral("phase done"));
                      const QJsonObject cur = rowOf(v, QStringLiteral("2:xray"));
                      f.check(cur.value(QLatin1String("state")).toString() == QLatin1String("connected"), QStringLiteral("current row"));
                      f.check(v.value(QLatin1String("verified")).toInt() <= 2, QStringLiteral("at most two working rows"));
                  }};

    // 5. Nothing works on cellular, VPN off (macOS host): empty state, «Понял, подключусь к Wi‑Fi», the Wi-Fi intent.
    l << Scenario{QStringLiteral("nothing_works_cellular"),
                  {QStringLiteral("empty state by network kind"), QStringLiteral("Wi-Fi intent fires once while in front")},
                  [] {
                      World w = baseWorld("nothing_works_cellular", hostMacMinimal(), ScanNetKind::Cellular);
                      w.nodes = ownOnly(w.nodes); // providers: only first-wave seats, the rest «Не проверено»
                      for (auto it = w.out.begin(); it != w.out.end(); ++it)
                          it.value().reachOk = false, it.value().works = false;
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
                      w.script << qMakePair(qint64(11000), at("got_it"));
                      World w2 = w;
                      w2.net = scanNet(ScanNetKind::Wifi, QStringLiteral("wifi:asn:64501"));
                      w.script << qMakePair(qint64(60000), at("network_changed", {{QStringLiteral("network"), netJson(w2.net)},
                                                                                {QStringLiteral("cached"), QJsonObject()},
                                                                                {QStringLiteral("app_in_front"), true}}));
                      w.runMs = 62000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject v = viewAt(d, 10500);
                      f.check(phaseOf(v) == QLatin1String("empty"), QStringLiteral("empty"));
                      f.check(v.value(QLatin1String("empty")).toObject().value(QLatin1String("variant")).toString() == QLatin1String("cellular"),
                              QStringLiteral("cellular variant"));
                      f.check(v.value(QLatin1String("card")).toObject().value(QLatin1String("mode")).toString() == QLatin1String("hidden"),
                              QStringLiteral("no card in the empty state"));
                      f.check(hasShade(d, "wifi_intent"), QStringLiteral("intent shade"));
                      f.check(d.closes.size() == 1 && d.opens.size() == 1, QStringLiteral("closed once, reopened by the intent"));
                      f.check(countActions(d, ScanActionKind::RequestManifest) == 2, QStringLiteral("second scan on Wi-Fi"));
                      f.check(d.m.wifiIntentUntil() == 0, QStringLiteral("intent consumed"));
                  }};

    // 6. Nothing works on Wi-Fi: «Понял» only closes.
    l << Scenario{QStringLiteral("nothing_works_wifi"),
                  {QStringLiteral("empty state wifi variant"), QStringLiteral("no intent on Wi-Fi")},
                  [] {
                      World w = baseWorld("nothing_works_wifi", hostMacMinimal(), ScanNetKind::Wifi);
                      w.nodes = ownOnly(w.nodes); // providers: only first-wave seats, the rest «Не проверено»
                      for (auto it = w.out.begin(); it != w.out.end(); ++it)
                          it.value().reachOk = false, it.value().works = false;
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
                      w.script << qMakePair(qint64(11000), at("got_it"));
                      w.runMs = 12000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject v = viewAt(d, 10500);
                      f.check(v.value(QLatin1String("empty")).toObject().value(QLatin1String("variant")).toString() == QLatin1String("wifi"),
                              QStringLiteral("wifi variant"));
                      f.check(!hasShade(d, "wifi_intent") && d.m.wifiIntentUntil() == 0, QStringLiteral("no intent"));
                      f.check(d.closes.size() == 1, QStringLiteral("closed"));
                  }};

    // 7. iPhone with the VPN off: «Подключаемся…», cached rows at once, the VPN stays on after the scan.
    l << Scenario{QStringLiteral("vpn_off_iphone"),
                  {QStringLiteral("S1 only on a host that needs the VPN"), QStringLiteral("cached rows with their age"),
                   QStringLiteral("the VPN stays on")},
                  [] {
                      World w = baseWorld("vpn_off_iphone", hostIosFull(), ScanNetKind::Wifi);
                      w.lkg = QStringLiteral("2:xray");
                      ScanCachedResult c;
                      c.networkKey = w.net.key;
                      c.fingerprint = w.net.fingerprint;
                      c.savedAtMs = kT0 - 12 * 60000;
                      for (const char *id : {"4:xray", "5:xray", "8:xray"}) {
                          ScanCachedRow r;
                          r.id = QLatin1String(id);
                          r.label = specOf(w, r.id)->label;
                          r.countryCode = specOf(w, r.id)->cc;
                          r.speed = ScanSpeed::Fast;
                          r.ms = 50;
                          c.rows << r;
                      }
                      ScanCachedRow gone; // a node the server no longer lists: its cached row must go
                      gone.id = QStringLiteral("77:xray");
                      gone.label = QStringLiteral("Old");
                      gone.countryCode = QStringLiteral("DE");
                      gone.speed = ScanSpeed::Fast;
                      gone.ms = 30;
                      c.rows << gone;
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false, c)));
                      w.runMs = 14000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject v0 = d.steps.value(0).view;
                      f.check(phaseOf(v0) == QLatin1String("connecting"), QStringLiteral("S1 first"));
                      f.check(v0.value(QLatin1String("stage")).toString() == QLatin1String("connecting"), QStringLiteral("stage connecting"));
                      f.check(v0.value(QLatin1String("checked_ago_min")).toInt() == 12, QStringLiteral("cached 12 min"));
                      f.check(rowIds(v0).size() == 4, QStringLiteral("cached rows at once"));
                      f.check(!rowIds(lastView(d)).contains(QStringLiteral("77:xray")), QStringLiteral("unverified cached row dropped"));
                      f.check(v0.value(QLatin1String("card")).toObject().value(QLatin1String("mode")).toString() == QLatin1String("off"),
                              QStringLiteral("card off"));
                      f.check(countActions(d, ScanActionKind::UserConnectForScan) == 1, QStringLiteral("one connect"));
                      f.check(countActions(d, ScanActionKind::CancelPendingConnect) == 0, QStringLiteral("never disconnected"));
                      f.check(phaseOf(lastView(d)) == QLatin1String("done"), QStringLiteral("done"));
                      f.check(!d.m.startedVpn(), QStringLiteral("no disconnect duty after S1"));
                  }};

    // 8. Stop during «Подключаемся…»: the single exception that turns the VPN off.
    l << Scenario{QStringLiteral("vpn_off_cancel_during_connect"),
                  {QStringLiteral("DisconnectForScan only on Stop during S1 of our own connect")},
                  [] {
                      World w = baseWorld("vpn_off_cancel_during_connect", hostIosMinimal(), ScanNetKind::Wifi);
                      w.lkg = QStringLiteral("2:xray");
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
                      w.script << qMakePair(qint64(700), at("stop"));
                      w.runMs = 3000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      f.check(countActions(d, ScanActionKind::CancelPendingConnect) == 1, QStringLiteral("one disconnect"));
                      f.check(d.closes.size() == 1, QStringLiteral("screen closed"));
                      f.check(phaseOf(lastView(d)) == QLatin1String("idle"), QStringLiteral("idle after stop"));
                  }};

    // 9. Stop after the VPN came up: no disconnect.
    l << Scenario{QStringLiteral("vpn_off_cancel_after_connect"),
                  {QStringLiteral("after the data passed the VPN stays on")},
                  [] {
                      World w = baseWorld("vpn_off_cancel_after_connect", hostIosMinimal(), ScanNetKind::Wifi);
                      w.lkg = QStringLiteral("2:xray");
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
                      w.script << qMakePair(qint64(3000), at("stop"));
                      w.runMs = 4000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      f.check(countActions(d, ScanActionKind::CancelPendingConnect) == 0, QStringLiteral("no disconnect"));
                      f.check(countActions(d, ScanActionKind::StopHostScan) == 1, QStringLiteral("host stopped"));
                  }};

    // 10. First connect from a row fails: shade + the next of the visible order; the screen stays.
    l << Scenario{QStringLiteral("first_connect_fails"),
                  {QStringLiteral("tap = ConnectRow with the visible order"), QStringLiteral("failed row dimmed"),
                   QStringLiteral("shade connect_failed_next"), QStringLiteral("card refills for the new node"), QStringLiteral("screen stays")},
                  [] {
                      World w = baseWorld("first_connect_fails", hostMac(), ScanNetKind::Wifi);
                      w.current = QStringLiteral("1");
                      w.connectFails.insert(QStringLiteral("4:xray"));
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.script << qMakePair(qint64(9000), at("row_tapped", {{QStringLiteral("node_id"), QStringLiteral("4:xray")}}));
                      w.runMs = 16000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QList<ScanAction> taps = actionsOf(d, ScanActionKind::ConnectRow);
                      f.check(taps.size() == 1 && taps.value(0).nodeId == QLatin1String("4:xray"), QStringLiteral("one ConnectRow"));
                      f.check(!taps.isEmpty() && !taps.value(0).ids.contains(QStringLiteral("4:xray")) && !taps.value(0).ids.contains(QStringLiteral("1")),
                              QStringLiteral("order excludes the tapped and the current"));
                      f.check(hasShade(d, "connect_failed_next"), QStringLiteral("warning shade"));
                      const QJsonObject v = lastView(d);
                      f.check(rowOf(v, QStringLiteral("4:xray")).value(QLatin1String("state")).toString() == QLatin1String("failed"), QStringLiteral("failed row"));
                      const QString next = taps.isEmpty() ? QString() : taps.value(0).ids.value(0);
                      f.check(rowOf(v, next).value(QLatin1String("state")).toString() == QLatin1String("connected"), QStringLiteral("next connected"));
                      bool refill = false;
                      for (const ScanAction &a : actionsOf(d, ScanActionKind::StartLightChecks))
                          refill = refill || a.nodeId == next;
                      f.check(refill, QStringLiteral("card refilled"));
                      f.check(d.closes.isEmpty(), QStringLiteral("screen stays"));
                      f.check(v.value(QLatin1String("card")).toObject().value(QLatin1String("mode")).toString() == QLatin1String("filled"),
                              QStringLiteral("card filled again"));
                  }};

    // 11. Filter by country: the list and the attempt order follow the filter.
    l << Scenario{QStringLiteral("filter_by_country"),
                  {QStringLiteral("filter after the scan"), QStringLiteral("order hint = the filtered visible order")},
                  [] {
                      World w = baseWorld("filter_by_country", hostMac(), ScanNetKind::Wifi);
                      w.current = QStringLiteral("1");
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.script << qMakePair(qint64(100), at("filter", {{QStringLiteral("cc"), QStringLiteral("DE")}})); // ignored while scanning
                      w.script << qMakePair(qint64(9000), at("filter", {{QStringLiteral("cc"), QStringLiteral("DE")}}));
                      w.script << qMakePair(qint64(9100), at("row_tapped", {{QStringLiteral("node_id"), QStringLiteral("4:xray")}}));
                      w.runMs = 12000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject during = viewAt(d, 150);
                      f.check(during.value(QLatin1String("bar")).toObject().value(QLatin1String("selected")).toString().isEmpty(),
                              QStringLiteral("filter ignored while scanning"));
                      const QJsonObject v = viewAt(d, 9050);
                      for (const QJsonValue &r : v.value(QLatin1String("rows")).toArray())
                          f.check(r.toObject().value(QLatin1String("cc")).toString() == QLatin1String("DE"), QStringLiteral("only DE"));
                      const QList<ScanAction> taps = actionsOf(d, ScanActionKind::ConnectRow);
                      for (const QString &id : taps.value(0).ids)
                          f.check(specOf(d.w, id) && specOf(d.w, id)->cc == QLatin1String("DE"), QStringLiteral("order only DE: ") + id);
                      f.check(v.value(QLatin1String("bar")).toObject().value(QLatin1String("menu_visible")).toBool(), QStringLiteral("menu visible"));
                  }};

    // 12. Cooldown: reopening inside 30 s shows the result; «Повторить через N с»; then a new scan.
    l << Scenario{QStringLiteral("cooldown"),
                  {QStringLiteral("cooldown from the scan start"), QStringLiteral("S6 reopen shows the last result")},
                  [] {
                      World w = baseWorld("cooldown", hostMac(), ScanNetKind::Wifi);
                      w.current = QStringLiteral("1");
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.script << qMakePair(qint64(9000), at("closed"));
                      w.script << qMakePair(qint64(12000), at("opened", openArgs(w, w.current, true)));
                      w.script << qMakePair(qint64(15000), at("retry"));
                      w.script << qMakePair(qint64(31000), at("retry"));
                      w.runMs = 33000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject v = viewAt(d, 12000);
                      f.check(phaseOf(v) == QLatin1String("done"), QStringLiteral("S6 shows the result"));
                      const QJsonObject bar = v.value(QLatin1String("bar")).toObject();
                      f.check(bar.value(QLatin1String("button")).toString() == QLatin1String("retry_in_s") && bar.value(QLatin1String("button_value")).toInt() == 18,
                              QStringLiteral("retry in 18 s"));
                      f.check(countActions(d, ScanActionKind::RequestManifest) == 2, QStringLiteral("only the 31 s retry scans again"));
                  }};

    // 13. Reopen after the cooldown: the last rows appear at once as cached, a fresh scan replaces them.
    l << Scenario{QStringLiteral("cached_reopen"),
                  {QStringLiteral("cached rows on open"), QStringLiteral("cached rows dropped unless re-verified")},
                  [] {
                      World w = baseWorld("cached_reopen", hostMac(), ScanNetKind::Wifi);
                      w.current = QStringLiteral("1");
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.script << qMakePair(qint64(9000), at("closed"));
                      w.script << qMakePair(qint64(9000 + 3 * 60000), [](qint64 t) {
                          World x = baseWorld("cached_reopen", hostMac(), ScanNetKind::Wifi);
                          // the node 10:xray dies meanwhile: its cached row must go
                          return ev("opened", t, openArgs(x, QStringLiteral("1"), true));
                      });
                      w.runMs = 9000 + 3 * 60000 + 12000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject v = viewAt(d, 9000 + 3 * 60000);
                      f.check(v.value(QLatin1String("checked_ago_min")).toInt() == 3, QStringLiteral("caption 3 min"));
                      bool cache = false;
                      for (const QJsonValue &r : v.value(QLatin1String("rows")).toArray())
                          cache = cache || r.toObject().value(QLatin1String("flags")).toArray().contains(QStringLiteral("cache"));
                      f.check(cache, QStringLiteral("cached rows shown"));
                      const QJsonObject end = lastView(d);
                      for (const QJsonValue &r : end.value(QLatin1String("rows")).toArray())
                          f.check(!r.toObject().value(QLatin1String("flags")).toArray().contains(QStringLiteral("cache")),
                                  QStringLiteral("no cached row after the scan"));
                  }};

    // 14. «Проверить и отправить отчёт»: checking, then sent; then again with no connectivity (queued).
    l << Scenario{QStringLiteral("check_and_report"),
                  {QStringLiteral("card Checking/Checked"), QStringLiteral("report always sent"), QStringLiteral("queued -> info shade")},
                  [] {
                      World w = baseWorld("check_and_report", hostMac(), ScanNetKind::Wifi);
                      w.current = QStringLiteral("1");
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.script << qMakePair(qint64(9000), at("check_tapped"));
                      w.runMs = 12000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject v = viewAt(d, 9100);
                      f.check(v.value(QLatin1String("card")).toObject().value(QLatin1String("mode")).toString() == QLatin1String("checking"),
                              QStringLiteral("checking"));
                      f.check(v.value(QLatin1String("card")).toObject().value(QLatin1String("button")).toString() == QLatin1String("busy"),
                              QStringLiteral("button busy"));
                      const QJsonObject e = lastView(d);
                      f.check(e.value(QLatin1String("card")).toObject().value(QLatin1String("mode")).toString() == QLatin1String("checked"),
                              QStringLiteral("checked"));
                      f.check(e.value(QLatin1String("card")).toObject().value(QLatin1String("speed")).toObject().value(QLatin1String("bars")).toInt() == 5,
                              QStringLiteral("speed bars"));
                      f.check(hasShade(d, "report_sent"), QStringLiteral("success shade"));
                      f.check(actionsOf(d, ScanActionKind::StartReportCheck).value(0).withConnection, QStringLiteral("with the connection"));
                  }};

    // 15. Empty state, report offline: «Отправляем отчёт…», then «Отчёт уйдёт, когда появится связь».
    l << Scenario{QStringLiteral("report_offline_empty"),
                  {QStringLiteral("report without a connection"), QStringLiteral("queued -> info shade")},
                  [] {
                      World w = baseWorld("report_offline_empty", hostMacMinimal(), ScanNetKind::Cellular);
                      w.nodes = ownOnly(w.nodes); // providers: only first-wave seats, the rest «Не проверено»
                      for (auto it = w.out.begin(); it != w.out.end(); ++it)
                          it.value().reachOk = false, it.value().works = false;
                      w.delivery = ScanReportDelivery::Queued;
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
                      w.script << qMakePair(qint64(10000), at("report_link_tapped"));
                      w.runMs = 13000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject v = viewAt(d, 10100);
                      f.check(v.value(QLatin1String("empty")).toObject().value(QLatin1String("report_sending")).toBool(), QStringLiteral("sending"));
                      f.check(hasShade(d, "report_queued"), QStringLiteral("queued shade"));
                      f.check(!actionsOf(d, ScanActionKind::StartReportCheck).value(0).withConnection, QStringLiteral("without a connection"));
                      f.check(!lastView(d).value(QLatin1String("empty")).toObject().value(QLatin1String("report_sending")).toBool(),
                              QStringLiteral("sending ends"));
                  }};

    // 16. A provider leg whose DNS plan is not through the leg: a full-profile follow-up confirms it.
    l << Scenario{QStringLiteral("legs_dns_follow_up"),
                  {QStringLiteral("leg verdict needs the DNS plan through the leg"), QStringLiteral("full follow-up after the legs"),
                   QStringLiteral("follow-up probe id <id>#full")},
                  [] {
                      World w = baseWorld("legs_dns_follow_up", hostMac(), ScanNetKind::Wifi);
                      w.current = QStringLiteral("1");
                      // few own nodes work, so the provider rows enter the list
                      for (const char *id : {"4:xray", "5:xray", "7:xray", "8:xray", "9:xray", "10:xray", "3", "6"})
                          w.out[QLatin1String(id)].reachOk = false, w.out[QLatin1String(id)].handshake = false;
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.runMs = 12000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QList<ScanAction> b = actionsOf(d, ScanActionKind::RequestProbeBatch);
                      f.check(b.size() == 1 && b.value(0).ids.contains(up(3)) && b.value(0).includeConfig,
                              QStringLiteral("one batch with the configs (a follow-up may come)"));
                      bool probeId = false;
                      for (const ScanAction &a : actionsOf(d, ScanActionKind::AddHostCandidates))
                          for (const ScanCandidate &c : a.candidates)
                              probeId = probeId || scanProbeIdOf(c) == up(3) + QStringLiteral("#full");
                      f.check(probeId, QStringLiteral("follow-up probe id"));
                      const QJsonObject v = lastView(d);
                      f.check(rowOf(v, up(3)).value(QLatin1String("state")).toString() == QLatin1String("works"), QStringLiteral("confirmed works"));
                      f.check(rowOf(v, up(1)).value(QLatin1String("state")).toString() == QLatin1String("works"), QStringLiteral("dns leg verdict"));
                      f.check(rowOf(v, up(1)).value(QLatin1String("flags")).toArray().contains(QStringLiteral("crowd")), QStringLiteral("crowd mark"));
                  }};

    // 17. Own AmneziaWG nodes on a host with awg_mini (awg-probe-plan.md): the device's own key, a sized download
    //     through the node, the egress node checked; never the live node or an attempt's target.
    l << Scenario{QStringLiteral("awg_mini"),
                  {QStringLiteral("awg_mini only with the switch, scan_awg_concurrency and awg_probe"), QStringLiteral("own pool number"),
                   QStringLiteral("egress node must be the probed node"), QStringLiteral("an attempt's target leaves the scan")},
                  [] {
                      World w = baseWorld("awg_mini", hostMac(), ScanNetKind::Wifi);
                      w.numbers.insert(QStringLiteral("scan_stop_works"), 48); // every verdict before the stop (rows are admitted across tiers)
                      w.current = QStringLiteral("2:xray");
                      w.awgMini = true;
                      w.numbers.insert(QStringLiteral("scan_awg_concurrency"), 2);
                      for (NodeSpec &n : w.nodes)
                          if (n.id == QLatin1String("3"))
                              n.awgProbe = false;          // no peer there: absent, never a failure
                      w.out[QStringLiteral("6")].handshake = false;
                      w.out[QStringLiteral("2")].egressNode = QStringLiteral("9"); // left through another node
                      for (const char *id : {"1", "2", "6"})
                          w.out[QLatin1String(id)].durMs = 900;
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      // the engine starts an attempt to "1" while its session runs: "1" must leave the scan
                      w.script << qMakePair(qint64(300), [](qint64 t) {
                          World x = baseWorld("awg_mini", hostMac(), ScanNetKind::Wifi);
                          ScanCurrent c = liveOf(x, QStringLiteral("2:xray"), true);
                          c.attemptNodeId = QStringLiteral("1");
                          return ev("vpn_state", t, {{QStringLiteral("current"), currentJson(c)}});
                      });
                      w.runMs = 12000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const ScanAction start = actionsOf(d, ScanActionKind::StartHostScan).value(0);
                      QStringList awg;
                      for (const ScanCandidate &c : start.candidates)
                          if (c.kind == ScanProbeKind::AwgMini)
                              awg << c.id;
                      f.check(awg == QStringList({QStringLiteral("1"), QStringLiteral("2"), QStringLiteral("6")}), QStringLiteral("three sessions: ") + awg.join(QLatin1Char(',')));
                      f.check(start.limits.awgConcurrency == 2 && start.limits.awgSpacingMs == 50, QStringLiteral("awg pool from scan_awg_concurrency"));
                      const QJsonObject v = lastView(d);
                      const QStringList ids = rowIds(v);
                      f.check(!ids.contains(QStringLiteral("3")), QStringLiteral("no peer -> absent"));
                      f.check(!ids.contains(QStringLiteral("6")), QStringLiteral("no handshake -> hidden"));
                      f.check(!ids.contains(QStringLiteral("2")), QStringLiteral("other egress node -> not verified, hidden"));
                      f.check(!ids.contains(QStringLiteral("1")), QStringLiteral("attempt target left the scan"));
                      bool awgOutcome = false, unreachable = false;
                      for (const ScanAction &a : actionsOf(d, ScanActionKind::SendOutcomes))
                          for (const ScanOutcomeItem &it : a.outcomes) {
                              awgOutcome = awgOutcome || it.probe == QLatin1String("awg_mini");
                              unreachable = unreachable || (it.id == QLatin1String("6") && it.outcome == ScanClass::Unreachable);
                              f.check(it.id != QLatin1String("1"), QStringLiteral("no outcome for the attempt's target"));
                          }
                      f.check(awgOutcome && unreachable, QStringLiteral("awg outcome with probe awg_mini"));
                  }};

    // 17b. Same world, switch off (the compiled default): no AWG probe at all.
    l << Scenario{QStringLiteral("awg_mini_switch_off"),
                  {QStringLiteral("scanner_awg_mini off -> no awg_mini")},
                  [] {
                      World w = baseWorld("awg_mini_switch_off", hostMac(), ScanNetKind::Wifi);
                      w.current = QStringLiteral("2:xray");
                      w.numbers.insert(QStringLiteral("scan_awg_concurrency"), 2);
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.runMs = 12000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      for (const ScanAction &a : actionsOf(d, ScanActionKind::StartHostScan))
                          for (const ScanCandidate &c : a.candidates)
                              f.check(c.kind != ScanProbeKind::AwgMini, QStringLiteral("no awg_mini"));
                  }};

    // 18. Tier warm-up: provider probes start while own ones run, the list fills tier 0 first.
    l << Scenario{QStringLiteral("tier_warmup"),
                  {QStringLiteral("lower tiers warm up in parallel"), QStringLiteral("rows admitted across tiers (1.14.0)")},
                  [] {
                      World w = baseWorld("tier_warmup", hostMac(), ScanNetKind::Wifi);
                      w.current = QStringLiteral("1");
                      w.awgMini = true; // 11 own nodes work: the list is full of tier 0
                      w.numbers.insert(QStringLiteral("scan_awg_concurrency"), 4);
                      for (const NodeSpec &n : w.nodes)
                          if (n.provider)
                              w.out[n.id].rtt = 20, w.out[n.id].t64 = 60, w.out[n.id].durMs = 200; // faster than own ones
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.runMs = 12000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      // the first provider probe enters the host before any own result arrived
                      f.check(!d.leasesAsked.isEmpty(), QStringLiteral("providers leased"));
                      int firstLeaseStep = -1, firstOwnResult = -1;
                      for (int i = 0; i < d.steps.size(); ++i) {
                          if (firstLeaseStep < 0 && d.steps.at(i).step.has(ScanActionKind::AddHostCandidates))
                              firstLeaseStep = i;
                          if (firstOwnResult < 0 && d.steps.at(i).event.value(QLatin1String("event")).toString() == QLatin1String("host_progress")
                              && !d.steps.at(i).event.value(QLatin1String("args")).toObject().value(QLatin1String("reply")).toObject()
                                      .value(QLatin1String("items")).toArray().isEmpty())
                              firstOwnResult = i;
                      }
                      f.check(firstLeaseStep >= 0 && (firstOwnResult < 0 || firstLeaseStep < firstOwnResult), QStringLiteral("warm-up in parallel"));
                      const QJsonObject v = lastView(d);
                      // the providers proved faster than the own nodes: they make the list, whatever their tier (owner 18.11,
                      // contract 1.14.0: tiers order Auto only)
                      int up = 0;
                      for (const QString &id : rowIds(v))
                          up += id.startsWith(QLatin1String("up:")) ? 1 : 0;
                      f.check(up > 0, QStringLiteral("faster provider rows admitted across tiers"));
                  }};

    // 19. Cellular budget used up: no scan, «Повторить через N мин».
    l << Scenario{QStringLiteral("budget_blocked_cellular"),
                  {QStringLiteral("hourly cellular budget"), QStringLiteral("no manifest fetch when blocked")},
                  [] {
                      World w = baseWorld("budget_blocked_cellular", hostIosFull(), ScanNetKind::Cellular);
                      w.current = QStringLiteral("2");
                      // a first scan fills the ledger, then the hour is full
                      QJsonArray ledger;
                      ledger << QJsonObject{{QStringLiteral("at_ms"), double(kT0 - 20 * 60000)}, {QStringLiteral("bytes"), 4.0 * 1024 * 1024},
                                            {QStringLiteral("cellular"), true}};
                      w.ledger = ledger;
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.script << qMakePair(qint64(9000), at("closed"));
                      w.script << qMakePair(qint64(40000), at("opened", openArgs(w, w.current, true)));
                      w.runMs = 42000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject v = lastView(d);
                      f.check(phaseOf(v) == QLatin1String("no_scan"), QStringLiteral("no scan"));
                      const QJsonObject bar = v.value(QLatin1String("bar")).toObject();
                      f.check(bar.value(QLatin1String("button")).toString() == QLatin1String("retry_in_min"), QStringLiteral("retry in minutes"));
                      f.check(bar.value(QLatin1String("button_value")).toInt() >= 1, QStringLiteral("minutes >= 1"));
                      f.check(bar.value(QLatin1String("hint")).toString() == QLatin1String("cellular_budget_hour"), QStringLiteral("budget hint"));
                      f.check(countActions(d, ScanActionKind::RequestManifest) == 1, QStringLiteral("second open fetched nothing"));
                  }};

    // 20. Support chat run_diag: scan, then the button's check runs by itself.
    l << Scenario{QStringLiteral("chat_run_diag"),
                  {QStringLiteral("withCheck runs the check after the scan")},
                  [] {
                      World w = baseWorld("chat_run_diag", hostMac(), ScanNetKind::Wifi);
                      w.current = QStringLiteral("1");
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true, ScanCachedResult(), true)));
                      w.runMs = 14000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      f.check(countActions(d, ScanActionKind::StartReportCheck) == 1, QStringLiteral("one check"));
                      f.check(hasShade(d, "report_sent"), QStringLiteral("report sent"));
                  }};

    // 21. The network changes during the scan: the old results are reported under the old key, a new scan.
    l << Scenario{QStringLiteral("network_change_mid_scan"),
                  {QStringLiteral("scan restarted on the new network"), QStringLiteral("outcomes keep their network key")},
                  [] {
                      World w = baseWorld("network_change_mid_scan", hostMac(), ScanNetKind::Wifi);
                      w.current = QStringLiteral("1");
                      for (auto it = w.out.begin(); it != w.out.end(); ++it)
                          it.value().durMs = 1500;
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.script << qMakePair(qint64(1900), at("network_changed", {{QStringLiteral("network"),
                                                                                  netJson(scanNet(ScanNetKind::Cellular, QStringLiteral("cell:250-02:4g")))},
                                                                                 {QStringLiteral("cached"), QJsonObject()},
                                                                                 {QStringLiteral("app_in_front"), true}}));
                      w.runMs = 5000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QList<ScanAction> m = actionsOf(d, ScanActionKind::RequestManifest);
                      f.check(m.size() == 2 && m.value(1).networkKey == QLatin1String("cell:250-02:4g"), QStringLiteral("manifest for the new key"));
                      bool oldKey = false;
                      for (const ScanAction &a : actionsOf(d, ScanActionKind::SendOutcomes))
                          oldKey = oldKey || a.networkKey == QLatin1String("wifi:asn:64500");
                      f.check(oldKey, QStringLiteral("outcomes under the old key"));
                  }};

    // 22. Provider seats refused: «Не проверено», never «Не работает».
    l << Scenario{QStringLiteral("no_seat_not_verified"),
                  {QStringLiteral("no_seat -> not verified"), QStringLiteral("terminal -> dropped")},
                  [] {
                      World w = baseWorld("no_seat_not_verified", hostMac(), ScanNetKind::Wifi);
                      w.current = QStringLiteral("1");
                      for (const char *id : {"4:xray", "5:xray", "7:xray", "8:xray", "9:xray", "10:xray", "3", "6"})
                          w.out[QLatin1String(id)].reachOk = false, w.out[QLatin1String(id)].handshake = false;
                      w.leaseRefuse.insert(up(1), QStringLiteral("no_seat"));
                      w.leaseRefuse.insert(up(3), QStringLiteral("disabled"));
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.runMs = 12000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject v = lastView(d);
                      f.check(rowOf(v, up(1)).value(QLatin1String("state")).toString() == QLatin1String("not_verified"), QStringLiteral("no_seat not verified"));
                      f.check(rowOf(v, up(3)).isEmpty(), QStringLiteral("disabled dropped"));
                  }};

    // 23-26. Stopping a scan (plan §2.2b step 5): freeze -> ack {spent, reserved} -> cancel -> the final
    // totals; without the final the ack's spent + reserved; without the ack the whole host grant. Own nodes,
    // VPN off, probes still running at «Остановить»: the app side is the manifest + token alone (20480 real).
    const auto drainWorld = [](const char *name, World::Stop stop) {
        World w = baseWorld(name, hostMac(), ScanNetKind::Cellular);
        w.nodes = ownOnly(w.nodes);
        for (auto it = w.out.begin(); it != w.out.end(); ++it)
            it.value().durMs = 3000;
        w.stop = stop;
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
        w.script << qMakePair(qint64(1500), at("stop"));
        w.runMs = 8000;
        return w;
    };
    const auto ledgerOf = [](const Driver &d) { return d.m.ledger().spentInHour(d.now, true); };
    const auto drainCommon = [](const Driver &d, Fail &f) {
        int freezeAt = -1, stopAt = -1;
        for (int i = 0; i < d.steps.size(); ++i)
            for (const ScanAction &a : d.steps.at(i).step.actions) {
                if (a.kind == ScanActionKind::FreezeHostScan && freezeAt < 0)
                    freezeAt = i;
                if (a.kind == ScanActionKind::StopHostScan && stopAt < 0)
                    stopAt = i;
            }
        f.check(freezeAt >= 0 && stopAt > freezeAt, QStringLiteral("freeze before cancel"));
        f.check(countActions(d, ScanActionKind::FreezeHostScan) == 1 && countActions(d, ScanActionKind::StopHostScan) == 1,
                QStringLiteral("one freeze, one cancel"));
        f.check(countActions(d, ScanActionKind::PersistBudget) == 1 && !d.m.draining(), QStringLiteral("one ledger entry, settled"));
    };
    const auto eventArg = [](const Driver &d, const char *name, const char *key) {
        for (const Recorded &r : d.steps)
            if (r.event.value(QLatin1String("event")).toString() == QLatin1String(name))
                return qint64(r.event.value(QLatin1String("args")).toObject().value(QLatin1String(key)).toDouble());
        return qint64(-1);
    };
    l << Scenario{QStringLiteral("drain_final"),
                  {QStringLiteral("freeze, ack, cancel, final total"), QStringLiteral("ledger = app actual + final")},
                  [drainWorld] { return drainWorld("drain_final", World::Stop::Final); },
                  [drainCommon, ledgerOf](const Driver &d, Fail &f) {
                      drainCommon(d, f);
                      qint64 fin = -1;
                      for (const Recorded &r : d.steps) {
                          const QJsonObject rep = r.event.value(QLatin1String("args")).toObject().value(QLatin1String("reply")).toObject();
                          if (rep.value(QLatin1String("final")).toBool())
                              fin = qint64(rep.value(QLatin1String("bytes_spent")).toDouble());
                      }
                      f.check(fin > 0 && ledgerOf(d) == 20480 + fin, QStringLiteral("charged the final total"));
                  }};
    l << Scenario{QStringLiteral("drain_cancel_ack_total"),
                  {QStringLiteral("the totals may come in the cancel ack")},
                  [drainWorld] { return drainWorld("drain_cancel_ack_total", World::Stop::CancelAckTotal); },
                  [drainCommon, ledgerOf, eventArg](const Driver &d, Fail &f) {
                      drainCommon(d, f);
                      const qint64 total = eventArg(d, "host_cancel_ack", "bytes_spent");
                      f.check(total > 0 && ledgerOf(d) == 20480 + total, QStringLiteral("charged the cancel ack total"));
                  }};
    l << Scenario{QStringLiteral("drain_ack_no_final"),
                  {QStringLiteral("no final within scan_drain_ms: the ack's spent + reserved")},
                  [drainWorld] { return drainWorld("drain_ack_no_final", World::Stop::AckNoFinal); },
                  [drainCommon, ledgerOf, eventArg](const Driver &d, Fail &f) {
                      drainCommon(d, f);
                      const qint64 spent = eventArg(d, "host_freeze_ack", "spent"), reserved = eventArg(d, "host_freeze_ack", "reserved");
                      f.check(reserved > 0 && ledgerOf(d) == 20480 + spent + reserved, QStringLiteral("charged ack spent + reserved"));
                      bool late = false; // the charge came scan_drain_ms after the ack, not before
                      for (const Recorded &r : d.steps)
                          if (r.step.has(ScanActionKind::PersistBudget))
                              late = qint64(r.event.value(QLatin1String("now_ms")).toDouble()) >= kT0 + 1500 + 30 + 2000;
                      f.check(late, QStringLiteral("after scan_drain_ms"));
                  }};
    l << Scenario{QStringLiteral("drain_no_ack"),
                  {QStringLiteral("no freeze ack within scan_freeze_ack_ms: the whole host grant")},
                  [drainWorld] { return drainWorld("drain_no_ack", World::Stop::NoAck); },
                  [drainCommon, ledgerOf](const Driver &d, Fail &f) {
                      drainCommon(d, f);
                      const qint64 grant = actionsOf(d, ScanActionKind::StartHostScan).value(0).maxBytes;
                      f.check(grant == 1572864 - 20480 - 16384 && ledgerOf(d) == 20480 + grant, QStringLiteral("charged the whole grant"));
                  }};

    // 27. The host's share cannot carry one probe (plan §2.2b step 3, S11): a full 200 manifest on a small
    // allowance; the scan runs app side only - the live-tunnel check and the light checks.
    l << Scenario{QStringLiteral("app_side_only"),
                  {QStringLiteral("grant below one probe: no host"), QStringLiteral("budget notice"), QStringLiteral("live check still runs")},
                  [] {
                      World w = baseWorld("app_side_only", hostMac(), ScanNetKind::Cellular);
                      w.current = QStringLiteral("1");
                      w.manifestBytes = 270336;
                      w.numbers.insert(QStringLiteral("scan_budget_scan_bytes"), 420000);
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.runMs = 12000;
                      return w;
                  },
                  [ledgerOf](const Driver &d, Fail &f) {
                      f.check(countActions(d, ScanActionKind::StartHostScan) == 0 && countActions(d, ScanActionKind::RequestProbeBatch) == 0,
                              QStringLiteral("no host, no seats"));
                      f.check(hasShade(d, "scan_budget"), QStringLiteral("budget shade"));
                      f.check(countActions(d, ScanActionKind::ProbeLiveTunnel) == 1 && countActions(d, ScanActionKind::StartLightChecks) == 1,
                              QStringLiteral("app side runs"));
                      const QJsonObject v = lastView(d);
                      f.check(phaseOf(v) == QLatin1String("done") && rowOf(v, QStringLiteral("1")).value(QLatin1String("state")).toString() == QLatin1String("connected"),
                              QStringLiteral("the live row"));
                      f.check(d.m.lastStats().value(QLatin1String("app_side_only")).toBool(), QStringLiteral("stats app_side_only"));
                      f.check(ledgerOf(d) > 0 && ledgerOf(d) <= 420000, QStringLiteral("inside the allowance"));
                  }};

    // 28. An app reply that passes its reservation is cut there (plan §2.2b step 2): the batch answer.
    l << Scenario{QStringLiteral("app_slice_abort"),
                  {QStringLiteral("a reply is cut at its reservation"), QStringLiteral("its grants fail as transport")},
                  [] {
                      World w = baseWorld("app_slice_abort", hostMac(), ScanNetKind::Cellular);
                      w.current = QStringLiteral("1");
                      w.cutApp = QStringLiteral("batch");
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.runMs = 12000;
                      return w;
                  },
                  [ledgerOf](const Driver &d, Fail &f) {
                      const ScanAction b = actionsOf(d, ScanActionKind::RequestProbeBatch).value(0);
                      f.check(b.costBytes == 12288 && !b.includeConfig, QStringLiteral("batch reserved at its worst case, no configs"));
                      qint64 reported = -1;
                      for (const Recorded &r : d.steps)
                          if (r.event.value(QLatin1String("event")).toString() == QLatin1String("app_request_done")
                              && r.event.value(QLatin1String("args")).toObject().value(QLatin1String("request_id")).toString() == b.requestId)
                              reported = qint64(r.event.value(QLatin1String("args")).toObject().value(QLatin1String("bytes")).toDouble());
                      f.check(reported == b.costBytes, QStringLiteral("cut at the reservation"));
                      f.check(countActions(d, ScanActionKind::AddHostCandidates) == 0, QStringLiteral("no provider probed"));
                      f.check(d.m.lastSummary().value(QLatin1String("not_verified_reasons")).toObject().value(QLatin1String("transport")).toInt() >= 1,
                              QStringLiteral("transport reason"));
                      f.check(ledgerOf(d) <= 1572864, QStringLiteral("inside the allowance"));
                  }};

    // 29-33. Proof by exclusion (plan §2.8): a whitelist window - the host's direct access check cannot reach
    // the API (no HTTP answer) before and after the probes, own nodes are cut, a provider leg brings the
    // verified body. Both attempts failed -> works (exclusion); any HTTP answer, a missing closing attempt,
    // another path state of the host, or the strict switch -> «Не проверено».
    const auto exclWorld = [](const char *name) {
        World w = baseWorld(name, hostMac(), ScanNetKind::Cellular);
        for (const NodeSpec &n : w.nodes)
            if (!n.provider)
                w.out[n.id].reachOk = false, w.out[n.id].handshake = false;
        w.accessOpen = QStringLiteral("network_error");
        w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
        w.runMs = 12000;
        return w;
    };
    const auto exclRow = [](const Driver &d) { return rowOf(lastView(d), up(1)); };
    l << Scenario{QStringLiteral("exclusion_both_failed"),
                  {QStringLiteral("both attempts failed at the network level -> works"), QStringLiteral("outcome and Doctor row with evidence exclusion")},
                  [exclWorld] { return exclWorld("exclusion_both_failed"); },
                  [exclRow](const Driver &d, Fail &f) {
                      const QJsonObject r = exclRow(d);
                      f.check(!r.isEmpty() && !r.value(QLatin1String("flags")).toArray().contains(QStringLiteral("unverified")),
                              QStringLiteral("works by exclusion"));
                      f.check(d.m.lastStats().value(QLatin1String("exclusion_rows")).toInt() == 1, QStringLiteral("stats"));
                      bool sent = false, evidence = false, strictOk = true;
                      for (const ScanAction &a : actionsOf(d, ScanActionKind::SendOutcomes)) {
                          ScanOutcomeCollector c;
                          c.begin(a.networkKey);
                          for (const ScanOutcomeItem &it : a.outcomes) {
                              c.add(it);
                              if (it.id == pidOf(up(1)) && scanClassWorking(it.outcome)) {
                                  sent = true;
                                  evidence = evidence || it.toJson(a.networkKey).value(QLatin1String("evidence")).toString() == QLatin1String("exclusion");
                              }
                          }
                          for (const QJsonObject &b : c.batches())
                              strictOk = strictOk && outcomeBatchRejects(b).isEmpty();
                      }
                      f.check(sent && evidence && strictOk, QStringLiteral("works outcome with evidence exclusion, accepted by the strict schema"));
                      bool persisted = false;
                      for (const ScanAction &a : actionsOf(d, ScanActionKind::PersistResults))
                          for (const ScanCachedRow &c : a.cached.rows)
                              persisted = persisted || c.id == up(1);
                      f.check(persisted, QStringLiteral("cached"));
                      const QJsonObject sum = d.m.lastSummary();
                      f.check(sum.value(QLatin1String("counts")).toObject().value(QLatin1String("works")).toInt() >= 1
                                  && !sum.value(QLatin1String("not_verified_reasons")).toObject().contains(QStringLiteral("unverifiable")),
                              QStringLiteral("summary counts it as works"));
                      bool inTop = false;
                      for (const QJsonValue &t : sum.value(QLatin1String("top")).toArray())
                          inTop = inTop || (t.toObject().value(QLatin1String("id")).toString() == pidOf(up(1))
                                            && t.toObject().value(QLatin1String("class")).toString() == QLatin1String("works")
                                            && t.toObject().value(QLatin1String("evidence")).toString() == QLatin1String("exclusion"));
                      f.check(inTop && summaryRejects(sum).isEmpty(), QStringLiteral("summary top row with evidence exclusion, strict schema"));
                  }};
    const auto exclNot = [exclRow](const Driver &d, Fail &f) {
        const QJsonObject r = exclRow(d);
        f.check(r.isEmpty() || r.value(QLatin1String("flags")).toArray().contains(QStringLiteral("unverified")), QStringLiteral("not verified"));
        f.check(d.m.lastStats().value(QLatin1String("exclusion_rows")).toInt() == 0, QStringLiteral("no exclusion row"));
        f.check(d.m.lastSummary().value(QLatin1String("not_verified_reasons")).toObject().value(QLatin1String("unverifiable")).toInt() >= 1,
                QStringLiteral("summary: unverifiable"));
    };
    l << Scenario{QStringLiteral("exclusion_http_answered"),
                  {QStringLiteral("an HTTP answer to an attempt -> not verified")},
                  [exclWorld] {
                      World w = exclWorld("exclusion_http_answered");
                      w.accessOpen = QStringLiteral("http_error");
                      w.accessClose = QStringLiteral("network_error");
                      return w;
                  },
                  exclNot};
    l << Scenario{QStringLiteral("exclusion_closing_missing"),
                  {QStringLiteral("no closing attempt -> not verified")},
                  [exclWorld] {
                      World w = exclWorld("exclusion_closing_missing");
                      w.accessClose = QStringLiteral("none");
                      return w;
                  },
                  exclNot};
    l << Scenario{QStringLiteral("exclusion_host_path_changed"),
                  {QStringLiteral("another path state between the attempts -> not verified")},
                  [exclWorld] {
                      World w = exclWorld("exclusion_host_path_changed");
                      w.hostGenBumpAtMs = 500;
                      return w;
                  },
                  exclNot};
    l << Scenario{QStringLiteral("exclusion_strict"),
                  {QStringLiteral("features.upstream_unverifiable_strict -> not verified")},
                  [exclWorld] {
                      World w = exclWorld("exclusion_strict");
                      w.strict = true;
                      return w;
                  },
                  exclNot};

    // 34-35. The probe host fails (coordinator finding 16.11): a refused scan_start settles at once with no
    // host charge; a host gone mid-scan goes through the bounded draining rule. Both end in NoScan host_<error>.
    l << Scenario{QStringLiteral("host_start_refused"),
                  {QStringLiteral("refused start: no host charge, settled at once"), QStringLiteral("NoScan host reason")},
                  [] {
                      World w = baseWorld("host_start_refused", hostMac(), ScanNetKind::Cellular);
                      w.nodes = ownOnly(w.nodes);
                      w.hostRefusesStart = QStringLiteral("memory");
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
                      w.runMs = 5000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject v = lastView(d);
                      f.check(phaseOf(v) == QLatin1String("no_scan") && v.value(QLatin1String("empty")).toObject().value(QLatin1String("reason")).toString()
                                  == QLatin1String("host_memory"), QStringLiteral("no scan, host reason"));
                      f.check(countActions(d, ScanActionKind::FreezeHostScan) == 0 && countActions(d, ScanActionKind::PersistBudget) == 1,
                              QStringLiteral("no freeze, one ledger entry"));
                      f.check(!d.m.draining() && d.m.ledger().spentInHour(d.now, true) == 20480, QStringLiteral("app actual only"));
                  }};
    l << Scenario{QStringLiteral("host_died_mid_scan"),
                  {QStringLiteral("host gone after the start: freeze unanswered, whole grant"), QStringLiteral("bounded, NoScan host reason")},
                  [] {
                      World w = baseWorld("host_died_mid_scan", hostMac(), ScanNetKind::Cellular);
                      w.nodes = ownOnly(w.nodes);
                      for (auto it = w.out.begin(); it != w.out.end(); ++it)
                          it.value().durMs = 4000;
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
                      w.script << qMakePair(qint64(1200), at("host_failed", {{QStringLiteral("scan_id"), QStringLiteral("scan-%1-1").arg(kT0)},
                                                                             {QStringLiteral("error"), QStringLiteral("unknown_scan")}}));
                      w.runMs = 5000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject v = lastView(d);
                      f.check(phaseOf(v) == QLatin1String("no_scan") && v.value(QLatin1String("empty")).toObject().value(QLatin1String("reason")).toString()
                                  == QLatin1String("host_unknown_scan"), QStringLiteral("no scan, host reason"));
                      f.check(countActions(d, ScanActionKind::FreezeHostScan) == 1 && countActions(d, ScanActionKind::StopHostScan) == 1
                                  && countActions(d, ScanActionKind::PersistBudget) == 1, QStringLiteral("freeze, cancel, one ledger entry"));
                      const qint64 grant = actionsOf(d, ScanActionKind::StartHostScan).value(0).maxBytes;
                      f.check(!d.m.draining() && d.m.ledger().spentInHour(d.now, true) == 20480 + grant, QStringLiteral("whole grant"));
                  }};

    // 36-41. Contract pass of 16.11 (the engine's additions made explicit).
    // An opening access attempt that never left the interface (dns / bind / no_route: null) and a closing
    // one that failed after packets left: not a bracket - no exclusion.
    l << Scenario{QStringLiteral("exclusion_opening_not_attempted"),
                  {QStringLiteral("opening not attempted + closing failed -> no exclusion")},
                  [exclWorld] {
                      World w = exclWorld("exclusion_opening_not_attempted");
                      w.openingSkipped = true;
                      w.manifestAccess = false; // the window: the app's own netinfo got nothing either
                      return w;
                  },
                  exclNot};
    // The desktop service cannot open its kill switch for probes: the start is refused with that detail.
    l << Scenario{QStringLiteral("host_kill_switch"),
                  {QStringLiteral("refused start with a detail -> host_kill_switch on the screen and in the summary")},
                  [] {
                      World w = baseWorld("host_kill_switch", hostMac(), ScanNetKind::Wifi);
                      w.nodes = ownOnly(w.nodes);
                      w.hostRefusesStart = QStringLiteral("internal");
                      w.hostRefusesDetail = QStringLiteral("kill_switch_exemption");
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
                      w.runMs = 4000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const QJsonObject v = lastView(d);
                      f.check(phaseOf(v) == QLatin1String("no_scan") && v.value(QLatin1String("empty")).toObject().value(QLatin1String("reason")).toString()
                                  == QLatin1String("host_kill_switch"), QStringLiteral("host_kill_switch"));
                      f.check(d.m.lastSummary().value(QLatin1String("stop_reason")).toString() == QLatin1String("host_kill_switch"), QStringLiteral("summary"));
                      f.check(!d.m.draining() && countActions(d, ScanActionKind::FreezeHostScan) == 0, QStringLiteral("settled at once"));
                  }};
    // The engine refuses the full check (the queue filled in a race): a notice, never «sent» / «will be sent».
    l << Scenario{QStringLiteral("report_check_refused"),
                  {QStringLiteral("refused check -> report_queue_full, card back to filled")},
                  [] {
                      World w = baseWorld("report_check_refused", hostMac(), ScanNetKind::Wifi);
                      w.current = QStringLiteral("1");
                      w.reportRefuse = QStringLiteral("queue_full");
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, w.current, true)));
                      w.script << qMakePair(qint64(9000), at("check_tapped"));
                      w.runMs = 11000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      f.check(shadeCount(d, "report_queue_full") == 1 && !hasShade(d, "report_sent") && !hasShade(d, "report_queued"),
                              QStringLiteral("notice only"));
                      f.check(lastView(d).value(QLatin1String("card")).toObject().value(QLatin1String("mode")).toString() == QLatin1String("filled"),
                              QStringLiteral("card filled again"));
                  }};
    // «Понял» on «no scan: budget» (the cellular hour used up): close and arm the Wi-Fi intent.
    l << Scenario{QStringLiteral("got_it_budget_no_scan"),
                  {QStringLiteral("budget no-scan: got it closes and arms the Wi-Fi intent")},
                  [] {
                      World w = baseWorld("got_it_budget_no_scan", hostMac(), ScanNetKind::Cellular);
                      QJsonArray ledger;
                      ledger << QJsonObject{{QStringLiteral("at_ms"), double(kT0 - 20 * 60000)}, {QStringLiteral("bytes"), 4.95 * 1024 * 1024},
                                            {QStringLiteral("cellular"), true}};
                      w.ledger = ledger;
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
                      w.script << qMakePair(qint64(2000), at("got_it"));
                      w.runMs = 3000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      f.check(phaseOf(viewAt(d, 1000)) == QLatin1String("no_scan") && countActions(d, ScanActionKind::RequestManifest) == 0,
                              QStringLiteral("budget no-scan"));
                      f.check(d.closes.size() == 1 && hasShade(d, "wifi_intent") && d.m.wifiIntentUntil() > 0, QStringLiteral("closed, intent armed"));
                  }};
    // awg_mini with the device's own tunnel address unknown: «Не проверено» awg_no_address, never probed.
    l << Scenario{QStringLiteral("awg_no_address"),
                  {QStringLiteral("no device address -> awg_mini not verified")},
                  [] {
                      World w = baseWorld("awg_no_address", hostMac(), ScanNetKind::Wifi);
                      w.awgMini = true;
                      w.awgAddressKnown = false;
                      w.numbers.insert(QStringLiteral("scan_awg_concurrency"), 2);
                      for (const NodeSpec &n : w.nodes)
                          if (n.transport == ScanTransport::Xray)
                              w.out[n.id].reachOk = false; // nothing else works: the «Не проверено» rows show
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
                      w.runMs = 12000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      bool awgProbed = false;
                      for (const ScanAction &a : actionsOf(d, ScanActionKind::StartHostScan))
                          for (const ScanCandidate &c : a.candidates)
                              awgProbed = awgProbed || c.kind == ScanProbeKind::AwgMini;
                      f.check(!awgProbed, QStringLiteral("no awg_mini scheduled"));
                      f.check(d.m.lastSummary().value(QLatin1String("not_verified_reasons")).toObject().value(QLatin1String("awg_no_address")).toInt() >= 1,
                              QStringLiteral("reason awg_no_address"));
                  }};
    // probe.base_ips from the coordinator reach the host's start (filtered, at most 8).
    l << Scenario{QStringLiteral("probe_base_ips"),
                  {QStringLiteral("base IPs passed to scan_start")},
                  [] {
                      World w = baseWorld("probe_base_ips", hostMac(), ScanNetKind::Wifi);
                      w.nodes = ownOnly(w.nodes);
                      w.probeBaseIps = {QStringLiteral("198.51.100.7"), QStringLiteral("2001:db8::7"), QStringLiteral("api.example")};
                      w.script << qMakePair(qint64(0), at("opened", openArgs(w, QString(), false)));
                      w.runMs = 10000;
                      return w;
                  },
                  [](const Driver &d, Fail &f) {
                      const ScanAction a = actionsOf(d, ScanActionKind::StartHostScan).value(0);
                      f.check(a.baseIps == QStringList({QStringLiteral("198.51.100.7"), QStringLiteral("2001:db8::7")}), QStringLiteral("base_ips"));
                  }};

    return l;
}

} // namespace scantest
