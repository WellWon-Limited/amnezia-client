#include "TribeScanner.h"

#include "DoctorReport.h"    // doctor::countryDisplayName: the app's country names (ru / es tables, QLocale)
#include "ScanPlan.h"        // scanAwgMiniFlag
#include "TuningStore.h"
#include "UpstreamVerdict.h" // upstreamUnverifiableStrictTuned
#include "XrayProfileSanitizer.h" // upstreamProfileCheck: the connect's profile rule

#include <QCryptographicHash>
#include <QDateTime>
#include <QDebug>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QHostInfo>
#include <QUrl>
#include <QJsonArray>
#include <QJsonDocument>
#include <QPointer>
#include <QTimer>

#include <climits>

namespace avpn {

namespace {

// The clock pair (header): monotonic inside the process, forward wall jumps taken, backward ones not.
class SystemScanClock : public IScanClock
{
public:
    SystemScanClock()
    {
        m_mono.start();
        m_anchor = QDateTime::currentMSecsSinceEpoch();
    }
    qint64 nowMs() override
    {
        qint64 t = m_anchor + m_mono.elapsed();
        const qint64 wall = QDateTime::currentMSecsSinceEpoch();
        if (wall > t + 2000) { // the machine slept or the wall clock was set forward
            m_anchor += wall - t;
            t = wall;
        }
        if (t < m_last)
            t = m_last;
        m_last = t;
        return t;
    }

private:
    QElapsedTimer m_mono;
    qint64 m_anchor = 0;
    qint64 m_last = 0;
};

class QtScanTimer : public IScanTimer
{
public:
    QtScanTimer()
    {
        m_t.setSingleShot(true);
        m_t.setTimerType(Qt::PreciseTimer);
        QObject::connect(&m_t, &QTimer::timeout, [this]() {
            if (onFire)
                onFire();
        });
    }
    void arm(qint64 delayMs) override { m_t.start(int(qBound(qint64(0), delayMs, qint64(INT_MAX)))); }
    void cancel() override { m_t.stop(); }

private:
    QTimer m_t;
};

QByteArray compactArray(const QJsonArray &a) { return QJsonDocument(a).toJson(QJsonDocument::Compact); }

class QtScanResolver : public IScanResolver
{
public:
    void lookup(const QString &host, std::function<void(const QStringList &)> done) override
    {
        QHostInfo::lookupHost(host, &m_ctx, [done](const QHostInfo &info) {
            QStringList ips;
            if (info.error() == QHostInfo::NoError)
                for (const QHostAddress &a : info.addresses())
                    ips << a.toString();
            if (done)
                done(ips);
        });
    }

private:
    QObject m_ctx; // late answers after the scanner is gone are dropped with it
};

// The detail a host error names its cause by (the core's host_<detail>): the error's own detail - except
// rate_limited, whose detail names the refused action ("scan_start"), not the cause.
QString scanHostFailureDetail(const ScanHostReply &r)
{
    if (r.errorCode == QLatin1String("rate_limited"))
        return QStringLiteral("rate_limited");
    return r.detail;
}

// The iOS host's refusal of awg_mini sessions while it cannot read the live AmneziaWG peer.
bool scanAwgLivePeerUnknown(const ScanHostReply &r)
{
    return r.kind == ScanHostReplyKind::Error && r.detail == QLatin1String("awg_live_peer_unknown");
}

// A transient "not now" of the host (iOS / desktop / engine review fixes): the tunnel started changing, a stop-all
// is still tearing down, or a start older than the last stop. Not a failure, nothing about any node.
bool scanHostNotNow(const ScanHostReply &r)
{
    return r.kind == ScanHostReplyKind::Error
           && (r.errorCode == QLatin1String("tunnel_changed") || r.errorCode == QLatin1String("stale_epoch")
               || r.detail == QLatin1String("stop_pending")          // iOS: internal + stop_pending
               || r.detail == QLatin1String("stopping")              // the engine: internal + stopping
               || r.errorCode == QLatin1String("teardown_pending")); // the desktop service's name of the same
}

// Waits for the tunnel to report its state (vpnState) rather than for scan_drain_ms: the tunnel was changing
// (tunnel_changed) or the start predates the last stop (stale_epoch).
bool scanHostNotNowWaitsForTunnel(const ScanHostReply &r)
{
    return r.errorCode == QLatin1String("tunnel_changed") || r.errorCode == QLatin1String("stale_epoch");
}

bool scanHasAwg(const QList<ScanHostCandidate> &cands)
{
    for (const ScanHostCandidate &c : cands)
        if (c.kind == ScanProbeKind::AwgMini)
            return true;
    return false;
}

// IP literals only, unique, the contract's at most 8 (IPv4 first: the probe hosts' sockets are bound to the
// physical interface, where IPv4 is the common case).
QStringList scanBaseIpsOf(const QStringList &in)
{
    QStringList v4, v6;
    for (const QString &raw : in) {
        const QString ip = raw.trimmed();
        if (!scanIsIpLiteral(ip) || v4.contains(ip) || v6.contains(ip))
            continue;
        (ip.contains(QLatin1Char(':')) ? v6 : v4) << ip;
    }
    return (v4 + v6).mid(0, kScanProbeBaseIpsMax);
}

} // namespace

QString scanCacheStoreKey(const QString &networkKey, const QString &fingerprint)
{
    const QByteArray h = QCryptographicHash::hash((QStringLiteral("tribe-scan-cache|") + networkKey + QLatin1Char('|') + fingerprint).toUtf8(),
                                                  QCryptographicHash::Sha256);
    return QLatin1String(kScanCacheStorePrefix) + QString::fromLatin1(h.toHex().left(16));
}

TribeScanner::TribeScanner(const Deps &d, QObject *parent)
    : QObject(parent), m_engine(d.engine), m_host(d.host), m_m(d.host ? d.host->knownCaps() : ScanHostCaps())
{
    Q_ASSERT(m_engine);
    m_fetchPoolOnOpen = d.fetchPoolOnOpen;
    if (d.store) {
        m_store = d.store;
    } else {
        m_ownStore = std::make_unique<ScanSettingsStore>();
        m_store = m_ownStore.get();
    }
    if (d.clock) {
        m_clock = d.clock;
    } else {
        m_ownClock = std::make_unique<SystemScanClock>();
        m_clock = m_ownClock.get();
    }
    if (d.timer) {
        m_timer = d.timer;
    } else {
        m_ownTimer = std::make_unique<QtScanTimer>();
        m_timer = m_ownTimer.get();
    }
    m_http = d.http;
    if (d.resolver) {
        m_resolver = d.resolver;
    } else {
        m_ownResolver = std::make_unique<QtScanResolver>();
        m_resolver = m_ownResolver.get();
    }
    m_api = new ScanApiClient(m_http, m_store, this);
    m_api->log = [this](const QString &line) { emitLog(QStringLiteral("api ") + line); };
    QPointer<TribeScanner> self(this);
    m_timer->onFire = [self]() {
        if (self)
            self->timerFired();
    };
    m_m.restoreBudget(QJsonDocument::fromJson(m_store->read(QLatin1String(kScanBudgetStoreKey))).array());
    m_enabled = TuningStore::flag(QLatin1String(kScannerFlag), false);
    m_doctorLegacy = TuningStore::flag(QLatin1String(kDoctorLegacyFlag), false);
    m_connectOnOpen = scanConnectOnOpenFlag();
    m_returnHome = TuningStore::flag(QLatin1String(kScannerReturnHomeFlag), false);
    if (m_host) {
        m_host->onAvailabilityChanged = [self]() {
            if (self)
                self->hostAvailabilityChanged();
        };
        m_host->onGenerationChanged = [self]() {
            if (self)
                self->hostGenerationChanged();
        };
        ScanNetSource g;
        if (hostGenerationNow(g)) {
            m_hostGenFolded = true;
            setHostGen(g);
        }
    }
    m_lastNet = buildNetwork();
    if (m_host && m_host->availability() == ScanHostAvailability::Available)
        queryCaps(nullptr);
    dispatch(m_m.reportQueueState(m_engine->reportQueueFull(), now()));
}

TribeScanner::~TribeScanner()
{
    if (m_timer)
        m_timer->onFire = nullptr;
    if (m_host) {
        m_host->onAvailabilityChanged = nullptr;
        m_host->onGenerationChanged = nullptr;
        bool open = false;
        for (const HostScan &h : m_hostScans)
            open = open || !h.finalSeen;
        for (const HostRecord &r : m_records)
            open = open || (r.ours && !r.settled);
        if (open)
            m_host->stopAll(); // best effort; never touches the tunnel
    }
}

void TribeScanner::configureApi(QNetworkAccessManager *nam, std::function<QString()> apiBase,
                                std::function<QString()> pubKeyHex, std::function<QString()> deviceToken)
{
    if (!m_http && nam) {
        m_ownHttp = std::make_unique<ScanQnamHttp>(nam);
        m_http = m_ownHttp.get();
        m_api->setHttp(m_http);
    }
    m_api->configure(std::move(apiBase), std::move(pubKeyHex), std::move(deviceToken));
    if (nam)
        m_api->setNetworkManager(nam);
}

qint64 TribeScanner::now() { return m_clock->nowMs(); }

void TribeScanner::emitLog(const QString &line) const
{
    if (log)
        log(line);
    else
        qInfo().noquote() << "[scanner]" << line;
}

int TribeScanner::pollsActive() const
{
    int n = 0;
    for (const HostScan &h : m_hostScans)
        n += h.finalSeen ? 0 : 1;
    return n;
}

// --- the event loop of the machine -----------------------------------------------------------------------------

void TribeScanner::dispatch(const ScanStep &s)
{
    m_machineWake = s.wakeAtMs; // the latest step describes the machine's current deadlines
    for (const ScanAction &a : s.actions)
        m_queue << a;
    if (m_dispatching)
        return;
    m_dispatching = true;
    while (!m_queue.isEmpty())
        execute(m_queue.takeFirst());
    m_dispatching = false;
    afterStep();
}

void TribeScanner::afterStep()
{
    refreshView();
    driveRecords(); // a step may have settled, handed over or untracked a host scan; re-arms the timer
}

void TribeScanner::execute(const ScanAction &a)
{
    switch (a.kind) {
    case ScanActionKind::RequestManifest:
        doRequestManifest(a);
        break;
    case ScanActionKind::StartHostScan:
        doStartHost(a);
        break;
    case ScanActionKind::AddHostCandidates:
        doAddHost(a);
        break;
    case ScanActionKind::FreezeHostScan:
        doFreeze(a);
        break;
    case ScanActionKind::StopHostScan:
        doCancel(a);
        break;
    case ScanActionKind::RequestProbeBatch:
        doProbeBatch(a);
        break;
    case ScanActionKind::ReleaseProbeLeases:
        doRelease(a);
        break;
    case ScanActionKind::StartLightChecks:
        doLight(a);
        break;
    case ScanActionKind::StartReportCheck:
        emitLog(QStringLiteral("action start_report_check with_connection=%1").arg(a.withConnection));
        m_checkReportId = a.reportId;
        m_checkAsked = bindingNow();
        m_engine->startReportCheck(a.reportId, a.report, a.withConnection);
        break;
    case ScanActionKind::ShowShade:
        doShade(a.shade);
        break;
    case ScanActionKind::SendOutcomes:
        doOutcomes(a);
        break;
    case ScanActionKind::PersistResults:
        persistCache(a.cached);
        break;
    case ScanActionKind::PersistBudget:
        m_store->write(QLatin1String(kScanBudgetStoreKey), compactArray(a.ledger));
        break;
    case ScanActionKind::CloseScreen:
        emitLog(QStringLiteral("action close_screen"));
        emit closeScreenRequested();
        break;
    case ScanActionKind::OpenScreen:
        emitLog(QStringLiteral("action open_screen"));
        emit openScreenRequested();
        break;
    case ScanActionKind::ProbeLiveTunnel:
        doLiveProbe(a);
        break;
    case ScanActionKind::RequestCandidates:
        doCandidates(a);
        break;
    // The only three that reach the tunnel (CONNECT-INVARIANTS §32): handed to the engine lane unchanged.
    case ScanActionKind::UserConnectForScan:
        emitLog(QStringLiteral("action user_connect_for_scan"));
        m_engine->userConnectForScan();
        break;
    case ScanActionKind::CancelPendingConnect:
        emitLog(QStringLiteral("action cancel_pending_connect"));
        m_engine->cancelPendingConnect();
        break;
    case ScanActionKind::ConnectRow:
        emitLog(QStringLiteral("action connect_row order=%1 user_origin=%2 force=%3")
                    .arg(a.ids.size())
                    .arg(a.userOrigin)
                    .arg(a.forceConnect));
        m_engine->connectRow(a.nodeId, a.ids, a.hintTtlMs, a.userOrigin, a.forceConnect);
        break;
    }
}

void TribeScanner::reschedule()
{
    qint64 due = -1;
    for (qint64 t : {m_machineWake, m_viewWake, m_shadeWake, m_nextPollAt, m_heldUntil, m_resolveUntil})
        if (t >= 0 && (due < 0 || t < due))
            due = t;
    const auto take = [&due](qint64 t) {
        if (t >= 0 && (due < 0 || t < due))
            due = t;
    };
    for (const HeldRetry &h : m_notNow)
        take(h.dueAt);
    // The settlement records (invariant 2): every one of their waits is bounded and wakes this timer.
    const bool hostUp = m_host && m_host->availability() == ScanHostAvailability::Available;
    for (const HostRecord &r : m_records) {
        if (r.ours && !r.settled) {
            take(r.deadline);
            if (hostUp && r.state != HostStart::InFlight && !r.pollInFlight)
                take(r.nextPollAt);
        }
        take(r.dropAt);
    }
    if (due < 0) {
        m_timer->cancel();
        return;
    }
    m_timer->arm(qMax<qint64>(0, due - now()));
}

void TribeScanner::timerFired()
{
    const qint64 t = now();
    if (m_shadeWake >= 0 && t >= m_shadeWake) {
        m_shadeWake = -1;
        applyShadeStep(m_shade.tick(t));
    }
    if (m_nextPollAt >= 0 && t >= m_nextPollAt)
        pollHost();
    if (m_heldUntil >= 0 && t >= m_heldUntil)
        resolveHeld(true);
    fireNotNow(false);
    driveRecords();
    if (m_resolveUntil >= 0 && t >= m_resolveUntil)
        finishResolve(QStringList()); // the name did not resolve in time: the host resolves it itself
    if (m_machineWake >= 0 && t >= m_machineWake) {
        m_machineWake = -1;
        dispatch(m_m.tick(t)); // a wake-up of the machine: it stops probes / fills the card, never the tunnel
        return;
    }
    afterStep();
}

void TribeScanner::refreshView()
{
    const qint64 t = now();
    const ScanView v = m_m.view(t);
    QJsonObject j = scanViewToJson(v);
    // Screen fields the core's JSON leaves out (scanner-api-note.md (b)): the row's protocol version (the
    // engine's node data, «Amnezia v3.1»), the card's server name and country, the country menu's names.
    QJsonArray rows = j.value(QLatin1String("rows")).toArray();
    for (int i = 0; i < rows.size() && i < v.rows.size(); ++i) {
        QJsonObject r = rows.at(i).toObject();
        r.insert(QStringLiteral("version"), v.rows.at(i).transportVersion);
        const QString name = m_engine->rowDisplayName(v.rows.at(i).id);
        if (!name.isEmpty())
            r.insert(QStringLiteral("label"), name);
        rows[i] = r;
    }
    j.insert(QStringLiteral("rows"), rows);
    QJsonObject card = j.value(QLatin1String("card")).toObject();
    if (v.card.mode != ScanCardMode::Hidden && v.card.mode != ScanCardMode::Off) {
        card.insert(QStringLiteral("server_label"), v.card.serverLabel);
        card.insert(QStringLiteral("server_cc"), v.card.serverCountry);
    }
    j.insert(QStringLiteral("card"), card);
    QJsonObject bar = j.value(QLatin1String("bar")).toObject();
    QJsonArray countries = bar.value(QLatin1String("countries")).toArray();
    const QString lang = m_engine->uiLanguage();
    for (int i = 0; i < countries.size(); ++i) {
        QJsonObject c = countries.at(i).toObject();
        c.insert(QStringLiteral("name"), doctor::countryDisplayName(c.value(QLatin1String("cc")).toString(), lang));
        countries[i] = c;
    }
    bar.insert(QStringLiteral("countries"), countries);
    QJsonArray scope = bar.value(QLatin1String("scope_countries")).toArray();
    for (int i = 0; i < scope.size(); ++i) {
        QJsonObject c = scope.at(i).toObject();
        c.insert(QStringLiteral("name"), doctor::countryDisplayName(c.value(QLatin1String("cc")).toString(), lang));
        scope[i] = c;
    }
    if (!scope.isEmpty())
        bar.insert(QStringLiteral("scope_countries"), scope);
    j.insert(QStringLiteral("bar"), bar);
    j.insert(QStringLiteral("cooldown_ends_at_ms"), double(t < m_m.cooldownUntil() ? m_m.cooldownUntil() : 0));
    j.insert(QStringLiteral("next_change_at_ms"), double(v.nextChangeAtMs));
    j.insert(QStringLiteral("screen_open"), m_m.screenOpen());
    m_viewWake = v.nextChangeAtMs;
    if (j == m_viewJson)
        return;
    m_viewJson = j;
    QJsonObject withNow = j;
    withNow.insert(QStringLiteral("now_ms"), double(t));
    m_viewMap = withNow.toVariantMap();
    emit viewChanged();
}

// --- network -----------------------------------------------------------------------------------------------------

ScanNetwork TribeScanner::buildNetwork() const
{
    const ScanNetFacts f = m_engine->network();
    ScanNetwork n;
    n.kind = f.kind;
    n.key = scanNetworkKeyValid(f.reportingKey) ? f.reportingKey : QStringLiteral("unknown");
    n.sources = f.appSources;
    if (m_hostGenFolded)
        n.sources << m_hostGen;
    n.fingerprint = scanNetFingerprint(QLatin1String(scanNetKindName(f.kind)), n.key, f.gatewayHash);
    n.radio = f.kind != ScanNetKind::Cellular ? QString() : !f.radio.isEmpty() ? f.radio : m_radio ? m_radio() : QString();
    return n;
}

ScanCachedResult TribeScanner::cachedFor(const ScanNetwork &n) const
{
    const QByteArray raw = m_store->read(scanCacheStoreKey(n.key, n.fingerprint));
    if (raw.isEmpty())
        return ScanCachedResult();
    const QJsonObject stored = QJsonDocument::fromJson(raw).object();
    ScanCachedResult c = scanCachedResultFromJson(stored);
    scanDropLegacyLabels(c, stored); // an earlier build's «Сервер N» rows are never shown
    return c;
}

QHash<QString, int> TribeScanner::listFigures() const
{
    const ScanNetwork n = buildNetwork();
    return scanListFigures(cachedFor(n), n.key, n.fingerprint, m_clock->nowMs(), m_m.tunables().cacheWorksTtlS);
}

void TribeScanner::persistCache(const ScanCachedResult &c)
{
    if (c.networkKey.isEmpty())
        return;
    if (onResultsSaved)
        onResultsSaved(c);
    const QString key = scanCacheStoreKey(c.networkKey, c.fingerprint);
    QJsonObject stored = scanCachedResultToJson(c);
    stored.insert(QLatin1String(kScanCachedLabelRuleKey), QLatin1String(kScanCachedLabelRule));
    m_store->write(key, QJsonDocument(stored).toJson(QJsonDocument::Compact));
    QJsonArray idx = QJsonDocument::fromJson(m_store->read(QLatin1String(kScanCacheIndexKey))).array();
    for (int i = idx.size() - 1; i >= 0; --i)
        if (idx.at(i).toString() == key)
            idx.removeAt(i);
    idx << key;
    while (idx.size() > kScanCacheMaxNetworks) {
        m_store->remove(idx.first().toString());
        idx.removeFirst();
    }
    m_store->write(QLatin1String(kScanCacheIndexKey), compactArray(idx));
    emitLog(QStringLiteral("action persist_results rows=%1").arg(c.rows.size()));
}

void TribeScanner::notifyNetwork()
{
    const ScanNetwork n = buildNetwork();
    if (n == m_lastNet)
        return;
    m_lastNet = n;
    emitLog(QStringLiteral("network kind=%1 sources=%2").arg(QLatin1String(scanNetKindName(n.kind))).arg(n.sources.size()));
    const ScanPhase before = m_m.phase();
    dispatch(m_m.networkChanged(n, cachedFor(n), m_engine->appInFront(), now()));
    // «Сеть сменилась — проверяем заново» (artboard): a scan the change restarted or a finished result it rescans
    // (the machine does both by itself, ScanMachine.h::scanRescanOnNetworkChange), or results that the change
    // turned into the new network's cache (NoScan network_changed). A scan still preparing just retargets: silent.
    const bool restarted = (before == ScanPhase::Reach || before == ScanPhase::Data || before == ScanPhase::Self
                            || before == ScanPhase::Done || before == ScanPhase::Empty || before == ScanPhase::NoScan)
                           && scanPhaseScanning(m_m.phase());
    const bool resultsVoided = m_m.phase() == ScanPhase::NoScan && m_m.view(now()).empty.reason == QLatin1String("network_changed");
    if (m_m.screenOpen() && (restarted || resultsVoided)) {
        ShadeRequest r;
        r.tone = ShadeTone::Info;
        r.textKey = QStringLiteral("network_changed");
        doShade(r);
    }
}

// The host's element of the strict tuple (plan §2.11a). It joins the tuple only at open(), from
// IScanHost::generation() (the host's own answer outside a scan). Once in, any change of it (generation() or
// scan_progress.gen) or its disappearance is a network change. A host that reports its element only inside
// scan_progress never joins: inside that scan the machine's own guard (the opening attempt's gen against
// every later gen, noteAttempts / scanExclusionWhy) already voids access and exclusion on a change; folding
// it later would turn every reopen inside the cooldown into a new scan (S6).
// Only ever forward: host replies come in any order (IScanHost), so an element older than the joined one (a lower
// counter of the same monitor start, or a monitor start the tuple already left) is a late reply's past, never a
// change - folding it would move the tuple back and cancel the scan running on the newer path.
void TribeScanner::foldHostGen(const ScanNetSource &g, bool fromProgress)
{
    Q_UNUSED(fromProgress);
    if (!m_hostGenFolded || g == m_hostGen)
        return;
    if (hostGenStale(g)) {
        emitLog(QStringLiteral("host gen older than the tuple's: ignored"));
        return;
    }
    setHostGen(g);
    notifyNetwork();
}

// ScanNetworkGeneration.h: a monitor's counter only grows within one start (source + epoch), and the epoch is random
// per start - one the tuple moved away from never comes back. So `g` is older than the joined element when it is the
// same start with a lower counter, or a start already left.
bool TribeScanner::hostGenStale(const ScanNetSource &g) const
{
    if (!m_hostGenFolded || g == m_hostGen)
        return false;
    if (g.source == m_hostGen.source && g.epoch == m_hostGen.epoch)
        return g.counter < m_hostGen.counter;
    for (const ScanNetSource &x : m_hostGenLeft)
        if (x.source == g.source && x.epoch == g.epoch)
            return true;
    return false;
}

// The host element becomes `g` (joined at open(), or folded): the monitor start it leaves is remembered (bounded).
void TribeScanner::setHostGen(const ScanNetSource &g)
{
    if (!m_hostGen.source.isEmpty() && (m_hostGen.source != g.source || m_hostGen.epoch != g.epoch)) {
        m_hostGenLeft << m_hostGen;
        while (m_hostGenLeft.size() > 8)
            m_hostGenLeft.removeFirst();
    }
    m_hostGen = g;
}

void TribeScanner::hostAvailabilityChanged()
{
    const ScanHostAvailability av = m_host ? m_host->availability() : ScanHostAvailability::Unavailable;
    emitLog(QStringLiteral("host %1 %2").arg(QLatin1String(scanHostAvailabilityName(av)), m_host ? m_host->unavailableReason() : QString()));
    if (av == ScanHostAvailability::Available) {
        // A manifest held for a connecting host goes on once the caps of the host are in.
        if (!m_held.requestId.isEmpty()) {
            QPointer<TribeScanner> self(this);
            queryCaps([self]() {
                if (self)
                    self->resolveHeld(false);
            });
        } else {
            queryCaps(nullptr);
        }
        hostGenerationChanged();
        driveRecords(); // a host scan the coordinator settles is asked again
        return;
    }
    resolveHeld(false);
    m_capsGenKnown = false;
    // The host went away while its scan ran (the service died, the channel broke): it took the start, so bytes
    // may have moved unreported - the machine freezes (unanswered here) and settles with the whole grant
    // after scan_freeze_ack_ms, bounded.
    const QString sid = m_m.scanId();
    if (m_hostScans.contains(sid) && (m_m.phase() == ScanPhase::Reach || m_m.phase() == ScanPhase::Data))
        dispatch(m_m.hostFailed(sid, hostUnavailableError(), now()));
    if (m_hostGenFolded) { // the source vanished
        m_hostGenFolded = false;
        notifyNetwork();
    }
}

bool TribeScanner::hostGenerationNow(ScanNetSource &out) const
{
    if (!m_host || m_host->availability() != ScanHostAvailability::Available)
        return false;
    if (m_host->generation(out))
        return true;
    if (m_capsGenKnown) { // outside a scan the iOS extension reports its element in the scan_caps reply
        out = m_capsGen;
        return true;
    }
    return false;
}

void TribeScanner::hostGenerationChanged()
{
    ScanNetSource g;
    if (hostGenerationNow(g))
        foldHostGen(g, false);
    else if (m_hostGenFolded) {
        m_hostGenFolded = false; // the source vanished
        notifyNetwork();
    }
}

void TribeScanner::queryCaps(std::function<void()> then)
{
    if (then)
        m_capsWaiters << then;
    if (!m_host || m_host->availability() != ScanHostAvailability::Available) {
        const QList<std::function<void()>> w = m_capsWaiters;
        m_capsWaiters.clear();
        for (const auto &f : w)
            f();
        return;
    }
    if (m_capsInFlight)
        return;
    m_capsInFlight = true;
    QPointer<TribeScanner> self(this);
    sendHost(scanCompact(scanEncodeCaps()), [self](const QByteArray &reply) {
        if (!self)
            return;
        self->m_capsInFlight = false;
        const ScanHostReply r = scanDecodeReply(reply);
        if (r.kind == ScanHostReplyKind::Caps) {
            // The host withholds AmneziaWG probes for this scan (the desktop service: the live peer is unknown):
            // the AWG rows are still planned and end «Не проверено» awg_live_peer_unknown, never sent.
            const QJsonValue w = QJsonDocument::fromJson(reply).object().value(QLatin1String(kScanCapsAwgWithheldField));
            self->m_awgWithheld = (w.isBool() && w.toBool()) || (w.isString() && !w.toString().isEmpty());
            self->m_awgWithheldReason = w.isString() && !w.toString().isEmpty() ? scanReasonKey(w.toString())
                                                                                : QStringLiteral("awg_live_peer_unknown");
            ScanHostCaps caps = r.caps;
            if (self->m_awgWithheld && self->m_host)
                caps.maxAwgConcurrent = qMax(caps.maxAwgConcurrent, self->m_host->knownCaps().maxAwgConcurrent);
            // The host's path element outside a scan rides in the caps reply ("gen", iOS extension). A late caps
            // answer may carry an element older than the joined one: foldHostGen never moves the tuple back.
            const QJsonValue g = QJsonDocument::fromJson(reply).object().value(QLatin1String("gen"));
            ScanNetSource gs;
            if (!g.isUndefined() && !g.isNull() && scanNetSourceFromJson(g, gs)) {
                self->m_capsGenKnown = true;
                self->m_capsGen = gs;
                self->foldHostGen(gs, false); // a change of a joined element; a new one joins at open()
            }
            self->m_m.setCaps(caps); // the machine is built from the host's own answer
            self->emitLog(QStringLiteral("host caps full=%1 legs=%2 awg=%3 needs_vpn=%4")
                              .arg(r.caps.maxFullConcurrent)
                              .arg(r.caps.maxLegConcurrent)
                              .arg(r.caps.maxAwgConcurrent)
                              .arg(r.caps.needsVpn));
        } else {
            self->emitLog(QStringLiteral("host caps error=%1").arg(reply.isEmpty() ? QStringLiteral("no_answer") : QLatin1String(scanHostErrorName(r.error))));
        }
        const QList<std::function<void()>> w = self->m_capsWaiters;
        self->m_capsWaiters.clear();
        for (const auto &f : w)
            f();
    });
}

void TribeScanner::sendHost(const QByteArray &request, IScanHost::ReplyFn reply)
{
    if (!m_host) {
        QTimer::singleShot(0, this, [reply]() {
            if (reply)
                reply(QByteArray());
        });
        return;
    }
    m_host->sendMessage(request, std::move(reply));
}

ScanHostError TribeScanner::hostUnavailableError() const
{
    if (m_host && m_host->availability() == ScanHostAvailability::NeedsVpn)
        return ScanHostError::NoVpn;
    return ScanHostError::Internal;
}

// --- manifest ------------------------------------------------------------------------------------------------------

void TribeScanner::doRequestManifest(const ScanAction &a)
{
    emitLog(QStringLiteral("action request_manifest cost=%1").arg(a.costBytes));
    m_manifestReqId = a.requestId;
    PendingManifest pm;
    pm.requestId = a.requestId;
    m_manifests.insert(a.requestId, pm);
    const QString id = a.requestId;
    QPointer<TribeScanner> self(this);
    m_api->fetchManifest(a.networkKey, a.costBytes, now(), [self, id](const ScanApiClient::Manifest &r) {
        if (!self)
            return;
        auto it = self->m_manifests.find(id);
        if (it == self->m_manifests.end())
            return;
        it->result = r;
        it->manifestDone = true;
        self->manifestComplete(id);
    });
    // The host's caps of this scan (iOS reports the composite capability per scan): asked beside the manifest.
    queryCaps([self, id]() {
        if (!self)
            return;
        auto it = self->m_manifests.find(id);
        if (it == self->m_manifests.end())
            return;
        it->capsDone = true;
        self->manifestComplete(id);
    });
}

void TribeScanner::manifestComplete(const QString &id)
{
    auto it = m_manifests.find(id);
    if (it == m_manifests.end() || !it->manifestDone || !it->capsDone)
        return;
    const ScanApiClient::Manifest r = it->result;
    m_manifests.erase(it);
    if (id != m_manifestReqId || !r.ok) {
        deliverManifest(id, r, QStringList());
        return;
    }
    // probe.base_ips (contract): IP literals of the probe base's host, so the host dials the API without DNS.
    // The engine's known addresses first; else one bounded resolution per scan (scan_stage1_timeout_ms);
    // empty is valid (the host resolves it itself).
    const QString host = QUrl(r.tunnelApiBase).host();
    QStringList ips = scanIsIpLiteral(host) ? QStringList{host} : scanBaseIpsOf(m_engine->knownHostIps(host));
    if (!ips.isEmpty() || host.isEmpty() || !m_resolver) {
        continueManifest(id, r, ips);
        return;
    }
    m_resolving.requestId = id;
    m_resolving.result = r;
    m_resolving.serial = ++m_resolveSerial;
    m_resolveUntil = now() + m_m.tunables().stage1TimeoutMs;
    const quint64 serial = m_resolving.serial;
    QPointer<TribeScanner> self(this);
    m_resolver->lookup(host, [self, serial](const QStringList &found) {
        if (self && self->m_resolving.serial == serial && !self->m_resolving.requestId.isEmpty())
            self->finishResolve(found);
    });
    reschedule();
}

void TribeScanner::finishResolve(const QStringList &ips)
{
    if (m_resolving.requestId.isEmpty())
        return;
    const Resolving r = m_resolving;
    m_resolving = Resolving();
    m_resolveUntil = -1;
    emitLog(QStringLiteral("probe base addresses=%1").arg(scanBaseIpsOf(ips).size()));
    continueManifest(r.requestId, r.result, scanBaseIpsOf(ips));
}

void TribeScanner::continueManifest(const QString &id, const ScanApiClient::Manifest &r, const QStringList &baseIps)
{
    if (id == m_manifestReqId && r.ok && m_host && m_host->availability() == ScanHostAvailability::Unavailable
        && m_host->unavailableReason() == QLatin1String("connecting")) {
        // The desktop service is still being reached (the first seconds after the app started): the scan waits
        // in Preparing for onAvailabilityChanged, at most scan_stop_ms (the scan's own bound; no deadline runs yet).
        emitLog(QStringLiteral("manifest held: host connecting"));
        m_held = PendingManifest{id, true, true, r};
        m_heldIps = baseIps;
        m_heldUntil = now() + m_m.tunables().stopMs;
        reschedule();
        return;
    }
    deliverManifest(id, r, baseIps);
}

// The NoScan reason of a host that cannot take a scan at all (no start is ever sent to it). One vocabulary
// with the screen: service_off («Служба Tribe VPN не запущена»; also "connecting" that never came and any
// unknown code), service_old / service_mismatch (the app and the installed service differ: update the
// service; connecting still works).
static QString scanUnavailableNoScanReason(const QString &hostReason)
{
    if (hostReason == QLatin1String("service_old") || hostReason == QLatin1String("service_mismatch"))
        return hostReason;
    return QStringLiteral("service_off");
}

void TribeScanner::deliverManifest(const QString &id, const ScanApiClient::Manifest &r, const QStringList &baseIps)
{
    const qint64 t = now();
    if (id != m_manifestReqId) {
        // Abandoned (a network change asked again): only its real bytes go back to its reservation.
        emitLog(QStringLiteral("manifest abandoned bytes=%1").arg(r.bytes));
        dispatch(m_m.appRequestDone(id, r.bytes, t));
        return;
    }
    if (r.ok && m_host && m_host->availability() == ScanHostAvailability::Unavailable) {
        // A desktop host that cannot take the scan: no start is sent; the screen says why.
        const QString reason = scanUnavailableNoScanReason(m_host->unavailableReason());
        emitLog(QStringLiteral("host unavailable: %1").arg(reason));
        dispatch(m_m.manifestUnavailable(reason, t, r.bytes));
    } else if (r.ok) {
        ScanManifestInput in;
        in.manifest = r.view;
        m_engine->fillManifestInput(in);
        in.access = ScanAccess(); // the host's own attempt of THIS scan is the only access evidence (§2.11)
        in.apiBytes = r.bytes;
        in.awgMiniEnabled = scanAwgMiniFlag();
        in.strictUnverifiable = upstreamUnverifiableStrictTuned();
        in.probeBaseIps = baseIps;
        in.awgProbeIpKnown = !baseIps.isEmpty(); // the AWG session dials the API by its IP, never by name
        // The device's tunnel address is the session's source: known when the engine gives one for an AWG node.
        bool anyAwg = false, anyAddress = false;
        for (const ScanOwnNode &n : in.ownNodes) {
            if (n.transport != ScanTransport::Awg)
                continue;
            anyAwg = true;
            ScanAwgNodeInput ai;
            anyAddress = anyAddress || (m_engine->awgProbeInput(n.nodeId, ai) && !ai.address.trimmed().isEmpty());
        }
        in.awgAddressKnown = !anyAwg || anyAddress;
        m_active.requestId = id;
        m_active.token = r.scanToken;
        m_active.tunnelBase = r.tunnelApiBase;
        m_active.directBase = r.directApiBase;
        m_active.body = r.body;
        m_active.baseIps = baseIps;
        m_active.tokenExpiresAtMs = r.tokenExpiresAtMs;
        if (!m_shade.visible() && m_shade.pendingCount() == 0)
            m_shade = ShadeQueue(shadeTimingFrom(r.view.numbers));
        dispatch(m_m.manifestReady(in, t));
    } else {
        if (r.reason == QLatin1String("scanner_off")) {
            // A 404 of the scan endpoints = the server's switch is off: no Scanner for this account now. No
            // more requests until the switches change (refreshSwitches); the engine's switch hides the entries.
            m_serverOff = true;
            emitLog(QStringLiteral("scanner switched off by the server: no requests until the switches change"));
            emit serverSwitchedOff();
        }
        dispatch(m_m.manifestUnavailable(r.reason, t, r.bytes)); // the request's real bytes (never its worst case)
    }
    dispatch(m_m.appRequestDone(id, r.bytes, now())); // idempotent after manifestReady; the real bytes otherwise
}

// A held manifest: delivered when the host answers, or (force: the bound passed) with the host's reason.
void TribeScanner::resolveHeld(bool force)
{
    if (m_held.requestId.isEmpty())
        return;
    const bool connecting = m_host && m_host->availability() == ScanHostAvailability::Unavailable
                            && m_host->unavailableReason() == QLatin1String("connecting");
    if (connecting && !force && m_held.requestId == m_manifestReqId)
        return;
    const PendingManifest h = m_held;
    const QStringList ips = m_heldIps;
    m_held = PendingManifest();
    m_heldIps.clear();
    m_heldUntil = -1;
    deliverManifest(h.requestId, h.result, ips); // still connecting after the bound = service_off
}

// --- the probe host --------------------------------------------------------------------------------------------------

QString TribeScanner::configOf(const ScanCandidate &c) const
{
    if (c.origin == ScanOrigin::Own)
        return m_engine->ownProbeConfig(c);
    if (c.kind == ScanProbeKind::XrayFull) {
        // The probe lease's config (include_config), judged by the connect's own profile rule first
        // (XrayProfileSanitizer.h::upstreamProfileCheck): a profile the connect would refuse is never probed, so it
        // can never show as working (owner's iPhone 16.11, build 140). Refused = empty config = «Не проверено».
        const Lease l = m_leases.value(c.id);
        if (l.config.isEmpty())
            return QString();
        const SanitizedProfile chk = upstreamProfileCheck(l.config.toUtf8(), l.configSha256,
                                                          m_engine->upstreamProtocolTags(c.id));
        if (!chk.ok()) {
            emitLog(QStringLiteral("probe_profile_refused code=profile_%1").arg(chk.code()));
            return QString();
        }
        return l.config;
    }
    return scanProviderLegConfig(m_active.body, c.profileId);
}

// The candidates of a start / add without the AWG sessions the host withholds for this scan (caps field
// kScanCapsAwgWithheldField): those go to `refused` with the field's value as the reason.
ScanAction TribeScanner::withoutWithheldAwg(const ScanAction &a, QList<QPair<QString, QString>> *refused) const
{
    if (!m_awgWithheld)
        return a;
    ScanAction out = a;
    out.candidates.clear();
    for (const ScanCandidate &c : a.candidates) {
        if (c.kind == ScanProbeKind::AwgMini)
            *refused << qMakePair(scanProbeIdOf(c), m_awgWithheldReason);
        else
            out.candidates << c;
    }
    return out;
}

// The AWG session input: the engine's node data (the device's own key and config) + the probe base's host and
// one of its IPs (the session dials the API without DNS) + the echo target the builder takes from the
// candidate. An unknown node gives an empty input: the builder refuses it (awg_no_address).
ScanAwgMiniInput TribeScanner::awgInputOf(const ScanCandidate &c) const
{
    ScanAwgMiniInput in;
    ScanAwgNodeInput n;
    if (!m_engine->awgProbeInput(c.id, n))
        return in;
    in.privateKey = n.privateKey;
    in.address = n.address;
    in.mtu = n.mtu;
    in.peerPublicKey = n.peerPublicKey;
    in.presharedKey = n.presharedKey;
    in.endpoint = n.endpoint;
    in.obfuscation = n.obfuscation;
    in.boundIf = n.boundIf;
    const QUrl base(m_active.tunnelBase);
    in.probeHost = base.host();
    in.probeIp = m_active.baseIps.isEmpty() ? QString() : m_active.baseIps.first();
    in.probePort = base.port(443);
    in.echoTarget = c.awgEchoTarget;
    return in;
}

void TribeScanner::doStartHost(const ScanAction &a)
{
    const qint64 t = now();
    if (!m_host || m_host->availability() != ScanHostAvailability::Available) {
        emitLog(QStringLiteral("action start_host_scan refused host=%1")
                    .arg(QLatin1String(scanHostAvailabilityName(m_host ? m_host->availability() : ScanHostAvailability::Unavailable))));
        // The start never reached a host: nothing was admitted, the scan settles at once (host charge 0).
        dispatch(m_m.hostFailed(a.scanId, hostUnavailableError(), t, /*startAccepted=*/false));
        return;
    }
    HostScan hs;
    hs.token = m_active.token;
    m_hostScans.insert(a.scanId, hs);
    QList<QPair<QString, QString>> refused;
    const ScanAction sa = withoutWithheldAwg(a, &refused);
    const ScanStartRequest req = scanBuildStartRequest(
        sa, m_active.token, m_active.tunnelBase, ScanAccess(), [this](const ScanCandidate &c) { return configOf(c); },
        [this](const ScanCandidate &c) { return awgInputOf(c); }, &refused);
    emitLog(QStringLiteral("action start_host_scan candidates=%1 max_bytes=%2").arg(req.candidates.size()).arg(req.maxBytes));
    HostAsk ask = askNow(a.scanId);
    for (const ScanHostCandidate &c : req.candidates)
        ask.probeIds << c.id;
    HostRecord rec;
    rec.start = ask;
    rec.grant = req.maxBytes;
    rec.cellular = m_lastNet.kind == ScanNetKind::Cellular;
    m_records.insert(a.scanId, rec);
    sendStart(ask, req, HostAttempt::First);
    if (m_nextPollAt < 0)
        m_nextPollAt = t + m_m.tunables().pollMs;
    // A probe whose config could not be built never reached the host: «Не проверено» with the builder's reason.
    for (const auto &x : refused)
        dispatch(m_m.candidateRefused(x.first, x.second, now()));
}

// --- host exchanges: the context of a message is captured when it is SENT (invariant 1) ---------------------------

// The context of a start / add sent now: the scan it is for, the token it carries, the network now.
TribeScanner::HostAsk TribeScanner::askNow(const QString &hostScanId) const
{
    HostAsk a;
    a.hostScanId = hostScanId;
    a.binding = ScanBinding{hostScanId, m_active.token, m_lastNet.generation()};
    a.afterStartReply = !startUnanswered(hostScanId);
    return a;
}

// The context of a freeze / cancel / poll of a host scan: its start's scan binding, and whether its start was
// answered when this message goes out.
TribeScanner::HostAsk TribeScanner::askOf(const QString &hostScanId) const
{
    HostAsk a;
    a.hostScanId = hostScanId;
    const auto it = m_records.constFind(hostScanId);
    if (it != m_records.constEnd()) {
        a.binding = it->start.binding;
        a.afterStartReply = it->state != HostStart::InFlight;
    } else {
        a.binding = ScanBinding{hostScanId, QString(), QString()};
        a.afterStartReply = true;
    }
    return a;
}

// Every host message of a scan goes out here: the handler gets back the context captured now, unchanged (never one
// rebuilt at reply time); a message of a host scan with a settlement record is counted until it is answered.
void TribeScanner::sendFor(const HostAsk &ask, const QByteArray &request, std::function<void(const HostAsk &, const QByteArray &)> handler)
{
    const auto it = m_records.find(ask.hostScanId);
    if (it != m_records.end())
        ++it->pending;
    QPointer<TribeScanner> self(this);
    sendHost(request, [self, ask, handler](const QByteArray &reply) {
        if (!self)
            return;
        const auto r = self->m_records.find(ask.hostScanId);
        if (r != self->m_records.end() && r->pending > 0)
            --r->pending;
        handler(ask, reply);
        self->driveRecords(); // what this answer decided: settle, poll, forget; the timer re-armed
    });
}

// Every machine event a host reply (or a held host message) causes goes through here; `target` = the scan it acts on.
void TribeScanner::hostEvent(const char *what, const QString &target, const ScanStep &step)
{
    if (onHostEvent)
        onHostEvent(what, target);
    dispatch(step);
}

// The scan that sent a message still runs (the same scan, token and network; host probes in Reach / Data).
bool TribeScanner::scanRunning(const ScanBinding &b) const
{
    return bindingCurrent(b) && (m_m.phase() == ScanPhase::Reach || m_m.phase() == ScanPhase::Data) && m_host
           && m_host->availability() == ScanHostAvailability::Available;
}

bool TribeScanner::startUnanswered(const QString &hostScanId) const
{
    const auto it = m_records.constFind(hostScanId);
    return it != m_records.constEnd() && (it->state == HostStart::InFlight || it->state == HostStart::Held);
}

void TribeScanner::sendStart(const HostAsk &ask, const ScanStartRequest &req, HostAttempt attempt)
{
    for (auto it = m_records.begin(); it != m_records.end(); ++it) {
        if (it.key() == ask.hostScanId)
            it->state = HostStart::InFlight; // sent: possibly taken from now on
        else
            it->laterStart = true; // the engine runs one scan: this start may end that one
    }
    QPointer<TribeScanner> self(this);
    sendFor(ask, scanCompact(scanEncodeStart(req)), [self, req, attempt](const HostAsk &a, const QByteArray &reply) {
        self->onStartReply(a, req, attempt, reply);
    });
}

// The one answer to a scan_start (the first, the one without AWG sessions, the "not now" retry).
void TribeScanner::onStartReply(const HostAsk &ask, const ScanStartRequest &req, HostAttempt attempt, const QByteArray &reply)
{
    const QString id = ask.hostScanId;
    const ScanHostReply r = scanDecodeReply(reply);
    auto it = m_records.find(id);
    if (it == m_records.end()) {
        // Forgotten (its bound passed): nothing is charged here any more; a host that took it is told to stop.
        if (r.kind == ScanHostReplyKind::Ack)
            sendRecordCancel(id);
        return;
    }
    if (r.kind == ScanHostReplyKind::Ack || reply.isEmpty()) {
        if (reply.isEmpty()) {
            emitLog(QStringLiteral("host start no_answer"));
            if (it->state == HostStart::InFlight) {
                it->state = HostStart::Unanswered; // it may have started: possibly taken until the host says otherwise
                if (it->ours && !it->settled) {    // a cancel and polls now; its final within scan_drain_ms
                    it->deadline = now() + m_m.tunables().drainMs;
                    it->nextPollAt = now() + m_m.tunables().pollMs;
                }
            }
        } else {
            noteTaken(id);
        }
        it = m_records.find(id);
        if (it->ours) {
            // Settled already (its bound passed: the whole grant): the host that took it is told to stop, no charge.
            if (it->settled && r.kind == ScanHostReplyKind::Ack && !it->cancelAcked && !it->cancelInFlight)
                sendRecordCancel(id);
        } else if (r.kind == ScanHostReplyKind::Ack && !m_hostScans.contains(id)) {
            // The machine settled this host scan by its own bounded rule (it no longer tracks it): the host took the
            // start after all - told to stop; nothing is charged here (the machine charged at least its grant).
            sendRecordCancel(id);
        }
        return; // a start the machine tracks: its polls decide
    }
    // An error: the host refused THIS message - it opened nothing for it.
    if (it->ours) {
        it->state = HostStart::Refused;
        settleRecord(id, HostCharge::NotTaken);
        return;
    }
    it->state = HostStart::Refused;
    const bool running = scanRunning(ask.binding);
    // The iOS extension cannot read the live AmneziaWG peer: it refuses a start WITH awg_mini sessions before its
    // engine. Once (never a loop): the same start without them; they end «Не проверено».
    if (attempt == HostAttempt::First && scanAwgLivePeerUnknown(r) && scanHasAwg(req.candidates) && running) {
        retryStartWithoutAwg(ask, req);
        return;
    }
    if (attempt != HostAttempt::NotNowRetry && scanHostNotNow(r) && running) {
        holdStart(ask, req, r); // a transient "not now": once more, after the tunnel settled
        return;
    }
    m_hostScans.remove(id); // refused: nothing to poll
    if (attempt == HostAttempt::NotNowRetry) {
        finishHeldStart(id, &r); // the second refusal: no third attempt
        return;
    }
    emitLog(QStringLiteral("host start error=%1").arg(QLatin1String(scanHostErrorName(r.error))));
    // The error IS the reply to scan_start: the host never took it (host charge 0, settled at once). Its detail
    // names the cause where it has one (kill_switch_exemption -> host_kill_switch, the core's rule).
    machineStartNotTaken(id, r.error, scanHostFailureDetail(r));
}

void TribeScanner::retryStartWithoutAwg(const HostAsk &ask, const ScanStartRequest &req)
{
    ScanStartRequest again = req;
    again.candidates.clear();
    QStringList dropped;
    for (const ScanHostCandidate &c : req.candidates)
        if (c.kind == ScanProbeKind::AwgMini)
            dropped << c.id;
        else
            again.candidates << c;
    emitLog(QStringLiteral("host start: awg sessions refused (live peer unknown), again without %1").arg(dropped.size()));
    const QString id = ask.hostScanId;
    for (const QString &probe : dropped) {
        const QString target = m_m.scanId();
        hostEvent("candidate_refused", target, m_m.candidateRefused(probe, QStringLiteral("awg_live_peer_unknown"), now()));
    }
    // Those refusals may have ended the scan (its freeze then settled the refused start at zero): no retry then.
    if (!m_hostScans.contains(id) || !scanRunning(ask.binding))
        return;
    HostAsk a = ask;
    a.probeIds.clear();
    for (const ScanHostCandidate &c : again.candidates)
        a.probeIds << c.id;
    sendStart(a, again, HostAttempt::WithoutAwg);
}

void TribeScanner::doAddHost(const ScanAction &a)
{
    if (!m_host || m_host->availability() != ScanHostAvailability::Available)
        return; // the host scan is gone; its candidates end with the machine's deadline
    QList<QPair<QString, QString>> refused;
    const QList<ScanHostCandidate> cands = scanBuildHostCandidates(
        withoutWithheldAwg(a, &refused).candidates, [this](const ScanCandidate &c) { return configOf(c); },
        [this](const ScanCandidate &c) { return awgInputOf(c); }, &refused);
    for (const auto &x : refused)
        dispatch(m_m.candidateRefused(x.first, x.second, now()));
    if (cands.isEmpty())
        return;
    emitLog(QStringLiteral("action add_host_candidates n=%1").arg(cands.size()));
    // The context of this add, captured now (review R1): its scan, its probes and the seats they hold NOW.
    HostAsk ask = askNow(a.scanId);
    for (const ScanHostCandidate &c : cands) {
        ask.probeIds << c.id;
        const QString cand = c.id.section(QLatin1Char('#'), 0, 0);
        const auto l = m_leases.constFind(cand);
        if (l != m_leases.constEnd())
            ask.leases.insert(cand, l->leaseId);
    }
    sendAdd(ask, cands, HostAttempt::First);
}

void TribeScanner::sendAdd(const HostAsk &ask, const QList<ScanHostCandidate> &cands, HostAttempt attempt)
{
    QPointer<TribeScanner> self(this);
    sendFor(ask, scanCompact(scanEncodeAdd(ask.hostScanId, cands)), [self, cands, attempt](const HostAsk &a, const QByteArray &reply) {
        self->onAddReply(a, cands, attempt, reply);
    });
}

void TribeScanner::onAddReply(const HostAsk &ask, const QList<ScanHostCandidate> &cands, HostAttempt attempt, const QByteArray &reply)
{
    const ScanHostReply r = scanDecodeReply(reply);
    if (r.kind == ScanHostReplyKind::Ack || reply.isEmpty()) {
        if (reply.isEmpty())
            emitLog(QStringLiteral("host add error=no_answer"));
        return;
    }
    const bool current = bindingCurrent(ask.binding);
    if (attempt == HostAttempt::First && scanAwgLivePeerUnknown(r) && scanHasAwg(cands)) {
        if (!current)
            return refuseAdd(ask, QStringLiteral("awg_live_peer_unknown")); // an older scan's: its seats only
        // Only this add's AWG sessions go (once); its Xray candidates are sent again.
        QList<ScanHostCandidate> keep;
        HostAsk k = ask;
        k.probeIds.clear();
        const QString target = m_m.scanId();
        for (const ScanHostCandidate &c : cands)
            if (c.kind != ScanProbeKind::AwgMini) {
                keep << c;
                k.probeIds << c.id;
            } else {
                hostEvent("candidate_refused", target, m_m.candidateRefused(c.id, QStringLiteral("awg_live_peer_unknown"), now()));
            }
        if (!keep.isEmpty() && bindingCurrent(ask.binding))
            sendAdd(k, keep, HostAttempt::WithoutAwg);
        return;
    }
    if (scanHostNotNow(r) && attempt != HostAttempt::NotNowRetry && current) {
        holdAdd(ask, cands, r); // once more, after the tunnel settled; again refused -> «Не проверено»
        return;
    }
    if (scanHostNotNow(r) || attempt == HostAttempt::NotNowRetry) {
        refuseAdd(ask, QStringLiteral("host_busy")); // the second refusal, or a "not now" of an older scan
        return;
    }
    emitLog(QStringLiteral("host add error=%1").arg(QLatin1String(scanHostErrorName(r.error))));
}

// An add refused for good. Of the CURRENT scan: its candidates end «Не проверено». Of an older scan (review R1): it never
// touches the current scan's candidates; the seats it carried (the same lease ids as when it was sent) are released
// as that scan's when still held under them, its refusals dropped.
void TribeScanner::refuseAdd(const HostAsk &ask, const QString &reason)
{
    if (!bindingCurrent(ask.binding)) {
        QStringList stale;
        for (auto l = ask.leases.constBegin(); l != ask.leases.constEnd(); ++l)
            if (m_leases.contains(l.key()) && m_leases.value(l.key()).leaseId == l.value()) {
                stale << l.value();
                m_leases.remove(l.key());
            }
        emitLog(QStringLiteral("add of an older scan refused: %1 seats released").arg(stale.size()));
        releaseStaleLeases(stale);
        return;
    }
    const QString target = m_m.scanId();
    for (const QString &probe : ask.probeIds)
        hostEvent("candidate_refused", target, m_m.candidateRefused(probe, reason, now()));
}

// --- a transient "not now" of the host (tunnel_changed / stop_pending = teardown_pending / stale_epoch) -----------
// Nothing about any node and not a host failure: the start (or add) is sent ONCE more, by the coordinator,
// after the tunnel state settled - tunnel_changed on the next vpnState event (at most scan_drain_ms), the others
// after scan_drain_ms. Meanwhile the scan stays where the machine has it (Reach: "checking reachability"); the
// machine's own deadline (scan_stop_ms) is longer than the wait. A second refusal of any kind ends the start
// as a refusal (startAccepted = false: no host charge) with NoScan host_busy; an add's candidates end
// «Не проверено» host_busy. Never a loop: the held entry goes when its retry is sent.
void TribeScanner::holdStart(const HostAsk &ask, const ScanStartRequest &req, const ScanHostReply &r)
{
    const auto it = m_records.find(ask.hostScanId);
    if (it != m_records.end())
        it->state = HostStart::Held; // refused: not taken; a stop now settles it at zero
    HeldRetry h;
    h.ask = ask;
    h.start = req;
    h.isStart = true;
    h.waitVpn = scanHostNotNowWaitsForTunnel(r);
    h.dueAt = now() + m_m.tunables().drainMs;
    m_notNow.insert(ask.hostScanId, h);
    emitLog(QStringLiteral("host start not now (%1): once more %2").arg(r.errorCode, h.waitVpn ? QStringLiteral("after the tunnel settles") : QStringLiteral("after scan_drain_ms")));
    reschedule();
}

void TribeScanner::holdAdd(const HostAsk &ask, const QList<ScanHostCandidate> &cands, const ScanHostReply &r)
{
    HeldRetry h;
    h.ask = ask; // the add's own context (captured when it was sent), never the scan of the moment
    h.add = cands;
    h.isStart = false;
    h.waitVpn = scanHostNotNowWaitsForTunnel(r);
    h.dueAt = now() + m_m.tunables().drainMs;
    m_notNow.insert(ask.hostScanId + QStringLiteral("/add/") + QString::number(++m_notNowSerial), h);
    reschedule();
}

// A held retry's moment came: the tunnel settled (vpnState) or the wait passed. byVpn = a vpnState event.
void TribeScanner::fireNotNow(bool byVpn)
{
    const qint64 t = now();
    const QStringList keys = m_notNow.keys();
    for (const QString &key : keys) {
        const auto it = m_notNow.constFind(key);
        if (it == m_notNow.constEnd())
            continue;
        const bool due = byVpn ? it->waitVpn : t >= it->dueAt;
        if (!due)
            continue;
        const HeldRetry h = it.value();
        m_notNow.remove(key); // one retry per held message: the entry goes when it fires
        // No tunnel event within the wait, or the scan that sent it no longer runs: never sent again.
        const bool give = (h.waitVpn && !byVpn) || !scanRunning(h.ask.binding);
        if (h.isStart) {
            if (give) {
                const auto r = m_records.find(h.ask.hostScanId);
                if (r != m_records.end())
                    r->state = HostStart::Refused;
                m_hostScans.remove(h.ask.hostScanId);
                finishHeldStart(h.ask.hostScanId, nullptr);
                continue;
            }
            emitLog(QStringLiteral("host start: once more"));
            sendStart(h.ask, h.start, HostAttempt::NotNowRetry);
        } else {
            if (give) {
                refuseAdd(h.ask, QStringLiteral("host_busy"));
                continue;
            }
            sendAdd(h.ask, h.add, HostAttempt::NotNowRetry);
        }
    }
    reschedule();
}

// The held start ends as a refusal of the start: settled at once, host charge 0; the screen says host_busy
// (a transient "not now"), or the second refusal's own cause when it named another one.
void TribeScanner::finishHeldStart(const QString &hostScanId, const ScanHostReply *second)
{
    // No second answer (the wait passed, the scan moved on) or another "not now": host_busy; a second refusal
    // with its own cause says that cause.
    const bool notNow = !second || scanHostNotNow(*second);
    const QString detail = notNow ? QStringLiteral("busy") : scanHostFailureDetail(*second);
    const ScanHostError e = notNow ? ScanHostError::Other : second->error;
    emitLog(QStringLiteral("host start refused again: %1").arg(detail));
    machineStartNotTaken(hostScanId, e, detail);
}

// --- exactly-once settlement per host scan id (invariant 2) -------------------------------------------------------

// The machine's host share of a scan is settled at zero (hostFailed, startAccepted = false) ONLY here. A start the host
// cannot have taken (refused, held, never sent) is simply zero. A start that may have been taken (its scan_start
// unanswered) is handed to the coordinator first: from now on settleRecord() charges it once - its final total, else
// the whole grant - and the machine never charges it. (Core addition proposed: a hostSettledOutside(scanId) event
// that settles the machine's share at zero without the "nothing was probed" cooldown rule of a refused start.)
void TribeScanner::machineStartNotTaken(const QString &hostScanId, ScanHostError e, const QString &detail)
{
    const auto it = m_records.find(hostScanId);
    if (it != m_records.end() && !it->ours
        && (it->state == HostStart::InFlight || it->state == HostStart::Unanswered || it->state == HostStart::Accepted)) {
        it->ours = true;
        // Bounded: the start's own answer within scan_stop_ms (the hosts' longest start wait is 6 s), the final
        // total within scan_drain_ms after it; then the whole grant.
        it->deadline = now() + (it->state == HostStart::InFlight ? m_m.tunables().stopMs : m_m.tunables().drainMs);
        if (it->state != HostStart::InFlight)
            it->nextPollAt = now() + m_m.tunables().pollMs;
        m_hostScans.remove(hostScanId);
        emitLog(QStringLiteral("host scan possibly taken: settled by the coordinator"));
    }
    hostEvent("host_failed", hostScanId, m_m.hostFailed(hostScanId, e, now(), /*startAccepted=*/false, detail));
}

// The host answered for this host scan (an ack of its start, a freeze, a cancel, a poll): it took the start.
void TribeScanner::noteTaken(const QString &hostScanId)
{
    const auto it = m_records.find(hostScanId);
    if (it == m_records.end() || it->state == HostStart::Accepted)
        return;
    const bool wasInFlight = it->state == HostStart::InFlight;
    it->state = HostStart::Accepted;
    if (it->ours && !it->settled && wasInFlight) {
        it->deadline = now() + m_m.tunables().drainMs; // its final total within scan_drain_ms, else the whole grant
        it->nextPollAt = now() + m_m.tunables().pollMs;
    }
}

// THE one place a host scan's bytes reach the ledger outside the machine, keyed by host scan id. Only for a record
// the coordinator owns (the machine's draining path charges every other one). Idempotent: a final total adjusts the
// charge UP to it (a second final never adds; an engine repeats the same total), a conservative charge (the whole
// grant) or "never taken" (zero) after any charge changes nothing - nothing ever lowers or duplicates a charge.
void TribeScanner::settleRecord(const QString &hostScanId, HostCharge kind, qint64 bytes)
{
    const auto it = m_records.find(hostScanId);
    if (it == m_records.end() || !it->ours)
        return;
    HostRecord &rec = it.value();
    qint64 target = 0;
    switch (kind) {
    case HostCharge::Final:
        target = qMax<qint64>(0, bytes);
        break;
    case HostCharge::NotTaken:
        target = 0;
        break;
    case HostCharge::Conservative: // the whole grant; without a cap the machine's own rule: the last spent + reserved
        target = rec.grant >= 0 ? rec.grant : qMax<qint64>(0, rec.lastSpent + rec.lastReserved);
        break;
    }
    const bool first = rec.charged < 0;
    if (first || kind == HostCharge::Final) {
        const qint64 add = target - qMax<qint64>(0, rec.charged);
        if (add > 0) {
            chargeOutsideScan(add, rec.cellular);
            if (onHostCharge)
                onHostCharge(hostScanId, add);
        }
        rec.charged = qMax(rec.charged, target);
    }
    if (!rec.settled)
        emitLog(QStringLiteral("host scan settled here: %1 bytes=%2")
                    .arg(QLatin1String(kind == HostCharge::Final ? "final" : kind == HostCharge::NotTaken ? "not_taken" : "whole_grant"))
                    .arg(rec.charged));
    rec.settled = true;
    rec.deadline = -1;
}

// unknown_scan for a host scan the coordinator settles. Proof only for a message sent after its start was answered
// (else it may have overtaken the start): taken before -> its bytes are unknown (the whole grant); never answered ->
// never taken, unless another start went out since (the engine may have replaced it: the whole grant).
void TribeScanner::recordUnknown(const HostAsk &ask)
{
    const auto it = m_records.find(ask.hostScanId);
    if (it == m_records.end() || !it->ours || it->settled || !ask.afterStartReply)
        return;
    if (it->state == HostStart::Accepted || it->laterStart)
        settleRecord(ask.hostScanId, HostCharge::Conservative);
    else
        settleRecord(ask.hostScanId, HostCharge::NotTaken);
}

void TribeScanner::sendRecordCancel(const QString &hostScanId)
{
    const auto it = m_records.find(hostScanId);
    if (it == m_records.end()) { // forgotten: a bare cancel (bounded: one per late acknowledgement)
        sendHost(scanCompact(scanEncodeCancel(hostScanId)), [](const QByteArray &) {});
        return;
    }
    it->cancelInFlight = true;
    if (it->state != HostStart::InFlight)
        it->cancelAfterReply = true;
    QPointer<TribeScanner> self(this);
    sendFor(askOf(hostScanId), scanCompact(scanEncodeCancel(hostScanId)),
            [self](const HostAsk &a, const QByteArray &reply) { self->onRecordCancelReply(a, reply); });
}

void TribeScanner::onRecordCancelReply(const HostAsk &ask, const QByteArray &reply)
{
    const auto it = m_records.find(ask.hostScanId);
    if (it == m_records.end())
        return;
    it->cancelInFlight = false;
    const ScanHostReply r = scanDecodeReply(reply);
    if (r.kind == ScanHostReplyKind::Ack && r.scanId == ask.hostScanId) {
        it->cancelAcked = true;
        noteTaken(ask.hostScanId);
        if (r.finalTotals)
            settleRecord(ask.hostScanId, HostCharge::Final, r.bytesSpent);
        return;
    }
    if (r.kind == ScanHostReplyKind::Error && r.error == ScanHostError::UnknownScan)
        recordUnknown(ask);
    // No answer or another error: the polls go on, bounded by the record's deadline.
}

void TribeScanner::sendRecordPoll(const QString &hostScanId)
{
    const auto it = m_records.find(hostScanId);
    if (it == m_records.end())
        return;
    it->pollInFlight = true;
    it->nextPollAt = now() + m_m.tunables().pollMs;
    QPointer<TribeScanner> self(this);
    sendFor(askOf(hostScanId), scanCompact(scanEncodePoll(hostScanId, it->since)),
            [self](const HostAsk &a, const QByteArray &reply) { self->onRecordPollReply(a, reply); });
}

// A poll of a host scan the coordinator settles: its bytes only - nothing of it reaches the machine.
void TribeScanner::onRecordPollReply(const HostAsk &ask, const QByteArray &reply)
{
    const auto it = m_records.find(ask.hostScanId);
    if (it == m_records.end())
        return;
    it->pollInFlight = false;
    const ScanHostReply r = scanDecodeReply(reply);
    if (r.kind == ScanHostReplyKind::Progress && r.progress.scanId == ask.hostScanId) {
        for (const ScanProbeFacts &f : r.progress.items)
            it->since = qMax(it->since, f.seq);
        it->lastSpent = qMax(it->lastSpent, r.progress.bytesSpent);
        it->lastReserved = qMax<qint64>(0, r.progress.bytesReserved);
        noteTaken(ask.hostScanId);
        if (r.progress.finalTotals)
            settleRecord(ask.hostScanId, HostCharge::Final, r.progress.bytesSpent);
        return;
    }
    if (r.kind == ScanHostReplyKind::Error && r.error == ScanHostError::UnknownScan)
        recordUnknown(ask);
}

// The records' bounded work (every wait wakes the one timer): a record the coordinator settles is cancelled once its
// start was answered and polled every scan_poll_ms until its final total, unknown_scan or its deadline (then the
// whole grant); a record that is done is forgotten once nothing is pending for it, at the latest scan_stop_ms later.
void TribeScanner::driveRecords()
{
    const qint64 t = now();
    const bool hostUp = m_host && m_host->availability() == ScanHostAvailability::Available;
    const QStringList ids = m_records.keys();
    for (const QString &id : ids) {
        auto it = m_records.find(id);
        if (it == m_records.end() || !it->ours || it->settled)
            continue;
        if (it->deadline >= 0 && t >= it->deadline) {
            settleRecord(id, HostCharge::Conservative); // no final total in time: never zero by default
            continue;
        }
        if (it->state == HostStart::InFlight || !hostUp)
            continue; // the start's own answer first (an unknown_scan now could have overtaken it)
        if (!it->cancelAcked && !it->cancelInFlight && !it->cancelAfterReply)
            sendRecordCancel(id);
        it = m_records.find(id);
        if (it != m_records.end() && !it->pollInFlight && t >= it->nextPollAt)
            sendRecordPoll(id);
    }
    for (const QString &id : ids) {
        const auto it = m_records.find(id);
        if (it == m_records.end())
            continue;
        const bool done = it->ours ? it->settled : (!m_hostScans.contains(id) && it->state != HostStart::Held);
        if (done && it->dropAt < 0)
            it->dropAt = t + m_m.tunables().stopMs;
        if ((done && it->pending == 0) || (it->dropAt >= 0 && t >= it->dropAt))
            m_records.erase(it);
    }
    reschedule();
}

void TribeScanner::doFreeze(const ScanAction &a)
{
    emitLog(QStringLiteral("action freeze_host_scan"));
    const QString id = a.scanId;
    const auto it = m_records.find(id);
    if (it != m_records.end() && it->ours)
        return; // the coordinator settles it already
    if (it != m_records.end() && (it->state == HostStart::Held || it->state == HostStart::Refused)) {
        // The machine stops a scan whose start the host did NOT take (refused; held for a "not now", the retry not
        // sent): nothing was admitted - settled at once, no freeze to a host that knows no such scan.
        it->state = HostStart::Refused; // the held retry is never sent now
        m_notNow.remove(id);
        m_hostScans.remove(id);
        machineStartNotTaken(id, ScanHostError::Other, QStringLiteral("busy"));
        return;
    }
    if (it != m_records.end() && it->state == HostStart::InFlight) {
        // Its scan_start is not answered yet (review R2, R3): a freeze could overtake it (unknown_scan) and the host
        // still take it after. The machine's share is settled at zero and the coordinator settles this host scan:
        // a cancel now (a host taking messages in order ends it right after the start) and after the start's
        // answer, polls until its final total - else the whole grant.
        machineStartNotTaken(id, ScanHostError::Other, QString());
        sendRecordCancel(id);
        return;
    }
    if (!m_host || m_host->availability() != ScanHostAvailability::Available)
        return; // no ack: the machine charges the whole grant after scan_freeze_ack_ms
    QPointer<TribeScanner> self(this);
    sendFor(askOf(id), scanCompact(scanEncodeFreeze(id)), [self](const HostAsk &ask, const QByteArray &reply) {
        const QString scanId = ask.hostScanId;
        const ScanHostReply r = scanDecodeReply(reply);
        if (r.kind == ScanHostReplyKind::FreezeAck && r.scanId == scanId) {
            self->noteTaken(scanId);
            self->hostEvent("host_freeze_ack", scanId, self->m_m.hostFreezeAck(scanId, r.bytesSpent, r.bytesReserved, self->now()));
        }
        // unknown_scan or no answer: the machine's bounded rule (no freeze ack: the whole grant after scan_freeze_ack_ms)
    });
}

void TribeScanner::doCancel(const ScanAction &a)
{
    emitLog(QStringLiteral("action stop_host_scan"));
    const auto rec = m_records.constFind(a.scanId);
    if (rec != m_records.constEnd() && rec->ours)
        return; // the coordinator settles it (its own cancel)
    if (!m_host || m_host->availability() != ScanHostAvailability::Available)
        return;
    QPointer<TribeScanner> self(this);
    sendFor(askOf(a.scanId), scanCompact(scanEncodeCancel(a.scanId)), [self](const HostAsk &ask, const QByteArray &reply) {
        const QString scanId = ask.hostScanId;
        const ScanHostReply r = scanDecodeReply(reply);
        if (r.kind == ScanHostReplyKind::Ack && r.scanId == scanId)
            self->noteTaken(scanId);
        if (r.kind == ScanHostReplyKind::Ack && r.scanId == scanId && r.finalTotals) {
            self->m_hostScans.remove(scanId); // the final total came with the ack
            self->hostEvent("host_cancel_ack", scanId, self->m_m.hostCancelAck(scanId, r.bytesSpent, self->now()));
            return;
        }
        if (r.kind == ScanHostReplyKind::Error && r.error == ScanHostError::UnknownScan)
            self->m_hostScans.remove(scanId);
        // Otherwise the final totals come with a poll (the machine keeps draining()).
        if (self->m_nextPollAt < 0 && self->m_hostScans.contains(scanId)) {
            self->m_nextPollAt = self->now() + self->m_m.tunables().pollMs;
            self->reschedule();
        }
    });
}

void TribeScanner::pollHost()
{
    const qint64 t = now();
    bool any = false;
    QStringList drop;
    const bool running = m_m.phase() == ScanPhase::Reach || m_m.phase() == ScanPhase::Data;
    const bool hostUp = m_host && m_host->availability() == ScanHostAvailability::Available;
    QStringList ask;
    for (auto it = m_hostScans.begin(); it != m_hostScans.end(); ++it) {
        if (it->finalSeen) {
            drop << it.key();
            continue;
        }
        // Poll while the host scan runs, and while the machine still waits for any scan's final totals.
        if (!(running && it.key() == m_m.scanId()) && !m_m.draining()) {
            drop << it.key();
            continue;
        }
        any = true;
        if (it->pollInFlight || !hostUp || startUnanswered(it.key()))
            continue; // a host that cannot answer is not asked; a start not answered yet (or held) is not polled
        it->pollInFlight = true;
        ask << it.key();
    }
    for (const QString &k : drop)
        m_hostScans.remove(k);
    m_nextPollAt = any ? t + m_m.tunables().pollMs : -1;
    for (const QString &scanId : ask) {
        QPointer<TribeScanner> self(this);
        sendFor(askOf(scanId), scanCompact(scanEncodePoll(scanId, m_hostScans.value(scanId).since)),
                [self](const HostAsk &a, const QByteArray &reply) { self->onPollReply(a, reply); });
    }
}

void TribeScanner::onPollReply(const HostAsk &ask, const QByteArray &reply)
{
    const QString scanId = ask.hostScanId;
    auto it = m_hostScans.find(scanId);
    if (it == m_hostScans.end())
        return;
    it->pollInFlight = false;
    if (reply.isEmpty()) {
        reschedule(); // no answer this round
        return;
    }
    const ScanHostReply r = scanDecodeReply(reply);
    if (r.kind == ScanHostReplyKind::Progress && r.progress.scanId == scanId) {
        for (const ScanProbeFacts &f : r.progress.items)
            it->since = qMax(it->since, f.seq);
        const QString token = it->token;
        if (r.progress.finalTotals)
            m_hostScans.erase(it);
        noteTaken(scanId);
        deliverProgress(r.progress, ask, token);
        return;
    }
    const bool refusedRound = r.kind == ScanHostReplyKind::Error
                              && (r.errorCode == QLatin1String("rate_limited")
                                  || (r.errorCode == QLatin1String("ipc_refused") && r.detail != QLatin1String("shutting_down")));
    if (refusedRound) {
        // The service's IPC bounds refused this poll (too_large / rate_limited / queue_full): the next round
        // asks again; the machine's own deadline bounds the scan.
        emitLog(QStringLiteral("host poll refused %1 %2").arg(r.errorCode, r.detail.left(16)));
        reschedule();
        return;
    }
    if (r.kind == ScanHostReplyKind::Error) {
        emitLog(QStringLiteral("host poll error=%1").arg(QLatin1String(scanHostErrorName(r.error))));
        m_hostScans.erase(it);
        const bool running = scanId == m_m.scanId() && (m_m.phase() == ScanPhase::Reach || m_m.phase() == ScanPhase::Data);
        if (r.error != ScanHostError::UnknownScan || running)
            hostEvent("host_failed", scanId, m_m.hostFailed(scanId, r.error, now(), true, scanHostFailureDetail(r))); // the host took the start: bounded drain
        else
            afterStep(); // an older scan the host already dropped: the machine's own timeout settles it
        return;
    }
    reschedule();
}

// `ask` = the poll's context captured when it was SENT (its host scan's start binding). Ownership is decided before
// anything is folded: only a progress of the CURRENT scan (its id, token and network generation as when its start
// went out) moves the host element of the tuple. A late answer of an older scan (still polled while draining)
// carries the path of ITS time: folding it would restore an older generation and cancel the newer scan.
void TribeScanner::deliverProgress(ScanHostProgress p, const HostAsk &ask, const QString &startToken)
{
    const bool owned = bindingCurrent(ask.binding) && p.scanId == m_m.scanId() && !m_active.token.isEmpty()
                       && startToken == m_active.token;
    if (p.hasGen && owned)
        foldHostGen(p.gen, true);
    // Access facts only from the host scan of THIS scan, started with THIS scan's token (review F5): a progress
    // of an older host scan still settles its bytes, but its attempts never reach the machine. Read again after
    // the fold: a changed element restarted the scan, and this progress is then an older scan's.
    const bool current = owned && p.scanId == m_m.scanId() && bindingCurrent(ask.binding);
    if (!current) {
        p.access = ScanAccessAttempt();
        p.accessClose = ScanAccessAttempt();
    }
    hostEvent("host_progress", p.scanId, m_m.hostProgress(p, now()));
}

// --- seats -----------------------------------------------------------------------------------------------------------

void TribeScanner::doProbeBatch(const ScanAction &a)
{
    QStringList pids;
    QHash<QString, QString> candOf; // profile id -> candidate id
    for (const ScanCandidate &c : a.candidates) {
        pids << c.profileId;
        candOf.insert(c.profileId, c.id);
    }
    emitLog(QStringLiteral("action request_probe_batch n=%1 include_config=%2 cost=%3").arg(pids.size()).arg(a.includeConfig).arg(a.costBytes));
    const QString reqId = a.requestId;
    const ScanBinding asked = bindingNow();
    QPointer<TribeScanner> self(this);
    m_api->probeBatch(pids, a.includeConfig, a.costBytes, [self, reqId, candOf, asked](const ScanApiClient::Batch &b) {
        if (!self)
            return;
        self->dispatch(self->m_m.appRequestDone(reqId, b.bytes, self->now())); // the bytes were spent either way
        if (!self->bindingCurrent(asked)) {
            // A reply of an older scan or network (review F5): it never touches the current scan's leases or
            // candidates; its grants are real seats at the providers - released at once, the bytes accounted.
            QStringList stale;
            for (const ScanApiClient::BatchItem &it : b.items)
                if (it.granted)
                    stale << it.leaseId;
            self->emitLog(QStringLiteral("stale probe_batch: %1 seats released, refusals dropped").arg(stale.size()));
            self->releaseStaleLeases(stale);
            return;
        }
        // Every lease is known before any grant reaches the machine (a late grant is released at once).
        for (const ScanApiClient::BatchItem &it : b.items)
            if (it.granted && candOf.contains(it.profileId))
                self->m_leases.insert(candOf.value(it.profileId), Lease{it.leaseId, it.config, it.configSha256});
        for (const ScanApiClient::BatchItem &it : b.items) {
            const QString cand = candOf.value(it.profileId);
            if (cand.isEmpty())
                continue;
            if (it.granted)
                self->dispatch(self->m_m.probeLeaseGranted(cand, ScanAccess(), self->now()));
            else
                self->dispatch(self->m_m.probeLeaseRefused(cand, it.code, self->now()));
        }
    });
}

void TribeScanner::doRelease(const ScanAction &a)
{
    QStringList leaseIds;
    for (const QString &id : a.ids) {
        const auto it = m_leases.constFind(id);
        if (it != m_leases.constEnd()) {
            leaseIds << it->leaseId;
            m_leases.remove(id);
        }
    }
    emitLog(QStringLiteral("action release_probe_leases n=%1").arg(leaseIds.size()));
    const QString reqId = a.requestId;
    QPointer<TribeScanner> self(this);
    m_api->releaseLeases(leaseIds, a.costBytes, [self, reqId](qint64 bytes) {
        if (self)
            self->dispatch(self->m_m.appRequestDone(reqId, bytes, self->now()));
    });
}

// --- the rest of the app side ----------------------------------------------------------------------------------

void TribeScanner::doOutcomes(const ScanAction &a)
{
    emitLog(QStringLiteral("action send_outcomes n=%1").arg(a.outcomes.size()));
    const QString reqId = a.requestId;
    QPointer<TribeScanner> self(this);
    m_api->sendOutcomes(a.networkKey, a.outcomes, a.costBytes, [self, reqId](int, qint64 bytes) {
        if (self)
            self->dispatch(self->m_m.appRequestDone(reqId, bytes, self->now()));
    });
}

// POST /v1/scan/candidates (1.14.0): the scope's next batch; the provider rows' stub nodes go into the engine's pool
// before the machine sees the rows (a tap pins them like any node).
void TribeScanner::doCandidates(const ScanAction &a)
{
    const QString scope = a.scopeCountry.isEmpty() ? QStringLiteral("default")
                          : a.scopeCountry == QLatin1String(kScanScopeWhitelist) ? QStringLiteral("whitelist")
                                                                                 : QStringLiteral("country");
    const QString country = scope == QLatin1String("country") ? a.scopeCountry : QString();
    emitLog(QStringLiteral("action request_candidates scope=%1 country=%2 seen=%3 limit=%4")
                .arg(scope, country.isEmpty() ? QStringLiteral("-") : country).arg(a.ids.size()).arg(a.batch));
    const QString id = a.requestId;
    QPointer<TribeScanner> self(this);
    m_api->fetchCandidates(a.networkKey, scope, country, a.ids, a.batch, a.costBytes, [self, id](const ScanApiClient::Candidates &r) {
        if (!self)
            return;
        if (r.ok) {
            // The batch's provider rows carry their projections (the leg configs the probes dial): they join the
            // active scan body the configs are taken from (scanProviderLegConfig), next to the manifest's rows.
            QJsonArray ups = self->m_active.body.value(QLatin1String("upstream")).toArray();
            QSet<QString> have;
            for (const QJsonValue &v : ups)
                have.insert(v.toObject().value(QLatin1String("profile_id")).toString());
            for (const QJsonValue &v : r.body.value(QLatin1String("upstream")).toArray())
                if (!have.contains(v.toObject().value(QLatin1String("profile_id")).toString()))
                    ups << v;
            self->m_active.body.insert(QStringLiteral("upstream"), ups);
            if (!r.view.providerNodes.isEmpty())
                self->m_engine->offerScanNodes(r.view.providerNodes);
            self->dispatch(self->m_m.candidatesReady(id, r.view, r.bytes, self->now()));
        } else {
            const QString reason = r.status == 404 ? QStringLiteral("unsupported") : r.reason; // the manifest answered: 404 = no endpoint
            self->dispatch(self->m_m.candidatesUnavailable(id, reason, r.bytes, self->now()));
        }
    });
}

// GET /v1/scan/pool when the screen opens, at most every 10 minutes (the server allows 60 per hour): the scope menu
// over the whole pool. Its few bytes go into the Scanner's ledger like any request outside a scan.
void TribeScanner::fetchPoolIfStale()
{
    if (!m_fetchPoolOnOpen || m_poolUnsupported || m_serverOff || !m_api || !m_api->configured())
        return;
    const qint64 t = now();
    if (m_poolAt >= 0 && t - m_poolAt < 10 * 60 * 1000)
        return;
    bool cellular = false;
    const qint64 cost = 4 * qint64(m_m.tunables().costApiBytes); // counts only, but the TLS estimate is counted too
    if (!admitOutsideScan(cost, &cellular))
        return;
    m_poolAt = t;
    QPointer<TribeScanner> self(this);
    m_api->fetchPool(cost, [self, cellular](const ScanApiClient::Pool &p) {
        if (!self)
            return;
        self->chargeOutsideScan(p.bytes, cellular);
        if (p.ok)
            self->dispatch(self->m_m.poolReady(p.view, self->now()));
        else if (p.status == 404)
            self->m_poolUnsupported = true;
        else
            self->m_poolAt = -1; // ask again at the next open
    });
}

void TribeScanner::doLiveProbe(const ScanAction &a)
{
    const ScanCurrent c = m_engine->current();
    QString base = m_engine->liveProbeBase(c);
    if (base.isEmpty())
        base = m_active.tunnelBase;
    const QString profileId = a.nodeId.startsWith(QLatin1String("up:")) ? a.nodeId.mid(3) : QString();
    emitLog(QStringLiteral("action probe_live_tunnel bytes=%1").arg(a.bytes));
    const QString nodeId = a.nodeId;
    const QString reqId = a.requestId;
    const ScanBinding asked = bindingNow();
    QPointer<TribeScanner> self(this);
    m_api->liveProbe(base, m_active.token, profileId, a.warmBytes, a.bytes, a.costBytes, m_m.tunables().stage2TotalMs,
                     [self, nodeId, reqId, asked](const ScanProbeFacts &f) {
                         if (!self)
                             return;
                         // Only the scan (and network, and token) that asked may be proven by it (review F1); a
                         // stale result is accounted (its bytes went) and otherwise dropped.
                         if (self->bindingCurrent(asked))
                             self->dispatch(self->m_m.liveProbeResult(nodeId, f, self->now()));
                         else
                             self->emitLog(QStringLiteral("stale live probe dropped"));
                         self->dispatch(self->m_m.appRequestDone(reqId, f.spentBytes > 0 ? f.spentBytes : -1, self->now()));
                     });
}

void TribeScanner::doLight(const ScanAction &a)
{
    emitLog(QStringLiteral("action start_light_checks"));
    m_lightAsked = bindingNow();
    m_lightNode = a.nodeId;
    ++m_lightAskId;
    m_engine->startLightChecksFor(a.nodeId, m_lightAskId);
    // The checks run in the engine and report no byte count: their worst case is their charge, reported at
    // once so the request id never waits for the allowance to close.
    if (!a.requestId.isEmpty())
        dispatch(m_m.appRequestDone(a.requestId, -1, now()));
}

void TribeScanner::doShade(const ShadeRequest &r)
{
    emitLog(QStringLiteral("action show_shade %1 %2").arg(QLatin1String(shadeToneName(r.tone)), r.textKey));
    applyShadeStep(m_shade.enqueue(r, now()));
}

void TribeScanner::applyShadeStep(const ShadeStep &s)
{
    m_shadeWake = s.wakeAtMs;
    QVariantMap m;
    m.insert(QStringLiteral("visible"), m_shade.visible());
    m.insert(QStringLiteral("leaving"), m_shade.leaving());
    m.insert(QStringLiteral("id"), m_shade.visible() ? double(m_shade.visibleId()) : 0.0);
    const ShadeRequest r = m_shade.visibleRequest();
    m.insert(QStringLiteral("tone"), m_shade.visible() ? QString::fromLatin1(shadeToneName(r.tone)) : QString());
    m.insert(QStringLiteral("text_key"), m_shade.visible() ? r.textKey : QString());
    m.insert(QStringLiteral("args"), m_shade.visible() ? r.args : QStringList());
    if (m != m_shadeMap) {
        m_shadeMap = m;
        emit shadeChanged();
    }
    if (!m_dispatching)
        reschedule();
}

// --- QML ---------------------------------------------------------------------------------------------------------------

void TribeScanner::open(bool withCheck)
{
    if (!m_enabled) {
        emitLog(QStringLiteral("open ignored: scanner switch off"));
        return;
    }
    if (m_serverOff) {
        // The last scan endpoint answered 404 (the server's switch): the screen keeps NoScan scanner_off and
        // nothing is requested until the switches change.
        emitLog(QStringLiteral("open: scanner off on the server, nothing requested"));
        afterStep();
        return;
    }
    ScanNetSource g;
    if (!m_hostGenFolded && hostGenerationNow(g)) {
        m_hostGenFolded = true; // the host's element joins the tuple here, before anything is measured
        setHostGen(g);
    }
    ScanOpen o;
    o.network = buildNetwork();
    o.current = m_engine->current();
    o.cached = cachedFor(o.network);
    o.withCheck = withCheck;
    o.connectOnOpen = m_connectOnOpen;
    m_lastNet = o.network;
    emitLog(QStringLiteral("open with_check=%1").arg(withCheck));
    fetchPoolIfStale();
    dispatch(m_m.reportQueueState(m_engine->reportQueueFull(), now()));
    dispatch(m_m.opened(o, now()));
}

void TribeScanner::close() { dispatch(m_m.closed(now())); }
void TribeScanner::stop() { dispatch(m_m.stopTapped(now())); }
void TribeScanner::retry()
{
    if (m_serverOff)
        return; // the server's switch is off: no retry loop of requests
    dispatch(m_m.retryTapped(now()));
}

void TribeScanner::connectAndScan()
{
    if (m_serverOff)
        return;
    dispatch(m_m.connectAndScanTapped(now()));
}
void TribeScanner::gotIt() { dispatch(m_m.gotItTapped(now())); }
void TribeScanner::chooseCountry(const QString &cc) { dispatch(m_m.filterChosen(cc, now())); }
void TribeScanner::findMore(const QString &country)
{
    if (!m_enabled || m_serverOff)
        return;
    emitLog(QStringLiteral("find_more country=%1").arg(country.isEmpty() ? QStringLiteral("-") : country));
    dispatch(m_m.moreTapped(country, now()));
}
void TribeScanner::tapRow(const QString &id) { dispatch(m_m.rowTapped(id, now())); }
void TribeScanner::tapCheck() { dispatch(m_m.checkTapped(now())); }
void TribeScanner::tapReportLink() { dispatch(m_m.reportLinkTapped(now())); }

void TribeScanner::tapShade() { applyShadeStep(m_shade.tapped(now())); }

void TribeScanner::showShade(const QString &tone, const QString &textKey, const QStringList &args, const QString &key)
{
    ShadeRequest r;
    r.tone = shadeToneFrom(tone);
    r.textKey = textKey;
    r.args = args;
    r.key = key;
    doShade(r);
}

// --- engine lane ------------------------------------------------------------------------------------------------------

void TribeScanner::engineStateChanged()
{
    dispatch(m_m.vpnState(m_engine->current(), now()));
    fireNotNow(true); // a start refused with tunnel_changed goes once more now that the tunnel reported its state
}
void TribeScanner::networkChanged() { notifyNetwork(); }
void TribeScanner::appForeground() { dispatch(m_m.appForeground(now())); }
void TribeScanner::lightFact(const ScanLightFact &f)
{
    // The facts of the light checks the machine asked for (StartLightChecks) belong to that scan, network and
    // live node: a late fact after any of them changed is dropped (the new check's facts follow). Facts of the
    // button's full check (the card is Checking) are bound by its report id instead and always delivered.
    const bool checking = m_m.view(now()).card.mode == ScanCardMode::Checking;
    if (!checking && !m_lightAsked.scanId.isEmpty()
        && (!bindingCurrent(m_lightAsked) || m_engine->current().nodeId != m_lightNode)) {
        emitLog(QStringLiteral("stale light fact dropped"));
        return;
    }
    dispatch(m_m.lightFact(f, now()));
}

void TribeScanner::lightFactForReport(const QString &reportId, const ScanLightFact &f)
{
    if (reportId.isEmpty() || reportId != m_checkReportId || !bindingCurrent(m_checkAsked)) {
        emitLog(QStringLiteral("card fact of another check dropped"));
        return;
    }
    dispatch(m_m.lightFact(f, now()));
}

void TribeScanner::lightFactFor(quint64 askId, const ScanLightFact &f)
{
    if (askId != m_lightAskId) {
        emitLog(QStringLiteral("light fact of an older check dropped"));
        return;
    }
    lightFact(f);
}

// The binding of an asynchronous reply to the scan that asked (review F1/F5).
TribeScanner::ScanBinding TribeScanner::bindingNow() const
{
    return ScanBinding{m_m.scanId(), m_active.token, m_lastNet.generation()};
}

bool TribeScanner::bindingCurrent(const ScanBinding &b) const
{
    return b.scanId == m_m.scanId() && b.token == m_active.token && b.generation == m_lastNet.generation();
}

// Seats a stale probe-batch reply granted: released at once (bounded: one request of <= 12 per call), their
// bytes charged outside any scan at what they really cost.
void TribeScanner::releaseStaleLeases(const QStringList &leaseIds)
{
    for (int k = 0; k < leaseIds.size(); k += kScanProbeBatchMax) {
        const QStringList part = leaseIds.mid(k, kScanProbeBatchMax);
        QPointer<TribeScanner> self(this);
        const bool cellular = m_lastNet.kind == ScanNetKind::Cellular;
        m_api->releaseLeases(part, m_m.tunables().costApiBytes, [self, cellular](qint64 bytes) {
            if (self && bytes > 0)
                self->chargeOutsideScan(bytes, cellular);
        });
    }
}
void TribeScanner::reportCheckStarted() { dispatch(m_m.reportCheckStarted(now())); }
void TribeScanner::reportCheckProgress(int step, int total) { dispatch(m_m.reportCheckProgress(step, total, now())); }

void TribeScanner::reportCheckDone(bool sent, const QString &reportId)
{
    dispatch(m_m.reportCheckDone(sent ? ScanReportDelivery::Sent : ScanReportDelivery::Queued, now(), reportId));
}

void TribeScanner::reportCheckRefused(const QString &reportId, const QString &reason)
{
    dispatch(m_m.reportCheckRefused(reportId, reason, now()));
}

// Outside a scan a request is charged at its worst case at once, against the cellular hour (cellular) and
// the device hour of the last manifest - the core's rule for a request after its scan (sendApp "post/").
bool TribeScanner::admitOutsideScan(qint64 cost, bool *cellularOut)
{
    const qint64 t = now();
    const bool cellular = m_lastNet.kind == ScanNetKind::Cellular;
    *cellularOut = cellular;
    const ScanBudgetLedger &l = m_m.ledger();
    if (cellular && l.leftInHour(t, m_m.tunables().budgetCellularBytesPerHour, true) < cost)
        return false;
    const qint64 device = qint64(m_active.body.value(QLatin1String("device_budget")).toObject().value(QLatin1String("bytes_per_hour")).toDouble(0));
    if (device > 0 && l.leftInHour(t, device, false) < cost)
        return false;
    return true;
}

qint64 TribeScanner::raceBytesLeft()
{
    const qint64 t = now();
    const ScanBudgetLedger &l = m_m.ledger();
    qint64 left = -1;
    if (m_lastNet.kind == ScanNetKind::Cellular)
        left = qMax<qint64>(0, l.leftInHour(t, m_m.tunables().budgetCellularBytesPerHour, true));
    const qint64 device = qint64(m_active.body.value(QLatin1String("device_budget")).toObject().value(QLatin1String("bytes_per_hour")).toDouble(0));
    if (device > 0) {
        const qint64 d = qMax<qint64>(0, l.leftInHour(t, device, false));
        left = left < 0 ? d : qMin(left, d);
    }
    return left;
}

void TribeScanner::raceCharge(qint64 bytes)
{
    if (bytes > 0)
        chargeOutsideScan(bytes, m_lastNet.kind == ScanNetKind::Cellular);
}

bool TribeScanner::hostScanRunning() const { return scanPhaseScanning(m_m.phase()) || !m_hostScans.isEmpty(); }

void TribeScanner::chargeOutsideScan(qint64 bytes, bool cellular)
{
    // The machine owns the ledger; its only entry point for an outside charge is the ledger itself: the same
    // entry list plus this charge, given back to the machine and persisted (PersistBudget's key).
    ScanBudgetLedger l = ScanBudgetLedger::fromJson(m_m.ledger().toJson());
    l.add(now(), bytes, cellular);
    l.prune(now());
    m_m.restoreBudget(l.toJson());
    m_store->write(QLatin1String(kScanBudgetStoreKey), compactArray(l.toJson()));
}

void TribeScanner::sampleSpeed(qint64 bytes, int timeoutMs, std::function<void(const ScanSpeedSample &)> done)
{
    const auto fail = [done](const char *why) {
        ScanSpeedSample s;
        s.error = QLatin1String(why);
        QTimer::singleShot(0, [done, s]() {
            if (done)
                done(s);
        });
    };
    const ScanCurrent c = m_engine->current();
    if (!c.working())
        return fail("no_tunnel");
    if (m_speedBusy)
        return fail("busy");
    const ScanTunables &t = m_m.tunables();
    const qint64 size = qBound(qint64(1024), bytes, qint64(4 * 1024 * 1024));
    const qint64 cost = size + kScanTlsOverheadBytes + 2048; // the body, one TLS handshake, the headers
    QString base = m_engine->liveProbeBase(c);
    if (base.isEmpty())
        base = m_active.tunnelBase;
    if (base.isEmpty())
        base = m_api->storedTunnelBase(m_lastNet.key);
    if (base.isEmpty())
        return fail("no_base");
    // This scan's token while valid; else a token fetched for the samples alone (never put into the scan's
    // context: the scan's access facts and live proof stay scoped to the scan's own token, F5).
    const bool scanTokenOk = !m_active.token.isEmpty() && m_active.tokenExpiresAtMs > now() + 60000;
    const bool speedTokenOk = !m_speedToken.isEmpty() && m_speedTokenExpiresAtMs > now() + 60000;
    const bool tokenOk = scanTokenOk || speedTokenOk;
    const QString token = scanTokenOk ? m_active.token : m_speedToken;
    bool cellular = false;
    if (!admitOutsideScan(cost + (tokenOk ? 0 : qint64(t.costApiBytes)), &cellular))
        return fail("budget");
    m_speedBusy = true;
    const QString profileId = c.nodeId.startsWith(QLatin1String("up:")) ? c.nodeId.mid(3) : QString();
    QPointer<TribeScanner> self(this);
    auto run = [self, base, profileId, size, cost, cellular, timeoutMs, done](const QString &token) {
        if (!self)
            return;
        self->chargeOutsideScan(cost, cellular);
        self->m_api->speedProbe(base, token, profileId, size, timeoutMs, [self, done, cost, cellular](const ScanApiClient::SpeedFacts &f) {
            if (self) {
                self->m_speedBusy = false;
                const qint64 real = f.wireBytes + kScanTlsOverheadBytes;
                if (real > cost)
                    self->chargeOutsideScan(real - cost, cellular); // never below what really came (review F2)
            }
            ScanSpeedSample s;
            s.ok = f.httpStatus == 200;
            s.bytes = f.bytes;
            s.ms = f.ms;
            s.digestOk = f.digestOk;
            if (!s.ok)
                s.error = QStringLiteral("transport");
            if (done)
                done(s);
        });
    };
    if (tokenOk) {
        run(token);
        return;
    }
    chargeOutsideScan(t.costApiBytes, cellular);
    m_api->fetchToken(t.costApiBytes, now(), [self, run, done](const QString &token, qint64 expiresAt, qint64) {
        if (!self)
            return;
        if (token.isEmpty()) {
            self->m_speedBusy = false;
            ScanSpeedSample s;
            s.error = QStringLiteral("no_token");
            if (done)
                done(s);
            return;
        }
        self->m_speedToken = token;
        self->m_speedTokenExpiresAtMs = expiresAt;
        run(token);
    });
}

void TribeScanner::connectFailed(const QString &nodeId) { dispatch(m_m.connectFailed(nodeId, now())); }
void TribeScanner::attemptEnded() { dispatch(m_m.attemptEnded(now())); }
void TribeScanner::connectRefused(const QString &nodeId)
{
    // queued: the engine answers from inside the ConnectRow action of the running dispatch
    QMetaObject::invokeMethod(this, [this, nodeId]() {
        emitLog(QStringLiteral("connect_refused node=%1").arg(nodeId));
        dispatch(m_m.connectRefused(nodeId, now()));
    }, Qt::QueuedConnection);
}
void TribeScanner::reportQueueChanged() { dispatch(m_m.reportQueueState(m_engine->reportQueueFull(), now())); }

void TribeScanner::refreshSwitches()
{
    const bool en = TuningStore::flag(QLatin1String(kScannerFlag), false);
    const bool legacy = TuningStore::flag(QLatin1String(kDoctorLegacyFlag), false);
    const bool coo = scanConnectOnOpenFlag();
    const bool home = TuningStore::flag(QLatin1String(kScannerReturnHomeFlag), false);
    if (en == m_enabled && legacy == m_doctorLegacy && coo == m_connectOnOpen && home == m_returnHome)
        return;
    const bool switchedOff = m_enabled && !en;
    m_serverOff = false; // the switches changed: the server may serve the Scanner again
    m_enabled = en;
    m_doctorLegacy = legacy;
    m_connectOnOpen = coo;
    m_returnHome = home;
    emit switchesChanged();
    if (switchedOff) {
        // The Scanner no longer exists: the screen closes as on «назад» (which cancels only a pending connect
        // this scan started); the host stops what it runs for us.
        dispatch(m_m.closed(now()));
        if (m_host)
            m_host->stopAll();
    }
}

void TribeScanner::noteUpstreamRevision(qint64 revision) { m_api->dropManifestsBelowRevision(revision); }

} // namespace avpn
