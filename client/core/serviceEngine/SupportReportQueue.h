// client/core/serviceEngine/SupportReportQueue.h
// AVPN - Tribe: bounded on-disk queue of support reports (Doctor check, diagnostics). Lane L9 (F12).
//
// The owner's rule: a diagnostics report is ALWAYS delivered to support. Every accepted report stays
// on disk until each of its parts is settled by the server; the queue never drops an accepted report
// to make room. When it is full it refuses NEW reports (EnqueueResult::Full) and the caller applies
// backpressure (no new full check, «Отчёты ждут связи: N. Новая проверка — после отправки»).
//
// Pure: QtCore only, no network, no singletons, no timers, nothing logged. Storage (a directory) and
// the clock are injected; the caller (TribeSupportChat) does the HTTP and settles each part by id.
//
// Model
//  - A report has up to three parts, at most one of each kind, always in this order:
//      Text  -> POST /v1/support/messages {"body": ...}  (<= 4000 code points; 422 above)
//      Log   -> POST /v1/support/attachments text/plain (<= 2 MiB; 413 above)
//      Bench -> POST /v1/bench/report application/json  (<= 256 KiB, the type doctor schema 5 cap; 413)
//    A report and each of its parts have their own UUID. A report leaves the queue only when no part
//    is pending: all acknowledged (Delivered: the file goes) or some refused with a terminal 4xx
//    (Rejected; the other parts are still delivered). The result is kept in a bounded journal.
//  - Rejected store (F4): a rejected report is never deleted for being rejected. Its file, payload
//    intact, moves to <dir>/rejected/ (bound: maxRejected 5 most recent and maxRejectedBytes 16 MiB;
//    beyond it the OLDEST rejected report is removed and the removal journalled "evicted:<reason>";
//    queued reports are never evicted). It is retried ONCE automatically when the context it was
//    rejected in changes (setContext: the app version, or the server's support limits as the chat
//    observes them), and on demand (resendRejected: the user's explicit "send logs"). A retry moves
//    it back with only its rejected parts pending; rejected again, it returns to the store.
//  - Files: <dir>/<report_id>.json, one per report, written with QSaveFile BEFORE enqueue returns
//    Queued and rewritten with QSaveFile on every part state change (payloads base64 + SHA-256);
//    <dir>/rejected/<report_id>.json (same format); <dir>/outcomes.json = the journal of finished
//    reports. Moves between the two directories are renames (atomic on one volume); every step of a
//    move is resolved by load() after a death.
//  - Eviction notices: when a rejected report is evicted, a small notice (its id, creation time, the
//    parts the server refused with their HTTP codes, the parts it had delivered) is journalled in the
//    same atomic write as the eviction, before the file goes. Each notice is appended as one line to
//    the TEXT part of the next report enqueued (a text part is created when the report has none), so
//    support learns the earlier report existed; a notice leaves the journal only when such a text
//    part is acknowledged. At most maxNotices (10), the oldest dropped first; one carrier at a time.
//  - Bounds: maxReports (20) and maxDiskBytes (32 MiB) over report files, blocked files and live
//    reservations. reserve() admits a check before its report exists: it holds one slot and the
//    worst-case file size, so the report the check produces later is never refused for space.
//  - Delivery: one part in flight. Two channels (support thread, bench); within a channel strict
//    oldest-first (report sequence, then part order) so the thread reads in order; a held head blocks
//    only its own channel.
//  - Retry: no HTTP answer -> Network hold, backoff 30 s doubling to 10 min, cleared by networkBack()
//    and foreground(); 5xx/401/403/408/425 -> Server hold, same backoff, cleared by foreground();
//    429 -> Rate hold of one server window (support: 60 s per account, bench: 3600 s per device; both
//    fixed windows), cleared only by time; terminal 4xx -> the part is Rejected.
//  - At least once: the support API has no client message id. Death between the server's accept and
//    the local ack (file rewrite) sends that part again after restart: a duplicate in the thread is
//    possible, a loss is not.
//  - A corrupt file (unparsable, wrong id, bad checksum, missing) is skipped, reported in
//    loadProblems(), removed and journalled as rejected "corrupt:<why>". An unreadable file (open
//    failed, e.g. iOS data protection) and a file of a newer format (after a rollback) are left in
//    place, counted against the bounds and retried on the next load().
#pragma once

#include <QByteArray>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QList>
#include <QMap>
#include <QSaveFile>
#include <QSettings>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QTimeZone>
#include <QUuid>

#include <algorithm>
#include <functional>
#include <optional>
#include <utility>

namespace avpn {
namespace srq {

enum class PartKind { Text = 0, Log = 1, Bench = 2 };
enum class PartState { Pending, Acked, Rejected };
enum class Hold { None, Network, Server, Rate };
// Outcome of one HTTP attempt for one part (see classify()).
enum class Response { Ack, RetryNetwork, RetryServer, RateLimited, Terminal };
enum class EnqueueResult { Queued, Full, TooLarge, Empty, Invalid, IoError };
enum class AckResult { Acked, Finished, UnknownReport, UnknownPart, NotPending };
enum class ReportState { Unknown, Queued, Sending, Delivered, Rejected };

inline QString kindName(PartKind k)
{
    switch (k) {
    case PartKind::Text: return QStringLiteral("text");
    case PartKind::Log: return QStringLiteral("log");
    case PartKind::Bench: return QStringLiteral("bench");
    }
    return QString();
}

inline std::optional<PartKind> kindFromName(const QString &s)
{
    if (s == QLatin1String("text")) return PartKind::Text;
    if (s == QLatin1String("log")) return PartKind::Log;
    if (s == QLatin1String("bench")) return PartKind::Bench;
    return std::nullopt;
}

inline QString stateName(PartState s)
{
    switch (s) {
    case PartState::Pending: return QStringLiteral("pending");
    case PartState::Acked: return QStringLiteral("acked");
    case PartState::Rejected: return QStringLiteral("rejected");
    }
    return QString();
}

inline std::optional<PartState> stateFromName(const QString &s)
{
    if (s == QLatin1String("pending")) return PartState::Pending;
    if (s == QLatin1String("acked")) return PartState::Acked;
    if (s == QLatin1String("rejected")) return PartState::Rejected;
    return std::nullopt;
}

inline QString holdName(Hold h)
{
    switch (h) {
    case Hold::None: return QStringLiteral("none");
    case Hold::Network: return QStringLiteral("network");
    case Hold::Server: return QStringLiteral("server");
    case Hold::Rate: return QStringLiteral("rate");
    }
    return QString();
}

inline std::optional<Hold> holdFromName(const QString &s)
{
    if (s == QLatin1String("none")) return Hold::None;
    if (s == QLatin1String("network")) return Hold::Network;
    if (s == QLatin1String("server")) return Hold::Server;
    if (s == QLatin1String("rate")) return Hold::Rate;
    return std::nullopt;
}

inline QString reportStateName(ReportState s)
{
    switch (s) {
    case ReportState::Unknown: return QStringLiteral("unknown");
    case ReportState::Queued: return QStringLiteral("queued");
    case ReportState::Sending: return QStringLiteral("sending");
    case ReportState::Delivered: return QStringLiteral("delivered");
    case ReportState::Rejected: return QStringLiteral("rejected");
    }
    return QString();
}

inline QString enqueueResultName(EnqueueResult r)
{
    switch (r) {
    case EnqueueResult::Queued: return QStringLiteral("queued");
    case EnqueueResult::Full: return QStringLiteral("full");
    case EnqueueResult::TooLarge: return QStringLiteral("too_large");
    case EnqueueResult::Empty: return QStringLiteral("empty");
    case EnqueueResult::Invalid: return QStringLiteral("invalid");
    case EnqueueResult::IoError: return QStringLiteral("io_error");
    }
    return QString();
}

inline bool isSupportKind(PartKind k) { return k != PartKind::Bench; }

// Bounds and timings. Defaults = the server limits of contract 1.5.0 (see the header comment).
struct Limits {
    int maxReports = 20;
    qint64 maxDiskBytes = qint64(32) * 1024 * 1024;
    int maxTextCodePoints = 4000;                 // SupportMessageIn.body max_length
    qint64 maxLogBytes = qint64(2) * 1024 * 1024; // _ATTACH_LOG_MAX
    qint64 maxBenchBytes = qint64(256) * 1024;    // bench_doctor_report_max_bytes
    qint64 backoffMinMs = qint64(30) * 1000;
    qint64 backoffMaxMs = qint64(10) * 60 * 1000;
    qint64 supportRateHoldMs = qint64(60) * 1000;    // support_msg_per_min, window_s=60
    qint64 benchRateHoldMs = qint64(60) * 60 * 1000; // bench_report_ratelimit_per_hour, window_s=3600
    qint64 reservationTtlMs = qint64(15) * 60 * 1000; // a full check takes minutes, not a quarter hour
    int maxOutcomes = 32;
    int maxRejected = 5;                              // rejected store: the 5 most recent
    qint64 maxRejectedBytes = qint64(16) * 1024 * 1024; // and at most 16 MiB (5 worst-case reports fit)
    int maxNotices = 10;                              // eviction notices kept until delivered
};

inline constexpr int kFormatVersion = 1;
inline constexpr qint64 kHeaderSlackBytes = 4096; // JSON skeleton: ids, numbers, digests (< 1.5 KiB)

inline qint64 base64Len(qint64 n) { return ((n + 2) / 3) * 4; }

inline qint64 maxPartBytes(const Limits &l, PartKind k)
{
    switch (k) {
    case PartKind::Text: return qint64(l.maxTextCodePoints) * 4; // UTF-8: at most 4 bytes per code point
    case PartKind::Log: return l.maxLogBytes;
    case PartKind::Bench: return l.maxBenchBytes;
    }
    return 0;
}

// Largest file one report can occupy: the bound a reservation holds.
inline qint64 worstCaseFileBytes(const Limits &l)
{
    return kHeaderSlackBytes + base64Len(maxPartBytes(l, PartKind::Text))
        + base64Len(maxPartBytes(l, PartKind::Log)) + base64Len(maxPartBytes(l, PartKind::Bench));
}

// HTTP outcome of one attempt. httpStatus 0 = no HTTP answer (offline, DNS, TLS, timeout before
// headers). A 2xx means the server stored the part; a bench 2xx counts only with its receipt (the
// stored report id, ReportDelivery.h reportAcknowledgement).
inline Response classify(PartKind kind, int httpStatus, bool benchReceipt = false)
{
    if (httpStatus >= 200 && httpStatus < 300) {
        if (kind == PartKind::Bench && !benchReceipt)
            return Response::RetryServer;
        return Response::Ack;
    }
    if (httpStatus == 0)
        return Response::RetryNetwork;
    if (httpStatus == 429)
        return Response::RateLimited;
    if (httpStatus == 401 || httpStatus == 403 || httpStatus == 408 || httpStatus == 425)
        return Response::RetryServer; // token heals (bootstrap), timeouts: not a verdict on the report
    if (httpStatus >= 400 && httpStatus < 500)
        return Response::Terminal; // 400/404/405/413/415/422: this part will never be accepted
    return Response::RetryServer; // 5xx and unexpected codes
}

struct PartInput {
    PartKind kind = PartKind::Text;
    QByteArray data;
};

struct PartInfo {
    QString id;
    PartKind kind = PartKind::Text;
    PartState state = PartState::Pending;
    int attempts = 0;
    qint64 nextTryAtMs = 0;
    Hold hold = Hold::None;
    int lastCode = 0;
    qint64 bytes = 0;
    QString sha256;
};

struct Entry {
    QString id;
    qint64 seq = 0;
    qint64 createdAtMs = 0;
    qint64 fileBytes = 0;
    QList<PartInfo> parts; // canonical order: text, log, bench
    QString text;          // payload of the Text part (small; the chat shows it while pending)
    // Rejected store only: when and in which context it was rejected; whether its one automatic
    // retry was used.
    qint64 rejectedAtMs = 0;
    QString epochApp;
    QString epochLimits;
    bool retried = false;
    QString storedAt;         // rejected store: the file's path
    bool requeueMark = false; // the file was marked by a retry move that a death interrupted
    QStringList noticeIds;    // eviction notices appended to this report's text part

    const PartInfo *partOfKind(PartKind k) const
    {
        for (const PartInfo &p : parts)
            if (p.kind == k)
                return &p;
        return nullptr;
    }

    bool hasRejected() const
    {
        for (const PartInfo &p : parts)
            if (p.state == PartState::Rejected)
                return true;
        return false;
    }

    bool hasPending() const
    {
        for (const PartInfo &p : parts)
            if (p.state == PartState::Pending)
                return true;
        return false;
    }
    PartInfo *part(const QString &partId)
    {
        for (PartInfo &p : parts)
            if (p.id == partId)
                return &p;
        return nullptr;
    }
    const PartInfo *part(const QString &partId) const
    {
        for (const PartInfo &p : parts)
            if (p.id == partId)
                return &p;
        return nullptr;
    }
};

// The part to send now; data = exactly the bytes to send (text: UTF-8 of the message body).
struct Due {
    QString reportId;
    QString partId;
    PartKind kind = PartKind::Text;
    QByteArray data;
};

struct EnqueueOutcome {
    EnqueueResult result = EnqueueResult::Invalid;
    QString reportId; // set when Queued
};

struct Outcome {
    QString id;
    ReportState result = ReportState::Unknown; // Delivered or Rejected
    QString reason;                            // "" | "log:413" | "corrupt:checksum" ...
    qint64 atMs = 0;
    QMap<QString, QString> parts; // kind name -> state name
};

// What support must learn about an evicted rejected report (no payload).
struct Notice {
    QString reportId;
    qint64 createdAtMs = 0;
    qint64 evictedAtMs = 0;
    QMap<QString, int> refused; // kind name -> HTTP code
    QStringList delivered;      // kind names the server had acknowledged
};

// Machine wording (tests, logs); the app installs a translated one (setNoticeFormatter).
inline QString defaultNoticeLine(const Notice &n)
{
    QStringList refused;
    for (auto it = n.refused.constBegin(); it != n.refused.constEnd(); ++it)
        refused << QStringLiteral("%1 for its %2").arg(it.value()).arg(it.key());
    return QStringLiteral("An earlier report of %1 UTC could not be delivered: the server answered %2; delivered: %3.")
        .arg(QDateTime::fromMSecsSinceEpoch(n.createdAtMs, QTimeZone::UTC).toString(QStringLiteral("yyyy-MM-dd HH:mm")),
             refused.join(QStringLiteral(", ")),
             n.delivered.isEmpty() ? QStringLiteral("nothing") : n.delivered.join(QStringLiteral(", ")));
}

struct Status {
    ReportState state = ReportState::Unknown;
    QString reason;
    QMap<QString, QString> parts;
    bool kept = false; // Rejected and its payload is in the rejected store (retry / manual resend possible)
};

class SupportReportQueue {
public:
    using Clock = std::function<qint64()>;
    using IdGen = std::function<QString()>;
    // Test hook: returning false at a named step stops the operation there (simulated process death);
    // the test then reopens the queue from disk. Steps: "enqueue_before_commit",
    // "persist_before_commit", "finalize_after_journal", "migrate_before_key_removal",
    // "reject_after_persist", "reject_after_journal", "evict_after_journal", "requeue_after_mark",
    // "requeue_after_journal".
    using CrashHook = std::function<bool(const char *step)>;

    SupportReportQueue(QString dir, Clock clock, Limits limits = Limits(), IdGen ids = IdGen())
        : m_dir(std::move(dir)), m_clock(std::move(clock)), m_limits(limits), m_ids(std::move(ids))
    {
        if (!m_ids)
            m_ids = [] { return QUuid::createUuid().toString(QUuid::WithoutBraces); };
    }

    void setCrashHook(CrashHook hook) { m_crash = std::move(hook); }
    const Limits &limits() const { return m_limits; }
    QString dir() const { return m_dir; }

    // Scans the directory and rebuilds the index. Nothing in flight survives a load.
    void load()
    {
        m_entries.clear();
        m_problems.clear();
        m_blockedCount = 0;
        m_blockedBytes = 0;
        m_inFlightReport.clear();
        m_inFlightPart.clear();
        QDir().mkpath(m_dir);
        loadOutcomes();
        const QDir d(m_dir);
        const QStringList names = d.entryList({QStringLiteral("*.json")}, QDir::Files, QDir::Name);
        QList<std::pair<Entry, QString>> toStore; // rejected reports whose move a death interrupted
        for (const QString &name : names) {
            const QString base = name.left(name.size() - 5);
            if (!isCanonicalUuid(base))
                continue; // not a report file (outcomes.json, foreign files)
            const QString path = d.filePath(name);
            const qint64 size = QFileInfo(path).size();
            QFile f(path);
            if (!f.open(QIODevice::ReadOnly)) {
                ++m_blockedCount;
                m_blockedBytes += size;
                m_problems << QStringLiteral("unreadable:%1").arg(base);
                continue;
            }
            const QByteArray raw = f.readAll();
            f.close();
            Entry e;
            QString why;
            const Parse p = parseEntry(raw, base, &e, &why);
            if (p == Parse::Future) {
                ++m_blockedCount;
                m_blockedBytes += size;
                m_problems << QStringLiteral("future:%1").arg(base);
                continue;
            }
            if (p == Parse::Corrupt) {
                QFile::remove(path);
                m_problems << QStringLiteral("corrupt:%1:%2").arg(base, why);
                recordOutcome(base, ReportState::Rejected, QStringLiteral("corrupt:") + why, {});
                continue;
            }
            e.fileBytes = size;
            const Outcome *o = latestOutcome(base);
            if (o && o->result == ReportState::Delivered) {
                QFile::remove(path); // delivered: died after the journal, before the removal
                continue;
            }
            if ((o && o->result == ReportState::Rejected) || (!e.hasPending() && e.hasRejected())) {
                // Rejected: died between the final rewrite / the journal and the move. Finish the move.
                if (!o)
                    recordOutcome(e);
                toStore.append({e, path});
                continue;
            }
            if (!e.hasPending()) {
                recordOutcome(e);
                QFile::remove(path);
                continue;
            }
            m_entries.append(e);
        }
        loadRejected();
        for (const auto &[e, path] : toStore)
            storeRejected(e, path);
        reconcileNotices();
        sortEntries();
        m_maxSeq = 0;
        for (const Entry &e : m_entries)
            m_maxSeq = std::max(m_maxSeq, e.seq);
    }

    // ── bounds ───────────────────────────────────────────────────────────────────────────────
    int count() const { return int(m_entries.size()); }
    int blockedFiles() const { return m_blockedCount; }
    qint64 diskBytes() const
    {
        qint64 sum = m_blockedBytes;
        for (const Entry &e : m_entries)
            sum += e.fileBytes;
        return sum;
    }
    // Room for one more report of the worst-case size (what a new full check needs).
    bool canAccept() const { return admits(liveReservations(QString()), worstCaseFileBytes(m_limits)); }
    bool full() const { return !canAccept(); }

    // Admits a check before its report exists. "" = full. The token is consumed by enqueue(), freed
    // by release() or expires after reservationTtlMs (a check that never finished).
    QString reserve()
    {
        pruneReservations();
        if (!admits(liveReservations(QString()), worstCaseFileBytes(m_limits)))
            return QString();
        const QString token = QUuid::createUuid().toString(QUuid::WithoutBraces);
        m_reservations.append({token, m_clock() + m_limits.reservationTtlMs});
        return token;
    }
    bool release(const QString &token)
    {
        for (int i = 0; i < m_reservations.size(); ++i) {
            if (m_reservations.at(i).token == token) {
                m_reservations.removeAt(i);
                return true;
            }
        }
        return false;
    }
    int reservations() const { return liveReservations(QString()); }

    EnqueueOutcome enqueue(const QList<PartInput> &parts, const QString &reservation = QString())
    {
        return enqueueImpl(parts, reservation, QString(), /*bypassBound=*/false);
    }

    // The one legacy report of `AvpnSupport/pendingDiag` (a log part). Its id is derived from the
    // content, so a migration repeated after a death before the key removal does not duplicate it.
    // It was accepted by the old code, so it is admitted past the bound.
    EnqueueOutcome migrateLegacy(const QString &legacyDiagText)
    {
        const QByteArray data = legacyDiagText.toUtf8();
        if (data.isEmpty())
            return {EnqueueResult::Empty, QString()};
        const QString id = legacyId(data);
        if (findEntry(id) || m_finalIds.contains(id) || indexOfRejected(id) >= 0)
            return {EnqueueResult::Queued, id};
        return enqueueImpl({PartInput{PartKind::Log, data}}, QString(), id, /*bypassBound=*/true);
    }

    // Moves `AvpnSupport/pendingDiag` into the queue once, then removes the key. An I/O failure keeps
    // the key for the next start; an invalid legacy value is dropped (it could never be sent).
    EnqueueOutcome migrateLegacySetting(QSettings &st)
    {
        const QString key = QStringLiteral("AvpnSupport/pendingDiag");
        if (!st.contains(key))
            return {EnqueueResult::Empty, QString()};
        const EnqueueOutcome out = migrateLegacy(st.value(key).toString());
        if (out.result == EnqueueResult::IoError)
            return out;
        if (m_crash && !m_crash("migrate_before_key_removal"))
            return out;
        st.remove(key);
        st.sync();
        return out;
    }

    // ── rejected store (F4) ──────────────────────────────────────────────────────────────────
    // The context a rejection is stamped with: the app version and a fingerprint of the server's
    // support limits as last observed ("" = not observed yet: never counts as a change).
    void setContext(const QString &appVersion, const QString &limitsKey)
    {
        m_ctxApp = appVersion;
        m_ctxLimits = limitsKey;
    }

    // The one automatic retry: every rejected report whose context changed since its rejection and
    // whose retry is unused goes back into the queue (room permitting; otherwise on a later call).
    int retryRejected()
    {
        int n = 0;
        for (const QString &id : rejectedIds()) {
            const int i = indexOfRejected(id);
            const Entry &e = m_rejected.at(i);
            if (e.retried)
                continue;
            const bool appChanged = !m_ctxApp.isEmpty() && !e.epochApp.isEmpty() && e.epochApp != m_ctxApp;
            const bool limitsChanged =
                !m_ctxLimits.isEmpty() && !e.epochLimits.isEmpty() && e.epochLimits != m_ctxLimits;
            if ((appChanged || limitsChanged) && requeue(i, /*automatic=*/true))
                ++n;
        }
        return n;
    }

    // The user's explicit "send logs": one rejected report (id) or all of them back into the queue,
    // whether or not the automatic retry was used. Returns how many moved (room permitting).
    int resendRejected(const QString &reportId = QString())
    {
        int n = 0;
        for (const QString &id : rejectedIds()) {
            if (!reportId.isEmpty() && id != reportId)
                continue;
            if (requeue(indexOfRejected(id), /*automatic=*/false))
                ++n;
        }
        return n;
    }

    const QList<Entry> &rejected() const { return m_rejected; }
    using NoticeFormatter = std::function<QString(const Notice &)>;
    void setNoticeFormatter(NoticeFormatter f) { m_noticeLine = f ? std::move(f) : NoticeFormatter(defaultNoticeLine); }
    const QList<Notice> &notices() const { return m_notices; }
    qint64 rejectedBytes() const
    {
        qint64 sum = 0;
        for (const Entry &e : m_rejected)
            sum += e.fileBytes;
        return sum;
    }
    QString rejectedDir() const { return QDir(m_dir).filePath(QStringLiteral("rejected")); }
    QString rejectedPathFor(const QString &reportId) const
    {
        return QDir(rejectedDir()).filePath(reportId + QStringLiteral(".json"));
    }

    // ── delivery ─────────────────────────────────────────────────────────────────────────────
    // The next due part, marked in flight; nothing while one is in flight. Settle it with ack() or
    // fail(), or abandon() it when the request ended without an answer worth classifying.
    std::optional<Due> takeNext()
    {
        if (!m_inFlightReport.isEmpty())
            return std::nullopt;
        const qint64 now = m_clock();
        normalizeHolds(now);
        for (int guard = 0; guard <= m_entries.size() + 2; ++guard) {
            int bestEntry = -1;
            int bestPart = -1;
            for (const bool support : {true, false}) {
                int ei = -1;
                int pi = -1;
                channelHead(support, &ei, &pi);
                if (ei < 0 || m_entries.at(ei).parts.at(pi).nextTryAtMs > now)
                    continue;
                if (bestEntry < 0 || ei < bestEntry || (ei == bestEntry && pi < bestPart)) {
                    bestEntry = ei;
                    bestPart = pi;
                }
            }
            if (bestEntry < 0)
                return std::nullopt;
            Entry &e = m_entries[bestEntry];
            PartInfo &p = e.parts[bestPart];
            QByteArray data;
            if (p.kind == PartKind::Text) {
                data = e.text.toUtf8();
            } else {
                const Read r = readPayload(e, p.id, &data);
                if (r == Read::Unreadable) {
                    ++p.attempts;
                    p.hold = Hold::Server;
                    p.nextTryAtMs = now + backoffMs(p.attempts);
                    continue;
                }
                if (r != Read::Ok) {
                    const QString why = r == Read::Missing ? QStringLiteral("missing") : QStringLiteral("payload");
                    m_problems << QStringLiteral("corrupt:%1:%2").arg(e.id, why);
                    QFile::remove(pathFor(e.id));
                    recordOutcome(e.id, ReportState::Rejected, QStringLiteral("corrupt:") + why, partStates(e));
                    m_entries.removeAt(bestEntry);
                    continue;
                }
            }
            m_inFlightReport = e.id;
            m_inFlightPart = p.id;
            return Due{e.id, p.id, p.kind, data};
        }
        return std::nullopt;
    }

    bool inFlight() const { return !m_inFlightReport.isEmpty(); }
    QString inFlightReport() const { return m_inFlightReport; }
    QString inFlightPart() const { return m_inFlightPart; }

    // The in-flight request was cancelled locally: the part stays pending, no hold change.
    void abandon()
    {
        m_inFlightReport.clear();
        m_inFlightPart.clear();
    }

    // The server stored (reportId, partId). Acknowledges exactly that part of exactly that report.
    AckResult ack(const QString &reportId, const QString &partId)
    {
        clearInFlightIf(reportId, partId);
        const int idx = indexOf(reportId);
        if (idx < 0)
            return AckResult::UnknownReport;
        Entry &e = m_entries[idx];
        PartInfo *p = e.part(partId);
        if (!p)
            return AckResult::UnknownPart;
        if (p->state != PartState::Pending)
            return AckResult::NotPending;
        p->state = PartState::Acked;
        p->hold = Hold::None;
        p->nextTryAtMs = 0;
        // The text that carried eviction notices is delivered: support has them now.
        const QStringList delivered = p->kind == PartKind::Text ? e.noticeIds : QStringList();
        if (!e.hasPending()) {
            dropNotices(delivered, /*save=*/false); // saved with the outcome in finalize()
            finalize(idx);
            return AckResult::Finished;
        }
        persist(e);
        if (m_crash && !m_crash("ack_after_persist"))
            return AckResult::Acked;
        dropNotices(delivered, /*save=*/true);
        return AckResult::Acked;
    }

    // A failed attempt for (reportId, partId); `r` from classify(). Ack is forwarded to ack().
    void fail(const QString &reportId, const QString &partId, Response r, int httpStatus)
    {
        if (r == Response::Ack) {
            ack(reportId, partId);
            return;
        }
        clearInFlightIf(reportId, partId);
        const int idx = indexOf(reportId);
        if (idx < 0)
            return;
        Entry &e = m_entries[idx];
        PartInfo *p = e.part(partId);
        if (!p || p->state != PartState::Pending)
            return;
        const qint64 now = m_clock();
        p->lastCode = httpStatus;
        switch (r) {
        case Response::Terminal:
            p->state = PartState::Rejected;
            p->hold = Hold::None;
            p->nextTryAtMs = 0;
            if (!e.hasPending()) {
                finalize(idx);
                return;
            }
            break;
        case Response::RateLimited:
            ++p->attempts;
            p->hold = Hold::Rate;
            p->nextTryAtMs = now + rateHoldMs(p->kind);
            break;
        case Response::RetryNetwork:
            ++p->attempts;
            p->hold = Hold::Network;
            p->nextTryAtMs = now + backoffMs(p->attempts);
            break;
        case Response::RetryServer:
        case Response::Ack:
            ++p->attempts;
            p->hold = Hold::Server;
            p->nextTryAtMs = now + backoffMs(p->attempts);
            break;
        }
        persist(e);
    }

    // A live answer from the backend: parts held for "no network" are due now. Rate holds stay.
    void networkBack()
    {
        for (Entry &e : m_entries)
            for (PartInfo &p : e.parts)
                if (p.state == PartState::Pending && p.hold == Hold::Network) {
                    p.hold = Hold::None;
                    p.nextTryAtMs = 0;
                }
    }

    // The app came to the foreground (the user is looking): network and server holds are due now.
    void foreground()
    {
        for (Entry &e : m_entries)
            for (PartInfo &p : e.parts)
                if (p.state == PartState::Pending && (p.hold == Hold::Network || p.hold == Hold::Server)) {
                    p.hold = Hold::None;
                    p.nextTryAtMs = 0;
                }
    }

    // ── state ────────────────────────────────────────────────────────────────────────────────
    const QList<Entry> &entries() const { return m_entries; }
    const QList<Outcome> &outcomes() const { return m_outcomes; }
    QStringList loadProblems() const { return m_problems; }

    Status status(const QString &reportId) const
    {
        Status s;
        const int idx = indexOf(reportId);
        if (idx >= 0) {
            s.state = m_inFlightReport == reportId ? ReportState::Sending : ReportState::Queued;
            s.parts = partStates(m_entries.at(idx));
            return s;
        }
        const int ri = indexOfRejected(reportId);
        if (ri >= 0) {
            s.state = ReportState::Rejected;
            s.reason = rejectReason(m_rejected.at(ri));
            s.parts = partStates(m_rejected.at(ri));
            s.kept = true;
            return s;
        }
        for (int i = int(m_outcomes.size()) - 1; i >= 0; --i) {
            const Outcome &o = m_outcomes.at(i);
            if (o.id == reportId) {
                s.state = o.result;
                s.reason = o.reason;
                s.parts = o.parts;
                return s;
            }
        }
        return s;
    }

    QString pathFor(const QString &reportId) const { return QDir(m_dir).filePath(reportId + QStringLiteral(".json")); }
    QString outcomesPath() const { return QDir(m_dir).filePath(QStringLiteral("outcomes.json")); }

private:
    enum class Parse { Ok, Corrupt, Future };
    enum class Read { Ok, Unreadable, Missing, Corrupt };
    struct Reservation {
        QString token;
        qint64 expiresAtMs = 0;
    };

    static bool isCanonicalUuid(const QString &s)
    {
        const QUuid u(s);
        return !u.isNull() && u.toString(QUuid::WithoutBraces) == s;
    }

    static QString sha256Hex(const QByteArray &data)
    {
        return QString::fromLatin1(QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex());
    }

    static QString legacyId(const QByteArray &data)
    {
        static const QUuid ns(QStringLiteral("6f1d2a1e-3c7b-4f0e-9a51-2b8c4d7e9f10"));
        return QUuid::createUuidV5(ns, QByteArray("AvpnSupport/pendingDiag:") + data)
            .toString(QUuid::WithoutBraces);
    }

    qint64 backoffMs(int attempts) const
    {
        qint64 d = m_limits.backoffMinMs;
        for (int i = 1; i < attempts && d < m_limits.backoffMaxMs; ++i)
            d *= 2;
        return std::min(d, m_limits.backoffMaxMs);
    }

    qint64 rateHoldMs(PartKind k) const
    {
        return k == PartKind::Bench ? m_limits.benchRateHoldMs : m_limits.supportRateHoldMs;
    }

    qint64 maxHoldMs(const PartInfo &p) const
    {
        return p.hold == Hold::Rate ? rateHoldMs(p.kind) : m_limits.backoffMaxMs;
    }

    // A hold never lasts longer than its own maximum from now: the wall clock may have moved back
    // (manual change, restore) after next_try_at_ms was persisted.
    void normalizeHolds(qint64 now)
    {
        for (Entry &e : m_entries)
            for (PartInfo &p : e.parts)
                if (p.state == PartState::Pending && p.nextTryAtMs > now + maxHoldMs(p))
                    p.nextTryAtMs = now + maxHoldMs(p);
    }

    // Head of a channel = the first pending part of that channel in queue order.
    void channelHead(bool support, int *entryIdx, int *partIdx) const
    {
        for (int i = 0; i < m_entries.size(); ++i) {
            const Entry &e = m_entries.at(i);
            for (int j = 0; j < e.parts.size(); ++j) {
                const PartInfo &p = e.parts.at(j);
                if (p.state == PartState::Pending && isSupportKind(p.kind) == support) {
                    *entryIdx = i;
                    *partIdx = j;
                    return;
                }
            }
        }
    }

    int liveReservations(const QString &exclude) const
    {
        const qint64 now = m_clock();
        int n = 0;
        for (const Reservation &r : m_reservations)
            if (r.expiresAtMs > now && r.token != exclude)
                ++n;
        return n;
    }

    bool hasLiveReservation(const QString &token) const
    {
        if (token.isEmpty())
            return false;
        const qint64 now = m_clock();
        for (const Reservation &r : m_reservations)
            if (r.token == token && r.expiresAtMs > now)
                return true;
        return false;
    }

    void pruneReservations()
    {
        const qint64 now = m_clock();
        m_reservations.erase(std::remove_if(m_reservations.begin(), m_reservations.end(),
                                            [now](const Reservation &r) { return r.expiresAtMs <= now; }),
                             m_reservations.end());
    }

    // Room for one more file of `bytes` next to the files on disk and `otherReservations` slots.
    bool admits(int otherReservations, qint64 bytes) const
    {
        const int liveCount = int(m_entries.size()) + m_blockedCount + otherReservations;
        const qint64 liveBytes = diskBytes() + qint64(otherReservations) * worstCaseFileBytes(m_limits);
        if (liveCount + 1 > m_limits.maxReports)
            return false;
        if (liveBytes + bytes > m_limits.maxDiskBytes)
            return false;
        return true;
    }

    int indexOf(const QString &reportId) const
    {
        for (int i = 0; i < m_entries.size(); ++i)
            if (m_entries.at(i).id == reportId)
                return i;
        return -1;
    }

    const Entry *findEntry(const QString &reportId) const
    {
        const int i = indexOf(reportId);
        return i < 0 ? nullptr : &m_entries.at(i);
    }

    int indexOfRejected(const QString &reportId) const
    {
        for (int i = 0; i < m_rejected.size(); ++i)
            if (m_rejected.at(i).id == reportId)
                return i;
        return -1;
    }

    QStringList rejectedIds() const
    {
        QStringList ids;
        for (const Entry &e : m_rejected)
            ids << e.id;
        return ids;
    }

    const Outcome *latestOutcome(const QString &reportId) const
    {
        for (int i = int(m_outcomes.size()) - 1; i >= 0; --i)
            if (m_outcomes.at(i).id == reportId)
                return &m_outcomes.at(i);
        return nullptr;
    }

    static QString rejectReason(const Entry &e)
    {
        QStringList reasons;
        for (const PartInfo &p : e.parts)
            if (p.state == PartState::Rejected)
                reasons << QStringLiteral("%1:%2").arg(kindName(p.kind)).arg(p.lastCode);
        return reasons.join(QLatin1Char(','));
    }

    void sortEntries()
    {
        std::sort(m_entries.begin(), m_entries.end(), [](const Entry &a, const Entry &b) {
            return a.seq != b.seq ? a.seq < b.seq : a.id < b.id;
        });
    }

    // Oldest rejection first: eviction takes the front.
    void sortRejected()
    {
        std::sort(m_rejected.begin(), m_rejected.end(), [](const Entry &a, const Entry &b) {
            if (a.rejectedAtMs != b.rejectedAtMs)
                return a.rejectedAtMs < b.rejectedAtMs;
            return a.seq != b.seq ? a.seq < b.seq : a.id < b.id;
        });
    }

    static bool moveFile(const QString &from, const QString &to)
    {
        if (QFile::exists(to))
            QFile::remove(to); // a stale copy of the same report: the source is the newer state
        return QFile::rename(from, to);
    }

    // A settled report with a rejected part goes to the rejected store, payload intact.
    void storeRejected(Entry e, const QString &from)
    {
        for (PartInfo &p : e.parts)
            if (p.state == PartState::Pending)
                p.state = PartState::Rejected; // a stale state in the file (the final rewrite failed)
        QDir().mkpath(rejectedDir());
        const QString to = rejectedPathFor(e.id);
        if (moveFile(from, to)) {
            e.storedAt = to;
        } else {
            e.storedAt = from; // stays where it is; the next load() moves it (the journal says rejected)
            m_problems << QStringLiteral("move_failed:%1").arg(e.id);
        }
        e.fileBytes = QFileInfo(e.storedAt).size();
        m_rejected.append(e);
        enforceRejectedBound();
    }

    // Beyond the store's bound the OLDEST rejected report goes; the removal is journalled first.
    void enforceRejectedBound()
    {
        sortRejected();
        qint64 bytes = rejectedBytes();
        while (!m_rejected.isEmpty()
               && (m_rejected.size() > m_limits.maxRejected || bytes > m_limits.maxRejectedBytes)) {
            const Entry old = m_rejected.first();
            if (m_crash && !m_crash("evict_before_journal"))
                return;
            addNotice(old); // written by the same journal save as the eviction below
            recordOutcome(old.id, ReportState::Rejected, QStringLiteral("evicted:") + rejectReason(old),
                          partStates(old));
            if (m_crash && !m_crash("evict_after_journal"))
                return;
            QFile::remove(old.storedAt);
            bytes -= old.fileBytes;
            m_rejected.removeFirst();
        }
    }

    // Moves rejected report i back into the queue with its rejected parts pending. Steps: mark the
    // file (parts pending, "requeue"), drop the rejection from the journal, rename into the queue
    // directory; load() completes a move interrupted after the mark. false = no room / I/O failure.
    bool requeue(int i, bool automatic)
    {
        Entry e = m_rejected.at(i);
        if (indexOf(e.id) >= 0 || !admits(liveReservations(QString()), e.fileBytes))
            return false;
        for (PartInfo &p : e.parts)
            if (p.state == PartState::Rejected) {
                p.state = PartState::Pending;
                p.attempts = 0;
                p.hold = Hold::None;
                p.nextTryAtMs = 0;
            }
        if (automatic)
            e.retried = true;
        if (!persist(e, e.storedAt, /*requeueMark=*/true))
            return false;
        if (m_crash && !m_crash("requeue_after_mark"))
            return false;
        dropOutcome(e.id);
        if (m_crash && !m_crash("requeue_after_journal"))
            return false;
        if (!moveFile(e.storedAt, pathFor(e.id)))
            return false; // the mark stays: the next load() finishes the move
        m_rejected.removeAt(i);
        e.storedAt.clear();
        m_entries.append(e);
        sortEntries();
        persist(m_entries[indexOf(e.id)]); // best effort: clears the mark
        return true;
    }

    void loadRejected()
    {
        m_rejected.clear();
        const QDir rd(rejectedDir());
        const QStringList names = rd.entryList({QStringLiteral("*.json")}, QDir::Files, QDir::Name);
        for (const QString &name : names) {
            const QString base = name.left(name.size() - 5);
            if (!isCanonicalUuid(base))
                continue;
            const QString path = rd.filePath(name);
            QFile rf(path);
            if (!rf.open(QIODevice::ReadOnly)) {
                m_problems << QStringLiteral("unreadable:rejected:%1").arg(base); // left in place
                continue;
            }
            const QByteArray raw = rf.readAll();
            rf.close();
            Entry e;
            QString why;
            const Parse p = parseEntry(raw, base, &e, &why);
            if (p == Parse::Future) {
                m_problems << QStringLiteral("future:rejected:%1").arg(base);
                continue;
            }
            if (p == Parse::Corrupt) {
                QFile::remove(path);
                m_problems << QStringLiteral("corrupt:%1:%2").arg(base, why);
                recordOutcome(base, ReportState::Rejected, QStringLiteral("corrupt:") + why, {});
                continue;
            }
            e.fileBytes = QFileInfo(path).size();
            e.storedAt = path;
            if (indexOf(base) >= 0) {
                QFile::remove(path); // a stale copy of a report that is queued again
                continue;
            }
            const Outcome *o = latestOutcome(base);
            if (o && o->reason.startsWith(QLatin1String("evicted:"))) {
                QFile::remove(path); // evicted: died after the journal, before the removal
                continue;
            }
            if (e.requeueMark) { // died inside a retry move: finish it
                dropOutcome(base);
                if (moveFile(path, pathFor(base))) {
                    e.storedAt.clear();
                    m_entries.append(e);
                    continue;
                }
            }
            for (PartInfo &part : e.parts)
                if (part.state == PartState::Pending && !e.requeueMark)
                    part.state = PartState::Rejected;
            m_rejected.append(e);
        }
        enforceRejectedBound();
    }

    void addNotice(const Entry &e)
    {
        Notice n;
        n.reportId = e.id;
        n.createdAtMs = e.createdAtMs;
        n.evictedAtMs = m_clock();
        for (const PartInfo &p : e.parts) {
            if (p.state == PartState::Acked)
                n.delivered << kindName(p.kind);
            else
                n.refused.insert(kindName(p.kind), p.lastCode);
        }
        for (int i = 0; i < m_notices.size(); ++i)
            if (m_notices.at(i).reportId == e.id)
                m_notices.removeAt(i--);
        m_notices.append(n);
        while (m_notices.size() > m_limits.maxNotices)
            m_notices.removeFirst();
    }

    void dropNotices(const QStringList &ids, bool save)
    {
        if (ids.isEmpty())
            return;
        const qsizetype before = m_notices.size();
        m_notices.erase(std::remove_if(m_notices.begin(), m_notices.end(),
                                       [&](const Notice &n) { return ids.contains(n.reportId); }),
                        m_notices.end());
        if (save && m_notices.size() != before)
            saveOutcomes();
    }

    // A notice is free unless a queued report still waits to deliver the text that carries it.
    QStringList freeNoticeIds() const
    {
        QSet<QString> carried;
        for (const Entry &e : m_entries) {
            const PartInfo *t = e.partOfKind(PartKind::Text);
            if (t && t->state == PartState::Pending)
                for (const QString &id : e.noticeIds)
                    carried.insert(id);
        }
        QStringList free;
        for (const Notice &n : m_notices)
            if (!carried.contains(n.reportId))
                free << n.reportId;
        return free;
    }

    // After a death between a text ack and the journal write: the report files are the truth.
    void reconcileNotices()
    {
        QStringList delivered;
        for (const QList<Entry> *list : {&m_entries, &m_rejected})
            for (const Entry &e : *list) {
                const PartInfo *t = e.partOfKind(PartKind::Text);
                if (t && t->state == PartState::Acked)
                    delivered << e.noticeIds;
            }
        dropNotices(delivered, /*save=*/true);
    }

    void dropOutcome(const QString &reportId)
    {
        const qsizetype before = m_outcomes.size();
        m_outcomes.erase(std::remove_if(m_outcomes.begin(), m_outcomes.end(),
                                        [&](const Outcome &o) { return o.id == reportId; }),
                         m_outcomes.end());
        if (m_outcomes.size() != before) {
            rebuildFinalIds();
            saveOutcomes();
        }
    }

    void clearInFlightIf(const QString &reportId, const QString &partId)
    {
        if (m_inFlightReport == reportId && m_inFlightPart == partId)
            abandon();
    }

    static QMap<QString, QString> partStates(const Entry &e)
    {
        QMap<QString, QString> m;
        for (const PartInfo &p : e.parts)
            m.insert(kindName(p.kind), stateName(p.state));
        return m;
    }

    static QJsonObject partJson(const PartInfo &p)
    {
        QJsonObject o;
        o.insert(QStringLiteral("id"), p.id);
        o.insert(QStringLiteral("kind"), kindName(p.kind));
        o.insert(QStringLiteral("state"), stateName(p.state));
        o.insert(QStringLiteral("attempts"), p.attempts);
        o.insert(QStringLiteral("next_try_at_ms"), double(p.nextTryAtMs));
        o.insert(QStringLiteral("hold"), holdName(p.hold));
        o.insert(QStringLiteral("last_code"), p.lastCode);
        o.insert(QStringLiteral("bytes"), double(p.bytes));
        o.insert(QStringLiteral("sha256"), p.sha256);
        return o;
    }

    EnqueueOutcome enqueueImpl(QList<PartInput> parts, const QString &reservation, const QString &forcedId,
                               bool bypassBound)
    {
        if (parts.isEmpty())
            return {EnqueueResult::Empty, QString()};
        std::stable_sort(parts.begin(), parts.end(),
                         [](const PartInput &a, const PartInput &b) { return int(a.kind) < int(b.kind); });
        for (int i = 1; i < parts.size(); ++i)
            if (parts.at(i).kind == parts.at(i - 1).kind)
                return {EnqueueResult::Invalid, QString()};
        QString text;
        for (const PartInput &in : parts) {
            if (in.data.isEmpty())
                return {EnqueueResult::Empty, QString()};
            if (in.kind == PartKind::Text) {
                text = QString::fromUtf8(in.data);
                if (text.toUtf8() != in.data)
                    return {EnqueueResult::Invalid, QString()};
                if (text.trimmed().isEmpty())
                    return {EnqueueResult::Empty, QString()};
                if (text.toUcs4().size() > m_limits.maxTextCodePoints)
                    return {EnqueueResult::TooLarge, QString()};
            } else if (in.data.size() > maxPartBytes(m_limits, in.kind)) {
                return {EnqueueResult::TooLarge, QString()};
            }
        }

        // Eviction notices ride on the text part (one line each, within the server's text cap; the rest
        // waits for a later report). Not for the legacy migration (its id is derived from its content).
        QStringList noticeIds;
        if (!bypassBound) {
            QString combined = text;
            const QStringList free = freeNoticeIds();
            for (const Notice &n : m_notices) {
                if (!free.contains(n.reportId))
                    continue;
                const QString line = m_noticeLine(n);
                const QString next = combined.isEmpty() ? line
                    : combined + (noticeIds.isEmpty() ? QStringLiteral("\n\n") : QStringLiteral("\n")) + line;
                if (int(next.toUcs4().size()) > m_limits.maxTextCodePoints)
                    break;
                combined = next;
                noticeIds << n.reportId;
            }
            if (!noticeIds.isEmpty()) {
                text = combined;
                if (!parts.isEmpty() && parts.first().kind == PartKind::Text)
                    parts.first().data = combined.toUtf8();
                else
                    parts.prepend(PartInput{PartKind::Text, combined.toUtf8()});
            }
        }

        const qint64 now = m_clock();
        Entry e;
        e.id = forcedId.isEmpty() ? m_ids() : forcedId;
        if (!isCanonicalUuid(e.id) || findEntry(e.id))
            return {EnqueueResult::Invalid, QString()};
        e.seq = std::max(now, m_maxSeq + 1);
        e.createdAtMs = now;
        e.text = text;
        e.noticeIds = noticeIds;
        QJsonArray jparts;
        for (const PartInput &in : parts) {
            PartInfo p;
            p.id = m_ids();
            p.kind = in.kind;
            p.bytes = in.data.size();
            p.sha256 = sha256Hex(in.data);
            if (!isCanonicalUuid(p.id) || p.id == e.id || e.part(p.id))
                return {EnqueueResult::Invalid, QString()};
            QJsonObject o = partJson(p);
            o.insert(QStringLiteral("data"), QString::fromLatin1(in.data.toBase64()));
            jparts.append(o);
            e.parts.append(p);
        }
        QJsonObject root;
        root.insert(QStringLiteral("format"), QStringLiteral("tribe-support-report"));
        root.insert(QStringLiteral("v"), kFormatVersion);
        root.insert(QStringLiteral("id"), e.id);
        root.insert(QStringLiteral("seq"), double(e.seq));
        root.insert(QStringLiteral("created_at_ms"), double(e.createdAtMs));
        root.insert(QStringLiteral("parts"), jparts);
        if (!e.noticeIds.isEmpty())
            root.insert(QStringLiteral("notice_ids"), QJsonArray::fromStringList(e.noticeIds));
        const QByteArray bytes = QJsonDocument(root).toJson(QJsonDocument::Compact);
        if (bytes.size() > worstCaseFileBytes(m_limits))
            return {EnqueueResult::TooLarge, QString()};

        pruneReservations();
        const bool reserved = hasLiveReservation(reservation);
        if (!bypassBound && !admits(liveReservations(reserved ? reservation : QString()), bytes.size()))
            return {EnqueueResult::Full, QString()};

        QDir().mkpath(m_dir);
        QSaveFile f(pathFor(e.id));
        if (!f.open(QIODevice::WriteOnly) || f.write(bytes) != bytes.size()) {
            f.cancelWriting();
            return {EnqueueResult::IoError, QString()};
        }
        if (m_crash && !m_crash("enqueue_before_commit")) {
            f.cancelWriting();
            return {EnqueueResult::IoError, QString()};
        }
        if (!f.commit())
            return {EnqueueResult::IoError, QString()};

        if (reserved)
            release(reservation);
        e.fileBytes = bytes.size();
        m_maxSeq = e.seq;
        m_entries.append(e);
        return {EnqueueResult::Queued, e.id};
    }

    Parse parseEntry(const QByteArray &raw, const QString &expectedId, Entry *out, QString *why) const
    {
        QJsonParseError err{};
        const QJsonDocument doc = QJsonDocument::fromJson(raw, &err);
        if (err.error != QJsonParseError::NoError || !doc.isObject()) {
            *why = QStringLiteral("json");
            return Parse::Corrupt;
        }
        const QJsonObject root = doc.object();
        if (root.value(QStringLiteral("format")).toString() != QLatin1String("tribe-support-report")) {
            *why = QStringLiteral("format");
            return Parse::Corrupt;
        }
        const int v = root.value(QStringLiteral("v")).toInt(0);
        if (v > kFormatVersion)
            return Parse::Future;
        if (v < 1) {
            *why = QStringLiteral("version");
            return Parse::Corrupt;
        }
        Entry e;
        e.id = root.value(QStringLiteral("id")).toString();
        if (e.id != expectedId) {
            *why = QStringLiteral("id");
            return Parse::Corrupt;
        }
        e.seq = qint64(root.value(QStringLiteral("seq")).toDouble(0));
        e.createdAtMs = qint64(root.value(QStringLiteral("created_at_ms")).toDouble(-1));
        e.rejectedAtMs = std::max<qint64>(0, qint64(root.value(QStringLiteral("rejected_at_ms")).toDouble(0)));
        e.epochApp = root.value(QStringLiteral("epoch_app")).toString();
        e.epochLimits = root.value(QStringLiteral("epoch_limits")).toString();
        e.retried = root.value(QStringLiteral("retried")).toBool(false);
        e.requeueMark = root.value(QStringLiteral("requeue")).toBool(false);
        for (const QJsonValue &v : root.value(QStringLiteral("notice_ids")).toArray())
            if (isCanonicalUuid(v.toString()))
                e.noticeIds << v.toString();
        const QJsonArray jparts = root.value(QStringLiteral("parts")).toArray();
        if (e.seq <= 0 || e.createdAtMs < 0 || jparts.isEmpty() || jparts.size() > 3) {
            *why = QStringLiteral("fields");
            return Parse::Corrupt;
        }
        for (const QJsonValue &jv : jparts) {
            const QJsonObject o = jv.toObject();
            PartInfo p;
            p.id = o.value(QStringLiteral("id")).toString();
            const auto kind = kindFromName(o.value(QStringLiteral("kind")).toString());
            const auto state = stateFromName(o.value(QStringLiteral("state")).toString());
            const auto hold = holdFromName(o.value(QStringLiteral("hold")).toString());
            if (!isCanonicalUuid(p.id) || p.id == e.id || e.part(p.id) || !kind || !state || !hold) {
                *why = QStringLiteral("part");
                return Parse::Corrupt;
            }
            for (const PartInfo &q : e.parts)
                if (q.kind == *kind) {
                    *why = QStringLiteral("part");
                    return Parse::Corrupt;
                }
            p.kind = *kind;
            p.state = *state;
            p.hold = *hold;
            p.attempts = std::max(0, o.value(QStringLiteral("attempts")).toInt(0));
            p.nextTryAtMs = std::max<qint64>(0, qint64(o.value(QStringLiteral("next_try_at_ms")).toDouble(0)));
            p.lastCode = o.value(QStringLiteral("last_code")).toInt(0);
            p.bytes = qint64(o.value(QStringLiteral("bytes")).toDouble(-1));
            p.sha256 = o.value(QStringLiteral("sha256")).toString();
            const auto decoded = QByteArray::fromBase64Encoding(
                o.value(QStringLiteral("data")).toString().toLatin1(), QByteArray::AbortOnBase64DecodingErrors);
            if (!decoded || decoded.decoded.isEmpty() || decoded.decoded.size() != p.bytes) {
                *why = QStringLiteral("payload");
                return Parse::Corrupt;
            }
            if (sha256Hex(decoded.decoded) != p.sha256) {
                *why = QStringLiteral("checksum");
                return Parse::Corrupt;
            }
            if (p.kind == PartKind::Text) {
                e.text = QString::fromUtf8(decoded.decoded);
                if (e.text.toUtf8() != decoded.decoded) {
                    *why = QStringLiteral("payload");
                    return Parse::Corrupt;
                }
            }
            e.parts.append(p);
        }
        std::stable_sort(e.parts.begin(), e.parts.end(),
                         [](const PartInfo &a, const PartInfo &b) { return int(a.kind) < int(b.kind); });
        *out = e;
        return Parse::Ok;
    }

    // Reads the file again and returns the verified payload of one part.
    Read readPayload(const Entry &e, const QString &partId, QByteArray *out) const
    {
        const QString path = pathFor(e.id);
        if (!QFile::exists(path))
            return Read::Missing;
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly))
            return Read::Unreadable;
        const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
        const PartInfo *want = e.part(partId);
        if (!want)
            return Read::Corrupt;
        for (const QJsonValue &jv : doc.object().value(QStringLiteral("parts")).toArray()) {
            const QJsonObject o = jv.toObject();
            if (o.value(QStringLiteral("id")).toString() != partId)
                continue;
            const auto decoded = QByteArray::fromBase64Encoding(
                o.value(QStringLiteral("data")).toString().toLatin1(), QByteArray::AbortOnBase64DecodingErrors);
            if (!decoded || sha256Hex(decoded.decoded) != want->sha256)
                return Read::Corrupt;
            *out = decoded.decoded;
            return Read::Ok;
        }
        return Read::Corrupt;
    }

    // Rewrites the report file with the index's part states (payloads unchanged). A failure leaves
    // the previous file: after a death the part is sent again (at least once).
    bool persist(Entry &e, const QString &at = QString(), bool requeueMark = false)
    {
        const QString path = at.isEmpty() ? pathFor(e.id) : at;
        QFile in(path);
        if (!in.open(QIODevice::ReadOnly))
            return false;
        QJsonObject root = QJsonDocument::fromJson(in.readAll()).object();
        in.close();
        QJsonArray jparts = root.value(QStringLiteral("parts")).toArray();
        for (int i = 0; i < jparts.size(); ++i) {
            QJsonObject o = jparts.at(i).toObject();
            const PartInfo *p = e.part(o.value(QStringLiteral("id")).toString());
            if (!p)
                return false;
            const QJsonValue data = o.value(QStringLiteral("data"));
            o = partJson(*p);
            o.insert(QStringLiteral("data"), data);
            jparts[i] = o;
        }
        root.insert(QStringLiteral("parts"), jparts);
        root.insert(QStringLiteral("rejected_at_ms"), double(e.rejectedAtMs));
        root.insert(QStringLiteral("epoch_app"), e.epochApp);
        root.insert(QStringLiteral("epoch_limits"), e.epochLimits);
        root.insert(QStringLiteral("retried"), e.retried);
        root.insert(QStringLiteral("requeue"), requeueMark);
        const QByteArray bytes = QJsonDocument(root).toJson(QJsonDocument::Compact);
        QSaveFile f(path);
        if (!f.open(QIODevice::WriteOnly) || f.write(bytes) != bytes.size()) {
            f.cancelWriting();
            return false;
        }
        if (m_crash && !m_crash("persist_before_commit")) {
            f.cancelWriting();
            return false;
        }
        if (!f.commit())
            return false;
        e.fileBytes = bytes.size();
        return true;
    }

    // Every part settled. Delivered: journal first, then the file goes. Rejected (F4): the final part
    // states are written, the rejection journalled, then the file moves to the rejected store with its
    // payload. A death between any two steps is resolved by load().
    void finalize(int idx)
    {
        if (!m_entries.at(idx).hasRejected()) {
            const Entry e = m_entries.at(idx);
            recordOutcome(e);
            if (m_crash && !m_crash("finalize_after_journal"))
                return;
            QFile::remove(pathFor(e.id));
            m_entries.removeAt(idx);
            return;
        }
        Entry &live = m_entries[idx];
        live.rejectedAtMs = m_clock();
        live.epochApp = m_ctxApp;
        live.epochLimits = m_ctxLimits;
        persist(live); // best effort: every non-acked part in the store counts as rejected anyway
        if (m_crash && !m_crash("reject_after_persist"))
            return;
        const Entry e = live;
        recordOutcome(e);
        if (m_crash && !m_crash("reject_after_journal"))
            return;
        m_entries.removeAt(idx);
        storeRejected(e, pathFor(e.id));
    }

    void recordOutcome(const Entry &e)
    {
        recordOutcome(e.id, e.hasRejected() ? ReportState::Rejected : ReportState::Delivered, rejectReason(e),
                      partStates(e));
    }

    void recordOutcome(const QString &id, ReportState result, const QString &reason,
                       const QMap<QString, QString> &parts)
    {
        Outcome o;
        o.id = id;
        o.result = result;
        o.reason = reason;
        o.atMs = m_clock();
        o.parts = parts;
        m_outcomes.append(o);
        while (m_outcomes.size() > m_limits.maxOutcomes)
            m_outcomes.removeFirst();
        rebuildFinalIds();
        saveOutcomes();
    }

    void rebuildFinalIds()
    {
        m_finalIds.clear();
        for (const Outcome &o : m_outcomes)
            m_finalIds.insert(o.id);
    }

    void saveOutcomes() const
    {
        QJsonArray arr;
        for (const Outcome &o : m_outcomes) {
            QJsonObject j;
            j.insert(QStringLiteral("id"), o.id);
            j.insert(QStringLiteral("result"), reportStateName(o.result));
            j.insert(QStringLiteral("reason"), o.reason);
            j.insert(QStringLiteral("at_ms"), double(o.atMs));
            QJsonObject parts;
            for (auto it = o.parts.constBegin(); it != o.parts.constEnd(); ++it)
                parts.insert(it.key(), it.value());
            j.insert(QStringLiteral("parts"), parts);
            arr.append(j);
        }
        QJsonArray notices;
        for (const Notice &n : m_notices) {
            QJsonObject j;
            j.insert(QStringLiteral("report_id"), n.reportId);
            j.insert(QStringLiteral("created_at_ms"), double(n.createdAtMs));
            j.insert(QStringLiteral("evicted_at_ms"), double(n.evictedAtMs));
            QJsonObject refused;
            for (auto it = n.refused.constBegin(); it != n.refused.constEnd(); ++it)
                refused.insert(it.key(), it.value());
            j.insert(QStringLiteral("refused"), refused);
            j.insert(QStringLiteral("delivered"), QJsonArray::fromStringList(n.delivered));
            notices.append(j);
        }
        QJsonObject root;
        root.insert(QStringLiteral("v"), 1);
        root.insert(QStringLiteral("outcomes"), arr);
        root.insert(QStringLiteral("notices"), notices);
        const QByteArray bytes = QJsonDocument(root).toJson(QJsonDocument::Compact);
        QDir().mkpath(m_dir);
        QSaveFile f(outcomesPath());
        if (f.open(QIODevice::WriteOnly) && f.write(bytes) == bytes.size())
            f.commit();
        else
            f.cancelWriting();
    }

    // The journal is information only: an unreadable or broken journal starts empty.
    void loadOutcomes()
    {
        m_outcomes.clear();
        m_notices.clear();
        QFile f(outcomesPath());
        if (f.open(QIODevice::ReadOnly)) {
            const QJsonObject jroot = QJsonDocument::fromJson(f.readAll()).object();
            for (const QJsonValue &jv : jroot.value(QStringLiteral("notices")).toArray()) {
                const QJsonObject j = jv.toObject();
                Notice n;
                n.reportId = j.value(QStringLiteral("report_id")).toString();
                if (!isCanonicalUuid(n.reportId))
                    continue;
                n.createdAtMs = qint64(j.value(QStringLiteral("created_at_ms")).toDouble(0));
                n.evictedAtMs = qint64(j.value(QStringLiteral("evicted_at_ms")).toDouble(0));
                const QJsonObject refused = j.value(QStringLiteral("refused")).toObject();
                for (auto it = refused.constBegin(); it != refused.constEnd(); ++it)
                    n.refused.insert(it.key(), it.value().toInt());
                for (const QJsonValue &k : j.value(QStringLiteral("delivered")).toArray())
                    n.delivered << k.toString();
                m_notices.append(n);
            }
            while (m_notices.size() > m_limits.maxNotices)
                m_notices.removeFirst();
            const QJsonArray arr = jroot.value(QStringLiteral("outcomes")).toArray();
            for (const QJsonValue &jv : arr) {
                const QJsonObject j = jv.toObject();
                Outcome o;
                o.id = j.value(QStringLiteral("id")).toString();
                const QString r = j.value(QStringLiteral("result")).toString();
                o.result = r == QLatin1String("delivered") ? ReportState::Delivered
                         : r == QLatin1String("rejected")  ? ReportState::Rejected
                                                           : ReportState::Unknown;
                if (o.id.isEmpty() || o.result == ReportState::Unknown)
                    continue;
                o.reason = j.value(QStringLiteral("reason")).toString();
                o.atMs = qint64(j.value(QStringLiteral("at_ms")).toDouble(0));
                const QJsonObject parts = j.value(QStringLiteral("parts")).toObject();
                for (auto it = parts.constBegin(); it != parts.constEnd(); ++it)
                    o.parts.insert(it.key(), it.value().toString());
                m_outcomes.append(o);
            }
        }
        while (m_outcomes.size() > m_limits.maxOutcomes)
            m_outcomes.removeFirst();
        rebuildFinalIds();
    }

    QString m_dir;
    Clock m_clock;
    Limits m_limits;
    IdGen m_ids;
    CrashHook m_crash;
    QList<Entry> m_entries; // sorted by (seq, id)
    QList<Entry> m_rejected; // the rejected store, oldest rejection first
    QString m_ctxApp;
    QString m_ctxLimits;
    QList<Notice> m_notices; // eviction notices not yet delivered, oldest first
    NoticeFormatter m_noticeLine = defaultNoticeLine;
    QList<Outcome> m_outcomes;
    QSet<QString> m_finalIds;
    QList<Reservation> m_reservations;
    QStringList m_problems;
    int m_blockedCount = 0;
    qint64 m_blockedBytes = 0;
    qint64 m_maxSeq = 0;
    QString m_inFlightReport;
    QString m_inFlightPart;
};

} // namespace srq
} // namespace avpn
