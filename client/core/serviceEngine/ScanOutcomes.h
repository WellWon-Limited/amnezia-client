// client/core/serviceEngine/ScanOutcomes.h
// AVPN serviceEngine - the outcome report of a scan or of a scanner-started connect
// (POST /v1/telemetry/path-outcomes, openapi PathOutcomeItem / PathOutcomeBatch). [header-only, QtCore; pure]
//
// Plan scanner-client-plan.md §2.9 and D12. Rules (each one a test in tests/scan_core_check.cpp):
//  - One item per candidate per collection (a scan, or one connect chain started by a tap): the first
//    verdict wins, later ones of the same (kind, id) are dropped.
//  - not_verified is never sent (the server ignores it anyway; it carries no evidence).
//  - Stage: reach (the reach socket failed), data (the data probe judged it), connect (a tap's
//    connect: works = data passed, no_data = the engine gave up on it). `cache` is never sent: a cached
//    row is not a new observation.
//  - The network key is the one of the collection's start; a key that does not match the contract's
//    pattern drops the whole collection (the server would refuse the batch with 422).
//  - Field bounds of the contract are applied (id <= 64 chars, ttfb <= 600000, bytes <= 1 GiB,
//    duration <= 3600000, rtt <= 600000); unknown timings are omitted, never sent as -1.
//  - `probe` (contract 1.5.0) says how the verdict was obtained: tunnel (a connect), full, leg, awg_mini;
//    `rtt_ms` (one full-path round trip: the probe's second-request first byte, the live ms for a connect) is
//    sent for works / slow only.
//  - Batches of at most kScanOutcomesMaxBatch items (SCAN_OUTCOMES_MAX_BATCH default 32).
//  - `evidence` (contract 1.7.0 PathOutcomeItem.evidence, plan §2.8): how the verdict was proven - "exclusion"
//    for a row proven by exclusion, "direct" for every other verdict (by the probe or the connect itself).
//    Sent on every item; the server validates the value and counts an exclusion works like any works.
// Nothing device-identifying goes in: no address, token, config or net token.
//
// Upstream Amnezia has no counterpart.
#pragma once

#include "ScanTypes.h"

#include <QJsonArray>
#include <QJsonObject>
#include <QList>
#include <QRegularExpression>
#include <QSet>
#include <QString>

namespace avpn {

inline constexpr int kScanOutcomesMaxBatch = 32;
// PathOutcomeItem.evidence / DoctorScanRow.evidence: accepted since contract 1.7.0 (deployed).
inline constexpr bool kScanOutcomeEvidenceAccepted = true;

enum class ScanOutcomeStage { Cache, Reach, Data, Connect };

inline const char *scanOutcomeStageName(ScanOutcomeStage s)
{
    switch (s) {
    case ScanOutcomeStage::Cache: return "cache";
    case ScanOutcomeStage::Reach: return "reach";
    case ScanOutcomeStage::Data: return "data";
    case ScanOutcomeStage::Connect: break;
    }
    return "connect";
}

// The contract's NetworkKey pattern (mirror of UpstreamEngine.h::upstreamNetworkKeyValid; that header is
// not included here to keep this module free of the lease and standby machinery).
inline bool scanNetworkKeyValid(const QString &k)
{
    static const QRegularExpression re(QStringLiteral(
        "^(cell:[0-9]{3}-[0-9]{2,3}:(2g|3g|4g|5g|unknown)|cell:asn:[0-9]{1,10}:(2g|3g|4g|5g|unknown)"
        "|wifi:asn:[0-9]{1,10}|wifi|unknown)$"));
    return k.size() <= 48 && re.match(k).hasMatch();
}

struct ScanOutcomeItem {
    QString kind;          // "node" | "upstream"
    QString id;            // node_id or profile_id
    ScanClass outcome = ScanClass::NotVerified;
    ScanOutcomeStage stage = ScanOutcomeStage::Data;
    int ttfbMs = -1;
    qint64 bytes = -1;
    qint64 durationMs = -1;
    QString probe;         // "tunnel" | "full" | "leg" | "awg_mini" ("" = not sent)
    int rttMs = -1;
    QString evidence;      // "exclusion" for a row proven by exclusion ("" = direct); sent only when accepted

    QJsonObject toJson(const QString &networkKey) const
    {
        QJsonObject o;
        o.insert(QStringLiteral("kind"), kind);
        o.insert(QStringLiteral("id"), id);
        o.insert(QStringLiteral("network_key"), networkKey);
        o.insert(QStringLiteral("outcome"), QLatin1String(scanClassName(outcome)));
        o.insert(QStringLiteral("stage"), QLatin1String(scanOutcomeStageName(stage)));
        if (ttfbMs >= 0)
            o.insert(QStringLiteral("ttfb_ms"), qMin(ttfbMs, 600000));
        if (bytes >= 0)
            o.insert(QStringLiteral("bytes"), double(qMin<qint64>(bytes, 1073741824)));
        if (durationMs >= 0)
            o.insert(QStringLiteral("duration_ms"), double(qMin<qint64>(durationMs, 3600000)));
        if (probe == QLatin1String("tunnel") || probe == QLatin1String("full") || probe == QLatin1String("leg")
            || probe == QLatin1String("awg_mini"))
            o.insert(QStringLiteral("probe"), probe);
        if (rttMs >= 0 && scanClassWorking(outcome))
            o.insert(QStringLiteral("rtt_ms"), qMin(rttMs, 600000));
        if (kScanOutcomeEvidenceAccepted)
            o.insert(QStringLiteral("evidence"), evidence == QLatin1String("exclusion") ? evidence : QStringLiteral("direct"));
        return o;
    }
};

class ScanOutcomeCollector
{
public:
    void begin(const QString &networkKey)
    {
        m_key = networkKey;
        m_items.clear();
        m_seen.clear();
    }

    // Returns true when the item was taken.
    bool add(const ScanOutcomeItem &item)
    {
        if (item.outcome == ScanClass::NotVerified || item.stage == ScanOutcomeStage::Cache)
            return false;
        if (item.id.isEmpty() || item.id.size() > 64)
            return false;
        if (item.kind != QLatin1String("node") && item.kind != QLatin1String("upstream"))
            return false;
        const QString k = item.kind + QLatin1Char('/') + item.id;
        if (m_seen.contains(k))
            return false;
        m_seen.insert(k);
        m_items << item;
        return true;
    }

    bool has(const QString &kind, const QString &id) const { return m_seen.contains(kind + QLatin1Char('/') + id); }
    int size() const { return m_items.size(); }
    bool empty() const { return m_items.isEmpty(); }
    const QString &networkKey() const { return m_key; }
    const QList<ScanOutcomeItem> &items() const { return m_items; }

    // Request bodies {"items": [...]}, each <= maxBatch items; nothing for an invalid network key.
    QList<QJsonObject> batches(int maxBatch = kScanOutcomesMaxBatch) const
    {
        QList<QJsonObject> out;
        if (!scanNetworkKeyValid(m_key) || m_items.isEmpty())
            return out;
        const int n = qBound(1, maxBatch, 128);
        QJsonArray cur;
        for (const ScanOutcomeItem &it : m_items) {
            cur << it.toJson(m_key);
            if (cur.size() == n) {
                out << QJsonObject{{QStringLiteral("items"), cur}};
                cur = QJsonArray();
            }
        }
        if (!cur.isEmpty())
            out << QJsonObject{{QStringLiteral("items"), cur}};
        return out;
    }

private:
    QString m_key;
    QList<ScanOutcomeItem> m_items;
    QSet<QString> m_seen;
};

} // namespace avpn
