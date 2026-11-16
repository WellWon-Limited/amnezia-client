// client/core/serviceEngine/ScanBudget.h
// AVPN serviceEngine - bytes accounting of the Scanner: the cost of one probe, the projection of a
// schedule, the rolling-hour ledger and the decision whether a scan may start and how much it may spend.
// [header-only, QtCore; pure]
//
// Plan scanner-client-plan.md §1.2, §2.9, A11; manifest numbers scan_budget_scan_bytes (1.5 MiB per
// cellular scan), scan_budget_cellular_bytes_per_hour (5 MiB per rolling hour on cellular), and the
// manifest's device_budget.bytes_per_hour (the server's per-device budget on every network).
// Rules (each one a test in tests/scan_core_check.cpp):
//  - Cost of a full data probe = warm request + data body + 2 TLS handshakes (8 KiB each: the path's
//    own handshake and the TLS to the probe base); a reach socket costs kScanReachCostBytes; an awg_mini
//    session adds the AmneziaWG handshake and its prime echoes (about 85 KB in all).
//  - A cellular scan may start only when the bytes left in the rolling hour cover the scan's projection
//    (capped at the per-scan budget); it may then spend at most min(per-scan budget, hour left). The same
//    holds for the server's device budget on every network when the manifest names one. Wi-Fi without a
//    device budget = no cap (-1).
//  - Blocked: retryInMs = when enough ledger entries age out of the hour (the button «через N мин»).
//  - The ledger only grows by actual bytes the host reported (bytes_spent); nothing is ever negative;
//    entries older than one hour are pruned; an entry stamped in the future (clock moved back) still
//    counts until it is an hour old by the current clock (conservative).
// Persistence: toJson()/fromJson() (QSettings avpn/scanBudget, written by the coordinator on the
// PersistBudget action).
//
// Upstream Amnezia has no counterpart.
#pragma once

#include "ScanTunables.h"
#include "ScanTypes.h"

#include <QJsonArray>
#include <QJsonObject>
#include <QList>

#include <algorithm>

namespace avpn {

inline constexpr qint64 kScanTlsOverheadBytes = 8192;
inline constexpr qint64 kScanReachCostBytes = 512;
inline constexpr qint64 kScanAwgHandshakeBytes = 2048; // AmneziaWG junk packets + handshake
inline constexpr qint64 kScanAwgEchoBytes = 300;       // one prime ICMP echo both ways
inline constexpr qint64 kScanHourMs = 3600 * 1000;
inline constexpr int kScanLedgerMaxEntries = 256;

inline qint64 scanProbeCostBytes(ScanProbeKind kind, bool hasReach, const ScanTunables &t)
{
    qint64 c = hasReach ? kScanReachCostBytes : 0;
    if (kind == ScanProbeKind::XrayFull || kind == ScanProbeKind::XrayLeg)
        c += qint64(t.warmBytes) + qint64(t.stage2Bytes) + 2 * kScanTlsOverheadBytes;
    else if (kind == ScanProbeKind::AwgMini) // awg-probe-plan.md §3: ~82-84 KB measured on loopback
        c += kScanAwgHandshakeBytes + qint64(t.awgPrimeEchoes) * kScanAwgEchoBytes + qint64(t.warmBytes)
             + qint64(t.stage2Bytes) + 2 * kScanTlsOverheadBytes;
    return c;
}

struct ScanLedgerEntry {
    qint64 atMs = 0;
    qint64 bytes = 0;
    bool cellular = false;
};

class ScanBudgetLedger
{
public:
    void add(qint64 atMs, qint64 bytes, bool cellular)
    {
        if (bytes <= 0)
            return;
        m_entries << ScanLedgerEntry{atMs, bytes, cellular};
        while (m_entries.size() > kScanLedgerMaxEntries)
            m_entries.removeFirst();
    }

    void prune(qint64 nowMs)
    {
        m_entries.erase(std::remove_if(m_entries.begin(), m_entries.end(),
                                       [nowMs](const ScanLedgerEntry &e) { return nowMs - e.atMs >= kScanHourMs; }),
                        m_entries.end());
    }

    // Bytes inside the rolling hour ending at nowMs.
    qint64 spentInHour(qint64 nowMs, bool cellularOnly) const
    {
        qint64 s = 0;
        for (const ScanLedgerEntry &e : m_entries)
            if (nowMs - e.atMs < kScanHourMs && (!cellularOnly || e.cellular))
                s += e.bytes;
        return s;
    }

    qint64 leftInHour(qint64 nowMs, qint64 capBytes, bool cellularOnly) const
    {
        return qMax<qint64>(0, capBytes - spentInHour(nowMs, cellularOnly));
    }

    // Milliseconds until at least `needed` bytes are left in the hour (0 = now; -1 = never: needed > cap).
    qint64 msUntilLeft(qint64 nowMs, qint64 capBytes, qint64 needed, bool cellularOnly) const
    {
        if (needed > capBytes)
            return -1;
        if (leftInHour(nowMs, capBytes, cellularOnly) >= needed)
            return 0;
        QList<ScanLedgerEntry> in;
        for (const ScanLedgerEntry &e : m_entries)
            if (nowMs - e.atMs < kScanHourMs && (!cellularOnly || e.cellular))
                in << e;
        std::stable_sort(in.begin(), in.end(), [](const ScanLedgerEntry &a, const ScanLedgerEntry &b) { return a.atMs < b.atMs; });
        qint64 spent = 0;
        for (const ScanLedgerEntry &e : in)
            spent += e.bytes;
        for (const ScanLedgerEntry &e : in) {
            spent -= e.bytes;
            if (capBytes - spent >= needed)
                return qMax<qint64>(0, e.atMs + kScanHourMs - nowMs);
        }
        return 0;
    }

    const QList<ScanLedgerEntry> &entries() const { return m_entries; }

    QJsonArray toJson() const
    {
        QJsonArray a;
        for (const ScanLedgerEntry &e : m_entries) {
            QJsonObject o;
            o.insert(QStringLiteral("at_ms"), double(e.atMs));
            o.insert(QStringLiteral("bytes"), double(e.bytes));
            o.insert(QStringLiteral("cellular"), e.cellular);
            a << o;
        }
        return a;
    }

    static ScanBudgetLedger fromJson(const QJsonArray &a)
    {
        ScanBudgetLedger l;
        for (const QJsonValue &v : a) {
            const QJsonObject o = v.toObject();
            const qint64 at = qint64(o.value(QLatin1String("at_ms")).toDouble(0));
            const qint64 b = qint64(o.value(QLatin1String("bytes")).toDouble(0));
            if (at > 0 && b > 0 && b < (qint64(1) << 40))
                l.add(at, b, o.value(QLatin1String("cellular")).toBool(false));
        }
        return l;
    }

private:
    QList<ScanLedgerEntry> m_entries;
};

struct ScanBudgetDecision {
    bool allowed = true;
    qint64 capBytes = -1;     // most this scan may spend; -1 = no cap
    qint64 retryInMs = 0;     // blocked: when the scan can start (-1 = not within an hour)
    bool hourly = false;      // blocked by an hourly budget (the «через N мин» button)
};

// projectedBytes = the schedule's projection (ScanPlan). deviceBytesPerHour = manifest device budget
// (0 = unknown, ignored).
inline ScanBudgetDecision decideScanBudget(const ScanBudgetLedger &ledger, qint64 nowMs, ScanNetKind net,
                                           qint64 projectedBytes, qint64 deviceBytesPerHour, const ScanTunables &t)
{
    ScanBudgetDecision d;
    const bool cellular = net == ScanNetKind::Cellular;
    qint64 needed = qMax<qint64>(0, projectedBytes);
    if (cellular)
        needed = qMin<qint64>(needed, t.budgetScanBytes);
    qint64 cap = cellular ? qint64(t.budgetScanBytes) : -1;
    const auto block = [&d](qint64 retry) {
        d.allowed = false;
        d.hourly = true;
        d.retryInMs = qMax(d.retryInMs, retry);
    };
    // A projection larger than a whole hourly cap is judged against the cap itself (otherwise it could
    // never start).
    if (cellular) {
        const qint64 hourCap = t.budgetCellularBytesPerHour;
        const qint64 need = qMin(needed, hourCap);
        const qint64 left = ledger.leftInHour(nowMs, hourCap, true);
        cap = qMin(cap, left);
        if (need > 0 && left < need) {
            const qint64 wait = ledger.msUntilLeft(nowMs, hourCap, need, true);
            block(wait < 0 ? kScanHourMs : wait);
        }
    }
    if (deviceBytesPerHour > 0) {
        const qint64 need = qMin(needed, deviceBytesPerHour);
        const qint64 left = ledger.leftInHour(nowMs, deviceBytesPerHour, false);
        cap = cap < 0 ? left : qMin(cap, left);
        if (need > 0 && left < need) {
            const qint64 wait = ledger.msUntilLeft(nowMs, deviceBytesPerHour, need, false);
            block(wait < 0 ? kScanHourMs : wait);
        }
    }
    d.capBytes = cap;
    return d;
}

// Whole minutes for the «Повторить через N мин» button (at least 1 while blocked).
inline int scanRetryMinutes(qint64 retryInMs)
{
    if (retryInMs <= 0)
        return 0;
    return int(qMax<qint64>(1, (retryInMs + 59999) / 60000));
}

} // namespace avpn
