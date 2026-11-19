// client/core/serviceEngine/ScanTunables.h
// AVPN serviceEngine - the Scanner's server-driven numbers. [header-only, QtCore; pure]
//
// Source: the signed scan manifest `numbers` (openapi ScanManifest.numbers = the server's
// SCAN_CLIENT_NUMBERS, operator override app_config.client_numbers). Conventions of REMOTE-TUNING.md: a
// key that is absent uses the compiled default, a value outside the range is clamped, a non-finite one
// falls back to the default; the clamp lives here, in code, so an operator typo cannot switch a rule off.
//
// Four groups of keys:
//  1. published since contract 1.5.0 (src/tribe_backend/config.py SCAN_CLIENT_NUMBERS, incl. the plan's G5
//     numbers): defaults and ranges copied from the server's own clamps;
//  2. the AWG probe's numbers (awg-probe-plan.md §6.1), published since contract 1.6.0;
//  3. the plan's gap-1 numbers (slow limits, entry-IP spacing, hint life, follow-up time), published since
//     contract 1.7.0 (the server also publishes scan_light_timeout_ms and scan_cost_light_bytes: the client
//     ignores them since the Scanner's connection step left it, 19.11);
//  4. the worst-case costs of the one allowance (clamps x0.5..x4 of the default) and the freeze / drain
//     waits (plan v2.2 §2.2b), published since contract 1.7.0.
// Every default and clamp equals the server's (checked against config.py of 1.7.0; scan_stage2_stall_after_bytes
// 16384 -> 4096 on 16.11 on both sides, lab seam S2); the compiled values are the fallback for a manifest that
// lacks a key.
// scan_shade_ms also has a compiled fallback outside a manifest (ShadeQueue.h::shadeTimingFrom). Racing probes are
// the path engine's stage 2 (design 2026-11-17), not part of the Scanner.
// scanTunableTable() enumerates every key with its default and range (tests and the REMOTE-TUNING registry).
//
// Upstream Amnezia has no counterpart. Tests: tests/scan_core_check.cpp (build_scan_core.sh).
#pragma once

#include <QJsonObject>
#include <QList>
#include <QMap>
#include <QString>

#include <cmath>

namespace avpn {

struct ScanTunables {
    // 1. published (contract 1.5.0, SCAN_CLIENT_NUMBERS)
    int ownFailureTtlS = 180;
    int cacheWorksTtlS = 600;
    int cacheFailTtlS = 180;
    int stage1Sockets = 16;
    int stage1StaggerMs = 50;
    int stage1PerEntryIp = 2;
    int stage1TimeoutMs = 1500;
    int stage2Bytes = 65536;
    int stage2ConcurrencyCellular = 4;
    int stage2ConcurrencyWifi = 6;
    int stage2TtfbMs = 3000;
    int stage2StallMs = 1500;
    int stage2StallAfterBytes = 4096;
    int stage2TotalMs = 5000;
    int stopWorks = 10;
    int stopMs = 8000;
    int listTargetWorks = 10;
    int budgetScanBytes = 1572864;
    int budgetCellularBytesPerHour = 5242880;
    int manualCooldownS = 30;
    int autoCommitBytes = 24576;
    int classFastMs = 400;
    int classSlowMs = 1200;
    int warmBytes = 1024;
    int unverifiedRowsMax = 2;
    int checkSpeedBytes = 1048576;
    int pollMs = 300;
    int shadeMs = 1500;
    // 2. being added with the AWG probe (contract 1.6.0, awg-probe-plan.md §6.1)
    int awgConcurrency = 0;
    int awgHandshakeMs = 1500;
    int awgPrimeEchoes = 1;
    // 3. published since 1.7.0 (plan v2.2 §6 gap 1)
    int slowTtfbMs = 1500;
    int slowT64Ms = 3000;
    int entryIpSpacingMs = 300;
    int attemptHintTtlS = 120;
    int followUpMinLeftMs = 3000;
    // 4. published since 1.7.0 (plan v2.2 §2.2b): the worst-case costs reserved inside the scan's ONE
    //    allowance, and the freeze / drain waits of a stopping scan
    int costApiBytes = 10240;
    int costManifestBytes = 270336;
    int costBatchBytes = 12288;
    int costConfigBytes = 262144;
    int costTunnelProbeBytes = 82944;
    int costOutcomesBytes = 16384;
    int costNetinfoBytes = 10240;
    int freezeAckMs = 1000;
    int drainMs = 2000;

    static ScanTunables fromNumbers(const QMap<QString, double> &numbers);
    static ScanTunables fromJson(const QJsonObject &numbers);
};

// The single authoritative table of the Scanner's numbers: key, field, default, min, max, unit, group, meaning.
// The default is the compiled fallback for an absent key (and the value the server should publish); min..max
// is the clamp applied here whatever the server sends. Groups by the contract that published them: 1 (1.5.0),
// 2 the AWG probe (1.6.0), 3 and 4 (1.7.0).
struct ScanTunableSpec {
    const char *key;
    int ScanTunables::*field;
    int def;
    int lo;
    int hi;
    const char *unit;
    int group;
    const char *meaning;
};

inline const QList<ScanTunableSpec> &scanTunableTable()
{
    static const QList<ScanTunableSpec> t = {
        {"scan_own_failure_ttl_s", &ScanTunables::ownFailureTtlS, 180, 30, 3600, "s", 1, "an own failure on this network stays fresh (orders the candidate last in its tier)"},
        {"scan_cache_works_ttl_s", &ScanTunables::cacheWorksTtlS, 600, 60, 3600, "s", 1, "cached working rows count as a result when no scan can run"},
        {"scan_cache_fail_ttl_s", &ScanTunables::cacheFailTtlS, 180, 30, 3600, "s", 1, "a cached failure orders the candidate last in its tier"},
        {"scan_stage1_sockets", &ScanTunables::stage1Sockets, 16, 1, 64, "count", 1, "reach sockets open at once"},
        {"scan_stage1_stagger_ms", &ScanTunables::stage1StaggerMs, 50, 0, 1000, "ms", 1, "spacing of reach socket opens"},
        {"scan_stage1_per_entry_ip", &ScanTunables::stage1PerEntryIp, 2, 1, 16, "count", 1, "connections to one entry IP at once"},
        {"scan_stage1_timeout_ms", &ScanTunables::stage1TimeoutMs, 1500, 200, 10000, "ms", 1, "reach timeout"},
        {"scan_stage2_bytes", &ScanTunables::stage2Bytes, 65536, 16384, 1048576, "bytes", 1, "size of the data probe body"},
        {"scan_stage2_concurrency_cellular", &ScanTunables::stage2ConcurrencyCellular, 4, 1, 16, "count", 1, "Xray probes at once on cellular (per pool)"},
        {"scan_stage2_concurrency_wifi", &ScanTunables::stage2ConcurrencyWifi, 6, 1, 32, "count", 1, "Xray probes at once on Wi-Fi (per pool)"},
        {"scan_stage2_ttfb_ms", &ScanTunables::stage2TtfbMs, 3000, 500, 15000, "ms", 1, "first-byte limit of a probe request"},
        {"scan_stage2_stall_ms", &ScanTunables::stage2StallMs, 1500, 200, 10000, "ms", 1, "longest pause after stall_after_bytes"},
        // 4096, not 16384 (lab seam S2, 16.11): a mobile operator's freeze cuts a flow after 15-20 KB of the
        // CONNECTION - only ~7-14 KB of the probe's body (the lab's 16 KiB freeze delivered 10674 body bytes) - so
        // a threshold of 16 KiB of body never armed the rule: the probe waited for its total timeout and was
        // cancelled at the scan's end with no verdict. Server default changed with it (config.py).
        {"scan_stage2_stall_after_bytes", &ScanTunables::stage2StallAfterBytes, 4096, 1024, 262144, "bytes", 1, "the stall rule applies after this many body bytes"},
        {"scan_stage2_total_ms", &ScanTunables::stage2TotalMs, 5000, 1000, 30000, "ms", 1, "whole-probe limit"},
        {"scan_stop_works", &ScanTunables::stopWorks, 10, 1, 48, "rows", 1, "stop at this many working rows"},
        {"scan_stop_ms", &ScanTunables::stopMs, 8000, 1000, 60000, "ms", 1, "stop this long after the host start"},
        {"scan_list_target_works", &ScanTunables::listTargetWorks, 10, 1, 48, "rows", 1, "verified rows shown at most; lower tiers fill only below it"},
        {"scan_budget_scan_bytes", &ScanTunables::budgetScanBytes, 1572864, 65536, 16 * 1024 * 1024, "bytes", 1, "most one cellular scan may spend"},
        {"scan_budget_cellular_bytes_per_hour", &ScanTunables::budgetCellularBytesPerHour, 5242880, 262144, 256 * 1024 * 1024, "bytes", 1, "most the scans may spend on cellular per rolling hour"},
        {"scan_manual_cooldown_s", &ScanTunables::manualCooldownS, 30, 5, 3600, "s", 1, "«Повторить» again after a scan start"},
        {"scan_auto_commit_bytes", &ScanTunables::autoCommitBytes, 24576, 4096, 262144, "bytes", 1, "a racing probe commits at this many bytes (compiled off)"},
        {"scan_class_fast_ms", &ScanTunables::classFastMs, 400, 50, 10000, "ms", 1, "q = rtt + t64/2 at or below: «быстро»"},
        {"scan_class_slow_ms", &ScanTunables::classSlowMs, 1200, 100, 30000, "ms", 1, "q at or below (and above fast): «средне»; never below fast"},
        {"scan_warm_bytes", &ScanTunables::warmBytes, 1024, 1024, 65536, "bytes", 1, "warm-up request of a data probe"},
        {"scan_unverified_rows_max", &ScanTunables::unverifiedRowsMax, 2, 0, 10, "rows", 1, "«Не проверено» rows shown at most"},
        {"scan_check_speed_bytes", &ScanTunables::checkSpeedBytes, 1048576, 65536, 4 * 1024 * 1024, "bytes", 1, "speed sample of the connection check"},
        {"scan_poll_ms", &ScanTunables::pollMs, 300, 100, 5000, "ms", 1, "probe host poll period while the screen is open"},
        {"scan_shade_ms", &ScanTunables::shadeMs, 1500, 500, 10000, "ms", 1, "hold time of a notification shade"},
        {"scan_awg_concurrency", &ScanTunables::awgConcurrency, 0, 0, 8, "count", 2, "awg_mini sessions at once; 0 = no AWG probe"},
        {"scan_awg_handshake_ms", &ScanTunables::awgHandshakeMs, 1500, 300, 5000, "ms", 2, "handshake wait of one awg_mini session"},
        {"scan_awg_prime_echoes", &ScanTunables::awgPrimeEchoes, 1, 0, 3, "count", 2, "ICMP echoes before the data of an awg_mini session"},
        {"scan_slow_ttfb_ms", &ScanTunables::slowTtfbMs, 1500, 300, 10000, "ms", 3, "a working probe whose first request is slower is «Медленно»"},
        {"scan_slow_t64_ms", &ScanTunables::slowT64Ms, 3000, 500, 20000, "ms", 3, "a working probe whose body takes longer is «Медленно»"},
        {"scan_entry_ip_spacing_ms", &ScanTunables::entryIpSpacingMs, 300, 0, 2000, "ms", 3, "two connection opens to one entry IP at least this far apart (R8)"},
        {"scan_attempt_hint_ttl_s", &ScanTunables::attemptHintTtlS, 120, 10, 600, "s", 3, "life of a tap's attempt order hint in the engine"},
        {"scan_followup_min_left_ms", &ScanTunables::followUpMinLeftMs, 3000, 1000, 30000, "ms", 3, "a full follow-up of a provider leg starts only with this much scan time left"},
        {"scan_cost_api_bytes", &ScanTunables::costApiBytes, 10240, 5120, 40960, "bytes", 4, "worst case of one small API request (scan token, batch release, a 304 manifest revalidation): 8 KiB TLS + 2 KiB"},
        {"scan_cost_manifest_bytes", &ScanTunables::costManifestBytes, 270336, 135168, 1081344, "bytes", 4, "worst case of a full manifest answer (signed manifest cap 256 KiB + TLS)"},
        {"scan_cost_batch_bytes", &ScanTunables::costBatchBytes, 12288, 6144, 49152, "bytes", 4, "worst case of the probe-batch answer without configs (<= 12 items + signature + TLS)"},
        {"scan_cost_config_bytes", &ScanTunables::costConfigBytes, 262144, 131072, 1048576, "bytes", 4, "worst case of one included config (Wi-Fi only; profile cap 256 KiB)"},
        {"scan_cost_tunnel_probe_bytes", &ScanTunables::costTunnelProbeBytes, 82944, 41472, 331776, "bytes", 4, "worst case of the sized check through the live tunnel (warm + body + 2 x 8 KiB TLS); never below that sum"},
        {"scan_cost_outcomes_bytes", &ScanTunables::costOutcomesBytes, 16384, 8192, 65536, "bytes", 4, "worst case of one outcomes POST (<= 32 items + TLS)"},
        {"scan_cost_netinfo_bytes", &ScanTunables::costNetinfoBytes, 10240, 5120, 40960, "bytes", 4, "worst case of one direct access attempt of the probe host (reserved by the host inside its grant)"},
        {"scan_freeze_ack_ms", &ScanTunables::freezeAckMs, 1000, 200, 5000, "ms", 4, "wait for the host's freeze ack; none -> the whole host grant is charged"},
        {"scan_drain_ms", &ScanTunables::drainMs, 2000, 500, 10000, "ms", 4, "wait for the final totals after the freeze ack; none -> the ack's spent + reserved are charged"},
    };
    return t;
}

inline int scanClampNumber(double v, int def, int lo, int hi)
{
    if (!std::isfinite(v))
        return def;
    if (v < lo)
        return lo;
    if (v > hi)
        return hi;
    return int(v);
}

inline ScanTunables ScanTunables::fromNumbers(const QMap<QString, double> &numbers)
{
    ScanTunables t;
    for (const ScanTunableSpec &s : scanTunableTable()) {
        const auto it = numbers.constFind(QLatin1String(s.key));
        t.*(s.field) = it == numbers.constEnd() ? s.def : scanClampNumber(it.value(), s.def, s.lo, s.hi);
    }
    // Cross rules: the "slow" boundary is never below the "fast" one; the live probe's reservation covers its
    // warm-up, body and TLS.
    if (t.classSlowMs < t.classFastMs)
        t.classSlowMs = t.classFastMs;
    t.costTunnelProbeBytes = qMax(t.costTunnelProbeBytes, t.warmBytes + t.stage2Bytes + 16384);
    return t;
}

inline ScanTunables ScanTunables::fromJson(const QJsonObject &numbers)
{
    QMap<QString, double> m;
    for (auto it = numbers.constBegin(); it != numbers.constEnd(); ++it)
        if (it.value().isDouble())
            m.insert(it.key(), it.value().toDouble());
    return fromNumbers(m);
}

} // namespace avpn
