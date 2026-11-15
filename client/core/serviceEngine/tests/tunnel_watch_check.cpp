// AVPN (iOS tunnel-side data watch, build 140): checks of the app's pure half.
//   ConnectTunables.h   - the one table of ios_tw_* numbers and its clamps;
//   TunnelWatchPlan.h   - the plan file the app writes for the extension (contract C1);
//   TunnelWatchStatus.h - the extension's `watch` block (contract C2), the freeze of the app's own
//                         decisions on return to the foreground, what an adopted snapshot means.
// Build/run: tests/build_tunnel_watch.sh. QtCore only, no network.
//
// What a mistake here costs: a wrong clamp lets a server typo storm or blind the watch; a plan the
// extension rejects switches the watch off silently; a freeze that never releases stops the app's
// own health checks; a verdict taken for another session re-checks (and may leave) a healthy node.
#include "../TunnelWatchPlan.h"
#include "../TunnelWatchStatus.h"

#include <QJsonDocument>
#include <QSet>
#include <cmath>
#include <cstdio>
#include <limits>

static int failures = 0;
static int total = 0;

#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        ++total;                                                                                   \
        if (!(cond)) {                                                                             \
            std::printf("FAIL - %s (line %d)\n", msg, __LINE__);                                   \
            ++failures;                                                                            \
        }                                                                                          \
    } while (0)

using namespace avpn;

static const TunnelWatchNumberSpec &spec(const char *key)
{
    const TunnelWatchNumberSpec *s = tunnelWatchNumberSpec(key);
    if (!s) {
        std::printf("FAIL - key %s is not in the table\n", key);
        ++failures;
        static const TunnelWatchNumberSpec none{"", 0, 0, 0, false};
        return none;
    }
    return *s;
}

// ---- the table -------------------------------------------------------------------------------------
static void tableAndClamps()
{
    // Defaults and bounds are the registry of REMOTE-TUNING: pinned one by one.
    struct Row { const char *key; double def, lo, hi; bool plan; };
    const Row rows[] = {
        {"ios_tw_cycle_s", 25, 10, 120, true},
        {"ios_tw_cycle_min_tx_bytes", 1024, 1024, 1048576, true},
        {"ios_tw_dead_cycles", 3, 2, 20, true},
        {"ios_tw_cycle_chain_gap_s", 30, 0, 300, true},
        {"ios_tw_recover_rx_bytes", 16384, 1024, 1048576, true},
        {"ios_tw_min_episode_tx_bytes", 3072, 2048, 1048576, true},
        {"ios_tw_hs_rx_allowance_bytes", 148, 92, 4096, true},
        {"ios_tw_hs_tx_allowance_bytes", 1024, 148, 8192, true},
        {"ios_tw_min_heal_steps", 2, 0, 6, true},
        {"ios_tw_path_stable_s", 20, 0, 120, true},
        {"ios_tw_start_grace_s", 20, 5, 120, true},
        {"ios_tw_wake_grace_s", 10, 0, 60, true},
        {"ios_tw_app_alive_s", 10, 3, 60, true},
        {"ios_tw_max_switches", 5, 0, 5, true},
        {"ios_tw_suspect_window_s", 60, 30, 600, true},
        {"ios_tw_suspect_min_tx_bytes", 65536, 4096, 16777216, true},
        {"ios_tw_suspect_max_rx_bytes", 4096, 0, 1048576, true},
        {"ios_tw_probe_timeout_ms", 4000, 1000, 15000, true},
        {"ios_tw_probe_max_per_episode", 3, 1, 10, true},
        {"ios_tw_probe_max_per_hour", 12, 1, 60, true},
        {"ios_tw_sanity_required", 1, 0, 1, true},
        {"ios_tw_probe", 1, 0, 1, true},
        {"ios_tw_plan_ttl_h", 24, 1, 168, true},
        {"ios_tw_policy_max_age_h", 24, 0, 168, true},
        {"ios_tw_resume_wait_ms", 3000, 500, 10000, false},
        {"ios_on_demand_bg_arm_max_s", 25, 5, 28, false},
    };
    int count = 0;
    for (const TunnelWatchNumberSpec &s : kIosTunnelWatchNumbers) {
        ++count;
        CHECK(s.lo <= s.def && s.def <= s.hi, "a default lies inside its own bounds");
    }
    CHECK(count == int(sizeof(rows) / sizeof(rows[0])), "the table has exactly the registry's rows");
    for (const Row &r : rows) {
        const TunnelWatchNumberSpec &s = spec(r.key);
        CHECK(s.def == r.def && s.lo == r.lo && s.hi == r.hi && s.toPlan == r.plan, r.key);
        CHECK(clampTunnelWatchNumber(s, r.def) == std::llround(r.def), "the default passes unchanged");
        CHECK(clampTunnelWatchNumber(s, -1e18) == std::llround(r.lo), "far below -> the floor");
        CHECK(clampTunnelWatchNumber(s, 1e18) == std::llround(r.hi), "far above -> the ceiling");
        CHECK(clampTunnelWatchNumber(s, std::numeric_limits<double>::quiet_NaN()) == std::llround(r.def), "NaN -> the default");
        CHECK(clampTunnelWatchNumber(s, std::numeric_limits<double>::infinity()) == std::llround(r.def), "infinity -> the default");
        CHECK(clampTunnelWatchNumber(s, r.lo - 1) == std::llround(r.lo), "one below the floor -> the floor");
        CHECK(clampTunnelWatchNumber(s, r.hi + 1) == std::llround(r.hi), "one above the ceiling -> the ceiling");
    }
    CHECK(tunnelWatchNumberSpec("ios_tw_no_such_key") == nullptr, "an unknown key is not in the table");
    CHECK(clampTunnelWatchNumber(spec("ios_tw_cycle_s"), 40.4) == 40 && clampTunnelWatchNumber(spec("ios_tw_cycle_s"), 40.6) == 41,
          "a fraction is rounded to the nearest integer");
    // Through the store: absent -> default, typo -> bound.
    TuningStore::set({}, {}, {}, {});
    CHECK(iosTunnelWatchNumberTuned("ios_tw_cycle_s") == 25 && iosTwResumeWaitMsTuned() == 3000 && iosOnDemandBgArmMaxSTuned() == 25,
          "an empty config gives the defaults");
    TuningStore::set({{QStringLiteral("ios_tw_cycle_s"), 1.0}, {QStringLiteral("ios_tw_resume_wait_ms"), 99999.0},
                      {QStringLiteral("ios_on_demand_bg_arm_max_s"), 600.0}}, {}, {}, {});
    CHECK(iosTunnelWatchNumberTuned("ios_tw_cycle_s") == 10 && iosTwResumeWaitMsTuned() == 10000 && iosOnDemandBgArmMaxSTuned() == 28,
          "a server typo is clamped: the background hold never outlives the 28 s iOS allows");
    CHECK(iosTunnelWatchNumberTuned("ios_tw_no_such_key") == 0, "an unknown key reads as 0");
    TuningStore::set({}, {}, {}, {});
}

// ---- the plan --------------------------------------------------------------------------------------
static WatchPlanInputs planInputs()
{
    WatchPlanInputs in;
    in.nowMs = 1800000000000LL;
    in.configFetchedMs = in.nowMs - 3600000;
    in.watch = true;
    in.poolRevision = 1794627422892LL;
    in.engineTransportMode = QStringLiteral("auto");
    in.sessionNodeId = QStringLiteral("12");
    in.sessionProto = QStringLiteral("awg");
    in.sessionCountry = QStringLiteral("EE");
    in.cellularKey = QStringLiteral("cellular:250-02");
    in.numbers = watchPlanNumbers([](const TunnelWatchNumberSpec &s) { return s.def; });
    return in;
}

static void planBuilder()
{
    const QJsonObject plan = buildWatchPlan(planInputs());
    const QStringList keyList = plan.keys();
    const QSet<QString> keys(keyList.begin(), keyList.end());
    const QSet<QString> expected{QStringLiteral("schema"), QStringLiteral("written_ms"), QStringLiteral("config_fetched_ms"),
                                 QStringLiteral("expires_ms"), QStringLiteral("policy_max_age_ms"), QStringLiteral("pool_revision"),
                                 QStringLiteral("transport_mode"), QStringLiteral("pin"), QStringLiteral("session"),
                                 QStringLiteral("net_keys"), QStringLiteral("net_memory"), QStringLiteral("features"),
                                 QStringLiteral("numbers"), QStringLiteral("candidates")};
    CHECK(keys == expected, "the plan has exactly the keys of contract C1 (no sanity_urls without a list)");
    CHECK(plan.value("schema").toInt() == 1, "schema 1");
    CHECK(qint64(plan.value("written_ms").toDouble()) == 1800000000000LL, "written_ms");
    CHECK(qint64(plan.value("config_fetched_ms").toDouble()) == 1800000000000LL - 3600000, "config_fetched_ms");
    CHECK(qint64(plan.value("expires_ms").toDouble()) == 1800000000000LL + 24LL * 3600000, "expires = written + ttl");
    CHECK(qint64(plan.value("policy_max_age_ms").toDouble()) == 24LL * 3600000, "policy max age in ms");
    CHECK(qint64(plan.value("pool_revision").toDouble()) == 1794627422892LL, "a 13-digit pool revision survives the JSON number");
    CHECK(plan.value("candidates").isArray() && plan.value("candidates").toArray().isEmpty(), "stage 1: candidates are always empty");
    const QJsonObject features = plan.value("features").toObject();
    CHECK(features.value("ios_tunnel_watch").isBool() && features.value("ios_tunnel_watch").toBool(), "the flag is a JSON boolean");
    CHECK(features.value("ios_tunnel_watch_switch").isBool() && !features.value("ios_tunnel_watch_switch").toBool()
              && features.value("ios_on_demand_bg_arm").isBool() && features.size() == 3, "three flags, booleans");
    {
        // The kill switch: each flag is written as the server gave it, false included.
        WatchPlanInputs off = planInputs();
        off.watch = false;
        off.bgArm = true;
        const QJsonObject f = buildWatchPlan(off).value("features").toObject();
        CHECK(f.value("ios_tunnel_watch").isBool() && !f.value("ios_tunnel_watch").toBool(), "the watch flag off is written as false");
        CHECK(f.value("ios_on_demand_bg_arm").toBool(), "the arming flag does not follow the watch flag");
        off.watch = true;
        off.bgArm = false;
        const QJsonObject g = buildWatchPlan(off).value("features").toObject();
        CHECK(g.value("ios_tunnel_watch").toBool() && !g.value("ios_on_demand_bg_arm").toBool(), "and the other way round");
    }
    const QJsonObject numbers = plan.value("numbers").toObject();
    int planRows = 0;
    for (const TunnelWatchNumberSpec &s : kIosTunnelWatchNumbers) {
        if (!s.toPlan) {
            CHECK(!numbers.contains(QLatin1String(s.key)), "an app-only number does not go into the plan");
            continue;
        }
        ++planRows;
        CHECK(numbers.value(QLatin1String(s.key)).isDouble() && numbers.value(QLatin1String(s.key)).toDouble() == s.def, s.key);
    }
    CHECK(numbers.size() == planRows, "every plan row of the table is written, nothing else");
    // 0 and 1 stay NUMBERS in the bytes (the extension tells a number from a boolean by type).
    WatchPlanInputs zeros = planInputs();
    zeros.numbers = watchPlanNumbers([](const TunnelWatchNumberSpec &s) { return s.lo; });
    const QByteArray bytes = serializeWatchPlan(buildWatchPlan(zeros));
    CHECK(bytes.contains("\"ios_tw_min_heal_steps\":0") && bytes.contains("\"ios_tw_probe\":0")
              && bytes.contains("\"ios_tw_sanity_required\":0") && bytes.contains("\"ios_tunnel_watch\":true"),
          "zeros are written as 0, flags as true/false");
    CHECK(bytes.size() > 500 && bytes.size() < 4096, "a stage 1 plan is a couple of kilobytes");
    CHECK(QJsonDocument::fromJson(bytes).object() == buildWatchPlan(zeros), "the bytes parse back to the same plan");

    // Clamped numbers reach the plan clamped.
    WatchPlanInputs wild = planInputs();
    wild.numbers = watchPlanNumbers([](const TunnelWatchNumberSpec &) { return 1e15; });
    const QJsonObject wildNumbers = buildWatchPlan(wild).value("numbers").toObject();
    CHECK(wildNumbers.value("ios_tw_cycle_s").toDouble() == 120 && wildNumbers.value("ios_tw_max_switches").toDouble() == 5
              && wildNumbers.value("ios_tw_probe_max_per_hour").toDouble() == 60, "a wild server value is written at its ceiling");
    CHECK(qint64(buildWatchPlan(wild).value("expires_ms").toDouble()) == 1800000000000LL + 168LL * 3600000, "the ttl uses the clamped hours");
    WatchPlanInputs zeroAge = planInputs();
    zeroAge.numbers = watchPlanNumbers([](const TunnelWatchNumberSpec &s) {
        return std::strcmp(s.key, "ios_tw_policy_max_age_h") == 0 ? 0.0 : s.def;
    });
    CHECK(buildWatchPlan(zeroAge).value("policy_max_age_ms").toDouble() == 0, "max age 0 = only while the app is alive");
    WatchPlanInputs noFetch = planInputs();
    noFetch.configFetchedMs = -5;
    CHECK(buildWatchPlan(noFetch).value("config_fetched_ms").toDouble() == 0, "an unknown fetch time is written as 0");

    // Session, pin, mode.
    const QJsonObject session = plan.value("session").toObject();
    CHECK(session.value("node_id").toInt() == 12 && session.value("proto").toString() == "awg" && session.value("country").toString() == "EE", "session");
    CHECK(plan.value("pin").toObject().value("node_id").toInt() == 0 && plan.value("pin").toObject().value("country").toString().isEmpty(), "no pin");
    WatchPlanInputs strayCountry = planInputs();
    strayCountry.pinCountry = QStringLiteral("EE"); // a country without a pinned node is not a pin
    CHECK(buildWatchPlan(strayCountry).value("pin").toObject().value("country").toString().isEmpty(), "no pinned node: no pin country");
    WatchPlanInputs pinned = planInputs();
    pinned.pinNodeId = QStringLiteral("16:xray");
    pinned.pinCountry = QStringLiteral("RS");
    pinned.engineTransportMode = QStringLiteral("awg");
    pinned.sessionProto = QStringLiteral("xray-reality");
    const QJsonObject p2 = buildWatchPlan(pinned);
    CHECK(p2.value("pin").toObject().value("node_id").toInt() == 16 && p2.value("pin").toObject().value("country").toString() == "RS", "the pin carries node and country");
    CHECK(p2.value("transport_mode").toString() == "amnezia" && p2.value("session").toObject().value("proto").toString() == "xray", "engine names -> contract names");
    CHECK(watchPlanTransportMode(QStringLiteral("xray")) == "xray" && watchPlanTransportMode(QStringLiteral("auto")) == "auto"
              && watchPlanTransportMode(QString()) == "auto" && watchPlanTransportMode(QStringLiteral("junk")) == "auto", "transport mode names");
    CHECK(watchPlanNodeId(QStringLiteral("16")) == 16 && watchPlanNodeId(QStringLiteral("16:xray:2")) == 16 && watchPlanNodeId(QString()) == 0
              && watchPlanNodeId(QStringLiteral("x16")) == 0 && watchPlanNodeId(QStringLiteral("16x")) == 0
              && watchPlanNodeId(QStringLiteral("99999999999")) == 0, "node ids: leading digits, junk -> 0");

    // Network keys and memory: only the two keys, only live entries.
    CHECK(plan.value("net_keys").toObject().value("wifi").toString() == "wifi"
              && plan.value("net_keys").toObject().value("cellular").toString() == "cellular:250-02", "net keys");
    WatchPlanInputs noCarrier = planInputs();
    noCarrier.cellularKey.clear();
    CHECK(buildWatchPlan(noCarrier).value("net_keys").toObject().value("cellular").toString() == "cellular", "no carrier code -> the shared key");
    const qint64 nowSec = 1800000000;
    QByteArray memory = networkMemoryRemember(QByteArray(), QStringLiteral("wifi"), QStringLiteral("15"), nowSec - 100);
    memory = networkMemoryRemember(memory, QStringLiteral("cellular:250-02"), QStringLiteral("16"), nowSec - kNetworkMemoryMaxAgeSec - 1);
    memory = networkMemoryRemember(memory, QStringLiteral("cellular:250-99"), QStringLiteral("12"), nowSec - 5);
    const WatchPlanMemoryEntry wifi = watchPlanMemoryEntry(memory, QStringLiteral("wifi"), nowSec);
    const WatchPlanMemoryEntry stale = watchPlanMemoryEntry(memory, QStringLiteral("cellular:250-02"), nowSec);
    CHECK(wifi.nodeId == 15 && wifi.savedMs == (nowSec - 100) * 1000, "a live entry: node and time");
    CHECK(stale.nodeId == 0 && stale.savedMs == 0, "an entry older than 7 days is not handed over");
    CHECK(watchPlanMemoryEntry(memory, QStringLiteral("nope"), nowSec).nodeId == 0 && watchPlanMemoryEntry(memory, QString(), nowSec).nodeId == 0
              && watchPlanMemoryEntry(QByteArray("garbage"), QStringLiteral("wifi"), nowSec).nodeId == 0, "absent key / garbage blob -> nothing");
    WatchPlanInputs withMemory = planInputs();
    withMemory.memory = {wifi, stale, watchPlanMemoryEntry(memory, QStringLiteral("cellular:250-99"), nowSec)};
    const QJsonObject mem = buildWatchPlan(withMemory).value("net_memory").toObject();
    CHECK(mem.size() == 1 && mem.value("wifi").toObject().value("node_id").toInt() == 15
              && qint64(mem.value("wifi").toObject().value("saved_ms").toDouble()) == (nowSec - 100) * 1000,
          "net_memory: the live entry of one of the two keys; another carrier's entry stays out");

    // Bypass-check targets only when the server gave a list.
    WatchPlanInputs urls = planInputs();
    urls.sanityUrlsKnown = true;
    urls.sanityUrls = {QStringLiteral("http://a.example/204")};
    CHECK(buildWatchPlan(urls).value("sanity_urls").toArray().size() == 1, "a server list is carried");
    urls.sanityUrls.clear();
    CHECK(!buildWatchPlan(urls).contains("sanity_urls"), "an empty list is not written (the extension uses its built-in two)");

    // The 64 KB guard.
    QJsonObject huge = plan;
    huge.insert(QStringLiteral("blob"), QString(70 * 1024, QLatin1Char('x')));
    CHECK(serializeWatchPlan(huge).isEmpty() && !serializeWatchPlan(plan).isEmpty(), "a plan over 64 KB is not written at all");
    QJsonObject edge = plan;
    const qsizetype room = kWatchPlanMaxBytes - serializeWatchPlan(plan).size() - qsizetype(sizeof(",\"b\":\"\"") - 1);
    edge.insert(QStringLiteral("b"), QString(room, QLatin1Char('x')));
    CHECK(serializeWatchPlan(edge).size() == kWatchPlanMaxBytes, "exactly 64 KB is still written");
    edge.insert(QStringLiteral("b"), QString(room + 1, QLatin1Char('x')));
    CHECK(serializeWatchPlan(edge).isEmpty(), "one byte more is not");

    // The file exists only once the flag has been true on this install.
    CHECK(!decideWatchPlanWrite(false, false).write && !decideWatchPlanWrite(false, false).everOnAfter, "flag never on: no file (build 139)");
    CHECK(decideWatchPlanWrite(true, false).write && decideWatchPlanWrite(true, false).everOnAfter, "flag on: written, remembered");
    CHECK(decideWatchPlanWrite(false, true).write && decideWatchPlanWrite(false, true).everOnAfter, "flag off after having been on: still written (the kill switch reaches the extension)");
    CHECK(decideWatchPlanWrite(true, true).write, "flag on again");

    // The journal line.
    CHECK(watchPlanJournalLine(plan, QStringLiteral("start"))
              == QStringLiteral("watch_plan_written candidates=0 switch=0 pool_rev=1794627422892 mode=auto pin=- watch=1 why=start"), "journal line");
    CHECK(watchPlanJournalLine(p2, QStringLiteral("pin")).contains(QStringLiteral("mode=amnezia pin=16 ")), "journal line with a pin");
}

// ---- the `watch` block ------------------------------------------------------------------------------
static QVariantMap watchBlock(const QString &verdict)
{
    return QJsonDocument::fromJson(QByteArray(
        "{\"enabled\":true,\"verdict\":\"") + verdict.toUtf8() + QByteArray(
        "\",\"since_ms\":1800000000000,\"passive\":\"no_data\",\"cycles\":3,\"ep_s\":78,\"tx\":25224,\"rx_data\":0,"
        "\"heal_steps\":2,\"sanity\":\"ok\",\"probe\":\"silent\",\"probe_reason\":\"passive\",\"probe_ms\":0,"
        "\"probe_at_ms\":1800000000500,\"probes_episode\":1,\"probes_hour\":2,\"refuted\":1,\"would_switch\":true,"
        "\"app_alive\":false,\"last_no_data_ms\":1800000001000,\"recovered_ms\":0,\"switch_seq\":0,\"switches\":[]}")).object().toVariantMap();
}

static void statusBlock()
{
    const TunnelWatchSnapshot absent = parseTunnelWatch(QVariant());
    CHECK(!absent.present && !absent.valid && !absent.enabled, "no `watch` key (a build 139 extension): absent");
    CHECK(!parseTunnelWatch(QVariant(QStringLiteral("no_data"))).present && !parseTunnelWatch(QVariant(7)).present, "not an object: absent");
    const TunnelWatchSnapshot s = parseTunnelWatch(watchBlock(QStringLiteral("no_data")));
    CHECK(s.present && s.valid && s.enabled && s.verdict == WatchVerdict::NoData, "a full block parses");
    CHECK(s.sinceMs == 1800000000000LL && s.passive == "no_data" && s.cycles == 3 && s.epS == 78 && s.tx == 25224 && s.rxData == 0, "counters");
    CHECK(s.healSteps == 2 && s.sanity == "ok" && s.probe == "silent" && s.probeReason == "passive" && s.probeAtMs == 1800000000500LL, "checks");
    CHECK(s.probesEpisode == 1 && s.probesHour == 2 && s.refuted == 1 && s.wouldSwitch && !s.appAlive, "probe counts and marks");
    CHECK(s.lastNoDataMs == 1800000001000LL && s.recoveredMs == 0 && s.switchSeq == 0 && s.switches == 0, "stage 2 fields are carried");
    for (const char *v : {"none", "suspect", "no_data", "unconfirmed", "network", "captive"}) {
        const TunnelWatchSnapshot each = parseTunnelWatch(watchBlock(QLatin1String(v)));
        CHECK(each.valid && watchVerdictName(each.verdict) == QLatin1String(v), v);
    }
    // Garbled blocks are present but not valid: nothing may act on them.
    CHECK(parseTunnelWatch(watchBlock(QStringLiteral("recovered"))).present && !parseTunnelWatch(watchBlock(QStringLiteral("recovered"))).valid,
          "an unknown verdict word is not valid");
    QVariantMap noEnabled = watchBlock(QStringLiteral("no_data"));
    noEnabled.remove(QStringLiteral("enabled"));
    CHECK(!parseTunnelWatch(noEnabled).valid, "no `enabled`: not valid");
    QVariantMap enabledNumber = watchBlock(QStringLiteral("no_data"));
    enabledNumber.insert(QStringLiteral("enabled"), 1);
    CHECK(!parseTunnelWatch(enabledNumber).valid, "`enabled` must be a boolean");
    QVariantMap junk = watchBlock(QStringLiteral("no_data"));
    junk.insert(QStringLiteral("cycles"), QStringLiteral("many"));
    junk.insert(QStringLiteral("since_ms"), true);
    junk.insert(QStringLiteral("switch_seq"), 4);
    junk.insert(QStringLiteral("switches"), QVariantList{QVariantMap{}, QVariantMap{}});
    const TunnelWatchSnapshot j = parseTunnelWatch(junk);
    CHECK(j.valid && j.cycles == 0 && j.sinceMs == 0 && j.switchSeq == 4 && j.switches == 2, "junk fields read as 0; stage 2 fields are read");
    QVariantMap off = watchBlock(QStringLiteral("no_data"));
    off.insert(QStringLiteral("enabled"), false);
    CHECK(parseTunnelWatch(off).valid && !parseTunnelWatch(off).enabled, "a switched-off watch is valid and off");
    CHECK(watchVerdictName(WatchVerdict::Unknown) == "unknown" && watchVerdictFromString(QStringLiteral("NO_DATA")) == WatchVerdict::Unknown, "verdict words are exact");
}

// ---- what an adopted snapshot means ------------------------------------------------------------------
static WatchConsumeInputs consumeInputs(const QString &verdict)
{
    WatchConsumeInputs in;
    in.snapshot = parseTunnelWatch(watchBlock(verdict));
    in.snapshotNodeId = QStringLiteral("16");
    in.snapshotGeneration = QStringLiteral("gen-A");
    in.appNodeId = QStringLiteral("16");
    in.appGeneration = QStringLiteral("gen-A");
    return in;
}

static void consume()
{
    CHECK(decideWatchConsume(consumeInputs(QStringLiteral("no_data"))) == WatchConsume::Reverify, "no_data for our session: re-check");
    CHECK(decideWatchConsume(consumeInputs(QStringLiteral("unconfirmed"))) == WatchConsume::Reverify, "unconfirmed for our session: re-check");
    for (const char *v : {"none", "suspect", "network", "captive"})
        CHECK(decideWatchConsume(consumeInputs(QLatin1String(v))) == WatchConsume::Nothing, v);
    WatchConsumeInputs in = consumeInputs(QStringLiteral("no_data"));
    in.snapshot = parseTunnelWatch(QVariant());
    CHECK(decideWatchConsume(in) == WatchConsume::Nothing, "a build 139 extension: nothing changes");
    in = consumeInputs(QStringLiteral("no_data"));
    in.snapshot.valid = false;
    CHECK(decideWatchConsume(in) == WatchConsume::Nothing, "a garbled block: nothing");
    in = consumeInputs(QStringLiteral("no_data"));
    in.snapshot.enabled = false;
    CHECK(decideWatchConsume(in) == WatchConsume::Nothing, "a switched-off watch: nothing");
    in = consumeInputs(QStringLiteral("no_data"));
    in.snapshotNodeId = QStringLiteral("12");
    CHECK(decideWatchConsume(in) == WatchConsume::OtherSession, "a verdict about another node is not ours");
    in = consumeInputs(QStringLiteral("no_data"));
    in.snapshotGeneration = QStringLiteral("gen-B");
    CHECK(decideWatchConsume(in) == WatchConsume::OtherSession, "a verdict of another extension session (iOS restarted the tunnel) is not ours");
    in = consumeInputs(QStringLiteral("no_data"));
    in.appNodeId.clear();
    CHECK(decideWatchConsume(in) == WatchConsume::OtherSession, "the app does not know its node: identity only");
    in.snapshotNodeId.clear();
    CHECK(decideWatchConsume(in) == WatchConsume::OtherSession, "no node on either side is not a match");
    in = consumeInputs(QStringLiteral("no_data"));
    in.snapshotGeneration.clear();
    in.appGeneration.clear();
    CHECK(decideWatchConsume(in) == WatchConsume::OtherSession, "no generation on either side is not a match");
    CHECK(watchVerdictForgetsNode(WatchVerdict::NoData), "a verdict the probe confirmed: the network memory forgets the node");
    for (WatchVerdict v : {WatchVerdict::Unconfirmed, WatchVerdict::None, WatchVerdict::Suspect, WatchVerdict::Network, WatchVerdict::Captive,
                           WatchVerdict::Unknown})
        CHECK(!watchVerdictForgetsNode(v), "any other verdict leaves the network memory alone");
    CHECK(reverifyActionFor(true, false) == ReverifyAction::RestartPending, "a pending check starts again with its full budget");
    CHECK(reverifyActionFor(false, true) == ReverifyAction::ReenterFromConnected, "a connected session goes back to verifying");
    CHECK(reverifyActionFor(false, false) == ReverifyAction::None, "a switch / start / stop under way is left alone");
    CHECK(reverifyActionFor(true, true) == ReverifyAction::RestartPending, "verifying wins");
    const TunnelWatchSnapshot s = parseTunnelWatch(watchBlock(QStringLiteral("no_data")));
    CHECK(watchConsumedJournalLine(s, QStringLiteral("16"), 1800000402760LL)
              == QStringLiteral("data_watch_consumed verdict=no_data node=16 age_ms=402760 probe=silent -> reverify"), "journal line");
    TunnelWatchSnapshot unknownAge = s;
    unknownAge.sinceMs = 0;
    unknownAge.probe.clear();
    CHECK(watchConsumedJournalLine(unknownAge, QStringLiteral("16"), 5).contains(QStringLiteral("age_ms=-1 probe=- ")), "unknown age and probe");
    CHECK(watchConsumedJournalLine(s, QStringLiteral("16"), 1).contains(QStringLiteral("age_ms=-1")), "a verdict from the future has no age");
}

// ---- the freeze on return to the foreground ----------------------------------------------------------
static ResumeFreezeInputs tick(qint64 nowMs, qint64 sinceLast = 1000)
{
    ResumeFreezeInputs in;
    in.flagOn = true;
    in.tunnelConnected = true;
    in.nowMs = nowMs;
    in.timeoutMs = 3000;
    in.sinceLastTickMs = sinceLast;
    in.tickPeriodMs = 1000;
    return in;
}

static void resumeFreeze()
{
    ResumeFreezeState idle;
    CHECK(decideResumeFreeze(idle, tick(1000)) == FreezeStep::NotFrozen && !idle.active, "nothing is held by default");
    CHECK(!resumeFreezeBegins(idle, false, true), "flag off: the freeze never begins (build 139)");
    CHECK(!resumeFreezeBegins(idle, true, false), "no tunnel: nothing to ask");
    CHECK(resumeFreezeBegins(idle, true, true), "flag on and connected: begins");

    // Snapshot releases.
    ResumeFreezeState st;
    beginResumeFreeze(st, 10000);
    CHECK(st.active && st.startMs == 10000 && !resumeFreezeBegins(st, true, true), "held; a second begin is not needed");
    CHECK(decideResumeFreeze(st, tick(11000)) == FreezeStep::Hold && st.active, "1 s: hold");
    ResumeFreezeInputs snap = tick(11200, 0);
    snap.snapshotArrived = true;
    CHECK(decideResumeFreeze(st, snap) == FreezeStep::ReleaseSnapshot && !st.active && st.startMs == -1, "the snapshot releases");
    CHECK(decideResumeFreeze(st, tick(12000)) == FreezeStep::NotFrozen, "released once");

    // Timeout releases, at the bound exactly.
    beginResumeFreeze(st, 10000);
    CHECK(decideResumeFreeze(st, tick(12999)) == FreezeStep::Hold, "2999 ms: hold");
    CHECK(decideResumeFreeze(st, tick(13000)) == FreezeStep::ReleaseTimeout && !st.active, "3000 ms: released by the timeout");

    // Flag off / tunnel gone release at once.
    beginResumeFreeze(st, 10000);
    ResumeFreezeInputs off = tick(10500);
    off.flagOn = false;
    CHECK(decideResumeFreeze(st, off) == FreezeStep::ReleaseOff && !st.active, "the flag went off: decide as before at once");
    beginResumeFreeze(st, 10000);
    ResumeFreezeInputs down = tick(10500);
    down.tunnelConnected = false;
    CHECK(decideResumeFreeze(st, down) == FreezeStep::ReleaseOff && !st.active, "the tunnel left Connected: nothing to wait for");
    beginResumeFreeze(st, 10000);
    ResumeFreezeInputs offWithSnapshot = tick(10500);
    offWithSnapshot.flagOn = false;
    offWithSnapshot.snapshotArrived = true;
    CHECK(decideResumeFreeze(st, offWithSnapshot) == FreezeStep::ReleaseOff, "flag off outranks a snapshot: it is not consumed");

    // A late tick inside the wait (the app was frozen again) is not a timeout: wait again, ask again.
    beginResumeFreeze(st, 10000);
    CHECK(decideResumeFreeze(st, tick(11000)) == FreezeStep::Hold, "first tick");
    CHECK(decideResumeFreeze(st, tick(500000, 489000)) == FreezeStep::HoldReask && st.active && st.startMs == 500000,
          "a tick 489 s late: the frozen time is not waiting time");
    CHECK(decideResumeFreeze(st, tick(502999)) == FreezeStep::Hold, "the wait runs from the thaw");
    CHECK(decideResumeFreeze(st, tick(503000)) == FreezeStep::ReleaseTimeout, "and ends 3 s after it");
    // The first late tick right after the freeze began (the one that revealed the thaw) is not a re-ask:
    // its previous tick was before the wait started.
    beginResumeFreeze(st, 500000);
    CHECK(decideResumeFreeze(st, tick(500300, 400000)) == FreezeStep::Hold && st.startMs == 500000, "the tick that revealed the thaw does not restart the wait");
    // A snapshot wins over a late tick.
    ResumeFreezeInputs lateWithSnapshot = tick(900000, 300000);
    lateWithSnapshot.snapshotArrived = true;
    CHECK(decideResumeFreeze(st, lateWithSnapshot) == FreezeStep::ReleaseSnapshot, "a snapshot is a snapshot, however late the tick");
    // The wall clock stepped back: never stretch the wait.
    beginResumeFreeze(st, 10000);
    CHECK(decideResumeFreeze(st, tick(4000)) == FreezeStep::Hold && st.startMs == 4000, "clock back: the wait restarts from now");
    CHECK(decideResumeFreeze(st, tick(7000)) == FreezeStep::ReleaseTimeout, "and is still bounded");
    // The timeout is the server's (clamped) number.
    beginResumeFreeze(st, 10000);
    ResumeFreezeInputs shortWait = tick(10500);
    shortWait.timeoutMs = 500;
    CHECK(decideResumeFreeze(st, shortWait) == FreezeStep::ReleaseTimeout, "a 500 ms wait");

    CHECK(freezeReleases(FreezeStep::ReleaseSnapshot) && freezeReleases(FreezeStep::ReleaseTimeout) && freezeReleases(FreezeStep::ReleaseOff)
              && !freezeReleases(FreezeStep::Hold) && !freezeReleases(FreezeStep::HoldReask) && !freezeReleases(FreezeStep::NotFrozen), "which steps release");

    // Thaw: a decision runs before the overdue 1 s tick did.
    CHECK(!thawDetected(10000, -1, 1000), "no tick yet: no thaw");
    CHECK(!thawDetected(10000, 9000, 1000) && !thawDetected(12999, 10000, 1000), "a tick up to 3 s old is not a thaw (period + 2 s slack)");
    CHECK(thawDetected(13001, 10000, 1000), "more than that is");
    CHECK(!thawDetected(5000, 10000, 1000), "the clock went back: not a thaw");
}

int main()
{
    tableAndClamps();
    planBuilder();
    statusBlock();
    consume();
    resumeFreeze();
    std::printf("\n%d/%d ok\n", total - failures, total);
    if (failures) {
        std::printf("tunnel_watch_check: %d FAILED\n", failures);
        return 1;
    }
    std::printf("tunnel_watch_check: OK\n");
    return 0;
}
