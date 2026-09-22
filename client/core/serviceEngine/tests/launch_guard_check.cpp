// AVPN (macOS self-update v2): юнит ЧИСТОЙ логики LaunchGuard.h (namespace launchguard) —
// pending round-trip, решение на старте (attempts / crash-loop / стейл-запись), отчёт отката.
// Собирается standalone (только QtCore), как crash_guard_check. Запуск: tests/build_launch_guard.sh.
#define LAUNCHGUARD_PURE_LOGIC_ONLY
#include "../LaunchGuard.h"

#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; }           \
        else         { std::printf("ok:   %s\n", msg); }                     \
    } while (0)

int main()
{
    using namespace avpn::launchguard;

    // ── pending round-trip ─────────────────────────────────────────────────────────────────
    {
        Pending p; p.from = "5.1.84"; p.to = "5.1.85"; p.app = "/Applications/Tribe VPN.app";
        p.mode = "auto"; p.attempts = 1; p.installedAt = 1758540000;
        const Pending q = parsePending(serializePending(p));
        CHECK(q.valid && q.from == "5.1.84" && q.to == "5.1.85" && q.app == p.app, "pending round-trip fields");
        CHECK(q.mode == "auto" && q.attempts == 1 && q.installedAt == 1758540000, "pending round-trip meta");
        CHECK(!parsePending("").valid && !parsePending("{not json").valid, "empty/broken pending invalid");
        CHECK(!parsePending(R"({"from":"5.1.84"})").valid, "pending without 'to' invalid");
        CHECK(parsePending(R"({"to":"5.1.85"})").mode == "manual", "mode defaults to manual");
    }

    // ── decideOnStart ──────────────────────────────────────────────────────────────────────
    {
        Pending none;
        CHECK(decideOnStart(none, "5.1.85", "").verdict == StartVerdict::NotPending, "no pending => NotPending");

        Pending p; p.valid = true; p.to = "5.1.85"; p.app = "/Applications/Tribe VPN.app"; p.attempts = 0;
        StartDecision d1 = decideOnStart(p, "5.1.85", p.app);
        CHECK(d1.verdict == StartVerdict::Continue && d1.pending.attempts == 1, "first start => Continue, attempts 1");
        StartDecision d2 = decideOnStart(d1.pending, "5.1.85", p.app);
        CHECK(d2.verdict == StartVerdict::Continue && d2.pending.attempts == 2, "second start => Continue, attempts 2");
        StartDecision d3 = decideOnStart(d2.pending, "5.1.85", p.app);
        CHECK(d3.verdict == StartVerdict::Rollback && d3.pending.attempts == 3, "third start => Rollback (crash-loop)");
        CHECK(decideOnStart(p, "5.1.85", p.app, 1).verdict == StartVerdict::Rollback, "maxAttempts=1 => immediate Rollback");

        StartDecision stale = decideOnStart(p, "5.1.84", p.app);
        CHECK(stale.verdict == StartVerdict::NotPending && stale.clearPending, "other running version => stale, clear");
        StartDecision other = decideOnStart(p, "5.1.85", "/Users/dev/build/TribeVPN.app");
        CHECK(other.verdict == StartVerdict::NotPending && other.clearPending, "other bundle path => stale, clear");
        Pending noApp = p; noApp.app.clear();
        CHECK(decideOnStart(noApp, "5.1.85", "/Applications/Tribe VPN.app").verdict == StartVerdict::Continue,
              "pending without app path still applies");
        CHECK(decideOnStart(p, "5.1.85", "").verdict == StartVerdict::Continue, "empty appPath skips path check");
        CHECK(decideOnStart(p, "5.1.85.114", p.app).verdict == StartVerdict::Continue,
              "4-part APP_VERSION matches 3-part pending.to");
        CHECK(marketingVersion("5.1.85.114") == "5.1.85" && marketingVersion("5.1.85") == "5.1.85", "marketingVersion");
    }

    // ── rollback report ────────────────────────────────────────────────────────────────────
    {
        const RollbackReport r = parseRollbackReport(
            R"({"from":"5.1.85","to":"5.1.84","reason":"watchdog","attempts":0,"mode":"auto","at":1758540100})");
        CHECK(r.valid && r.from == "5.1.85" && r.to == "5.1.84" && r.reason == "watchdog", "rollback report parses");
        CHECK(r.mode == "auto" && r.attempts == 0 && r.at == 1758540100, "rollback report meta");
        CHECK(!parseRollbackReport(R"({"to":"5.1.84"})").valid, "report without reason invalid");
        CHECK(!parseRollbackReport("").valid, "empty report invalid");

        const QJsonObject o = rollbackReportJson(r, "5.1.84.113", "macos", "27.0");
        CHECK(o.value("type").toString() == "crash" && o.value("subtype").toString() == "update_rollback",
              "server report is a crash/update_rollback");
        CHECK(o.value("schema").toInt() == 1 && o.value("phase").toString() == "launch", "server report schema/phase");
        CHECK(o.value("build").toString() == "5.1.84.113" && o.value("platform").toString() == "macos", "server report build/platform");
        CHECK(o.value("from").toString() == "5.1.85" && o.value("to").toString() == "5.1.84"
              && o.value("reason").toString() == "watchdog", "server report carries from/to/reason");

        CHECK(rollbackNoticeText(r).contains("5.1.85") && rollbackNoticeText(r).contains("5.1.84")
              && rollbackNoticeText(r).contains("не запустилась"), "notice names both versions");
        RollbackReport b = r; b.reason = "blocked";
        CHECK(rollbackNoticeText(b).contains("отозвана"), "blocked notice wording");
        CHECK(rollbackNoticeText(RollbackReport()).isEmpty(), "invalid report => no notice");
    }

    std::printf(g_fail ? "launchguard: %d FAIL\n" : "launchguard: OK\n", g_fail);
    return g_fail ? 1 : 0;
}
