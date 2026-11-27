// AVPN (plan v3 step 5): checks of the whoami verdict (WhoamiVerdict.h). Build/run: tests/build_whoami_verdict.sh.
//
// The verdict decides whether a freshly raised tunnel gets "Connected" with the "data flows" mark,
// moves to the next path of the same attempt, stays as it is, or hands the decision to the existing
// generate_204 check (tiebreak). A false NoData/BypassVpn sends a healthy user through the failover
// chain, a false Works shows a green mark on a dead path - both directions are pinned below.
#include <QDir>
#include <QFile>
#include <QSettings>
#include "../WhoamiVerdict.h"

#include <QCryptographicHash>
#include <cstdio>

static int failures = 0;
static int total = 0;

#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        ++total;                                                                                   \
        if (cond) {                                                                                \
            std::printf("ok   - %s\n", msg);                                                       \
        } else {                                                                                   \
            std::printf("FAIL - %s\n", msg);                                                       \
            ++failures;                                                                            \
        }                                                                                          \
    } while (0)

using avpn::WhoamiObservation;
using avpn::WhoamiStep;
using avpn::WhoamiVerdict;

static QByteArray sha(const QByteArray &body)
{
    return QCryptographicHash::hash(body, QCryptographicHash::Sha256).toHex();
}

// A healthy, complete 128 KiB answer from node 11 for nonce "abc".
static WhoamiObservation good()
{
    const QByteArray body(128 * 1024, 'x');
    WhoamiObservation o;
    o.httpStatus = 200;
    o.complete = true;
    o.bytesReceived = body.size();
    o.bodySha256Hex = sha(body);
    o.headerSha256 = sha(body);
    o.sentNonce = "abc";
    o.headerNonce = "abc";
    o.nodeHeaderPresent = true;
    o.node = 11;
    return o;
}

// The body was cut by OUR timeout after `bytes` arrived (slow link or a stall).
static WhoamiObservation cutByOurTimeout(qint64 bytes)
{
    WhoamiObservation o = good();
    const QByteArray part(int(bytes), 'x');
    o.complete = false;
    o.timedOut = true;
    o.bytesReceived = bytes;
    o.bodySha256Hex = sha(part);
    return o;
}

int main()
{
    // --- verdict: works ---
    CHECK(avpn::whoamiVerdict(good()) == WhoamiVerdict::Works, "200 + whole body + our node -> works");
    {
        WhoamiObservation o = good();
        o.headerSha256 = o.headerSha256.toUpper();
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::Works, "sha256 compare is case-insensitive");
        o.headerNonce = " abc ";
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::Works, "header whitespace is not a mismatch");
    }
    {
        const QByteArray body(64 * 1024, 'y');
        WhoamiObservation o = good();
        o.bytesReceived = body.size();
        o.bodySha256Hex = sha(body);
        o.headerSha256 = sha(body);
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::Works, "64 KiB (contract minimum) -> works");
    }
    // review item 4: slow link - our own timeout cut the body after >= 16 KiB: data flows, slowly
    CHECK(avpn::whoamiVerdict(cutByOurTimeout(40 * 1024)) == WhoamiVerdict::Works,
          "slow link: 40 KiB then our timeout -> works (hash checked only on a complete body)");
    CHECK(avpn::whoamiVerdict(cutByOurTimeout(avpn::kWhoamiMinBodyBytes)) == WhoamiVerdict::Works,
          "slow link: exactly 16 KiB then our timeout -> works");
    {
        WhoamiObservation o = cutByOurTimeout(40 * 1024);
        o.node = 0;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::BypassVpn, "slow link past the VPN -> bypass");
        o = cutByOurTimeout(40 * 1024);
        o.headerNonce = "zzz";
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "slow link with a foreign nonce -> no data");
    }

    // --- verdict: no data ---
    CHECK(avpn::whoamiVerdict(cutByOurTimeout(5 * 1024)) == WhoamiVerdict::NoData,
          "headers came, body froze after 5 KiB, our timeout -> no data");
    CHECK(avpn::whoamiVerdict(cutByOurTimeout(avpn::kWhoamiMinBodyBytes - 1)) == WhoamiVerdict::NoData,
          "16 KiB - 1 then our timeout -> no data");
    {
        WhoamiObservation o = cutByOurTimeout(100 * 1024);
        o.timedOut = false; // cut by the path (reset), not by our clock
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "body cut by the path (not our timeout) -> no data");
    }
    {
        WhoamiObservation o = good();
        o.bytesReceived = 0;
        o.bodySha256Hex = sha(QByteArray());
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "complete 200 with an empty body -> no data");
    }
    {
        WhoamiObservation o = good();
        const QByteArray other(128 * 1024, 'z');
        o.bodySha256Hex = sha(other);
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "complete body, sha mismatch -> no data");
    }
    {
        WhoamiObservation o = good();
        o.headerSha256.clear();
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData,
              "complete 200 without X-Whoami-Sha256 (captive portal page) -> no data");
    }
    {
        WhoamiObservation o = good();
        o.headerNonce = "zzz";
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "foreign nonce echo (cached answer) -> no data");
        o.headerNonce.clear();
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "missing nonce echo -> no data");
        o = good();
        o.sentNonce.clear();
        o.headerNonce.clear();
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "no nonce sent -> never works");
    }
    {
        WhoamiObservation o = cutByOurTimeout(1000);
        o.node = 0;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::NoData, "short body wins over node 0 (data first)");
    }

    // --- verdict: bypass ---
    {
        WhoamiObservation o = good();
        o.node = 0;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::BypassVpn, "whole body + node 0 -> past the VPN");
    }

    // --- verdict: check limited only for 429 / 404 (review item 3) ---
    {
        WhoamiObservation o = good();
        o.httpStatus = 429;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::CheckLimited, "429 rate limit -> check limited");
        o.httpStatus = 404;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::CheckLimited, "404 feature off -> check limited");
    }

    // --- verdict: inconclusive -> generate_204 tiebreak ---
    {
        WhoamiObservation none;
        CHECK(avpn::whoamiVerdict(none) == WhoamiVerdict::Inconclusive,
              "no HTTP answer at all -> inconclusive (tiebreak)");
        WhoamiObservation noneTimedOut;
        noneTimedOut.timedOut = true;
        CHECK(avpn::whoamiVerdict(noneTimedOut) == WhoamiVerdict::Inconclusive,
              "our timeout before the headers -> inconclusive (tiebreak)");
        WhoamiObservation o = good();
        for (int code : {400, 401, 500, 502, 204, 301}) {
            o.httpStatus = code;
            CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::Inconclusive,
                  qPrintable(QStringLiteral("HTTP %1 -> inconclusive (tiebreak)").arg(code)));
        }
        o = good();
        o.nodeHeaderPresent = false;
        o.node = -1;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::Inconclusive, "200 without X-Whoami-Node -> inconclusive");
        o.nodeHeaderPresent = true;
        o.node = -1;
        CHECK(avpn::whoamiVerdict(o) == WhoamiVerdict::Inconclusive, "garbage X-Whoami-Node -> inconclusive");
    }
    CHECK(avpn::whoamiTiebreakVerdict(true, 2) == WhoamiVerdict::CheckLimited,
          "tiebreak: generate_204 passed -> check limited (Connected, no green mark)");
    CHECK(avpn::whoamiTiebreakVerdict(false, 2) == WhoamiVerdict::NoData,
          "tiebreak: generate_204 failed too -> no data (next path)");
    // N2: the tiebreak ran out of budget without one request ever sent (app suspended, timers fired
    // late on return): no evidence - no verdict, never NoData.
    CHECK(avpn::whoamiTiebreakVerdict(false, 0) == WhoamiVerdict::CheckLimited,
          "tiebreak: zero budget and zero requests sent -> check limited, not no data");

    // --- N2: the attempt gate - budget already spent before any request ---
    {
        CHECK(avpn::whoamiAttemptGate(0, 5000, 9000) == avpn::WhoamiGate::Send, "budget left -> send whoami");
        CHECK(avpn::whoamiAttemptGate(1, 500, 4000) == avpn::WhoamiGate::Tiebreak,
              "whoami budget spent, verify budget left -> tiebreak");
        CHECK(avpn::whoamiAttemptGate(0, 500, 4000) == avpn::WhoamiGate::Tiebreak,
              "nothing sent yet, generate_204 still has budget -> tiebreak");
        CHECK(avpn::whoamiAttemptGate(0, -20000, -12000) == avpn::WhoamiGate::NoEvidence,
              "elapsed >= budget at verification start, no request sent -> no evidence (limited)");
        CHECK(avpn::whoamiAttemptGate(0, -7200, 0) == avpn::WhoamiGate::NoEvidence,
              "verify budget exactly spent, no request -> no evidence");
        CHECK(avpn::whoamiAttemptGate(1, -1000, -500) == avpn::WhoamiGate::Tiebreak,
              "a request was sent -> the tiebreak decides (its own guard)");
        // no evidence must neither fail the path nor erase the network memory
        CHECK(!avpn::whoamiFailsPath(avpn::whoamiTiebreakVerdict(false, 0)),
              "no-evidence result does not move to the next path / does not forget the memory");
    }

    // --- N2 leftover: the request's timer fired late = the app was suspended, not a dead path ---
    {
        const qint64 scheduled = 6400; // whoami timeout armed with 6.4 s
        // on-time timer: the existing behaviour (no data / tiebreak stays as it was)
        CHECK(!avpn::timerFiredLate(scheduled + 50, scheduled), "timer on time -> not late");
        CHECK(!avpn::timerFiredLate(scheduled + avpn::kWhoamiLateTimerSlackMs, scheduled), "within 2 s slack -> not late");
        CHECK(avpn::timerFiredLate(scheduled + avpn::kWhoamiLateTimerSlackMs + 1, scheduled), "beyond 2 s slack -> late");
        // whoami: cut before the headers, timer late -> no evidence
        WhoamiObservation none;
        none.timedOut = true;
        CHECK(avpn::whoamiCutBySuspension(avpn::whoamiVerdict(none), none, 60000, scheduled),
              "no answer, timer 54 s late -> suspended (limited, no request counted)");
        CHECK(!avpn::whoamiCutBySuspension(avpn::whoamiVerdict(none), none, scheduled + 30, scheduled),
              "no answer, timer on time -> the existing tiebreak");
        // whoami: headers came, body < 16 KiB, timer late -> no evidence (was: no data)
        WhoamiObservation part = cutByOurTimeout(5 * 1024);
        CHECK(avpn::whoamiVerdict(part) == WhoamiVerdict::NoData, "control: < 16 KiB is no data");
        CHECK(avpn::whoamiCutBySuspension(avpn::whoamiVerdict(part), part, 60000, scheduled),
              "< 16 KiB with a late timer -> suspended, not no data");
        CHECK(!avpn::whoamiCutBySuspension(avpn::whoamiVerdict(part), part, scheduled + 10, scheduled),
              "< 16 KiB with an on-time timer -> no data as before");
        // evidence survives a late timer: >= 16 KiB arrived (works), a full answer, a full bypass
        WhoamiObservation slow = cutByOurTimeout(40 * 1024);
        CHECK(!avpn::whoamiCutBySuspension(avpn::whoamiVerdict(slow), slow, 60000, scheduled),
              ">= 16 KiB then a late timer -> still works (data did flow)");
        WhoamiObservation full = good();
        CHECK(!avpn::whoamiCutBySuspension(avpn::whoamiVerdict(full), full, 60000, scheduled),
              "a complete answer is evidence whatever the clock says");
        WhoamiObservation limited = good();
        limited.httpStatus = 429;
        limited.complete = false;
        CHECK(!avpn::whoamiCutBySuspension(avpn::whoamiVerdict(limited), limited, 60000, scheduled),
              "a 429 that arrived is an answer, not a suspension cut");
        // the suspended result is limited: no next path, no forget, no streak
        CHECK(!avpn::whoamiFailsPath(WhoamiVerdict::CheckLimited)
                  && avpn::whoamiAction(WhoamiVerdict::CheckLimited, true, true) == avpn::WhoamiAction::ConnectUnproven,
              "suspended -> Connected without the mark on both transports (verifyInconclusive)");
    }

    // --- S3 (device round 5): the request is judged by progress, not by a hard cut ---
    {
        CHECK(!avpn::whoamiProgressCut(1500, 0, -1, 1600), "no first byte yet, within its limit: runs");
        CHECK(avpn::whoamiProgressCut(1700, 0, -1, 1600), "no first byte past its limit: cut");
        CHECK(!avpn::whoamiProgressCut(2600, 0, 2400, 1600), "bytes still arriving past 1.6 s: runs (works, slow)");
        CHECK(avpn::whoamiProgressCut(3500, 0, 2400, 1600), "bytes stopped for over a second: cut");
    }
    // --- N1: what each verdict does; xray never connects on a bare 429/404 ---
    {
        using avpn::WhoamiAction;
        CHECK(avpn::whoamiAction(WhoamiVerdict::Works, false, false) == WhoamiAction::Succeed, "awg works -> succeed");
        CHECK(avpn::whoamiAction(WhoamiVerdict::Works, true, false) == WhoamiAction::Succeed, "xray works -> succeed");
        CHECK(avpn::whoamiAction(WhoamiVerdict::NoData, true, false) == WhoamiAction::FailPath, "no data -> next path");
        CHECK(avpn::whoamiAction(WhoamiVerdict::BypassVpn, false, true) == WhoamiAction::FailPath, "bypass -> next path");
        CHECK(avpn::whoamiAction(WhoamiVerdict::CheckLimited, false, false) == WhoamiAction::Tiebreak,
              "awg 429/404 -> generate_204 tiebreak first (review E7 of 18.11: not attributable to the tunnel)");
        CHECK(avpn::whoamiAction(WhoamiVerdict::CheckLimited, true, false) == WhoamiAction::Tiebreak,
              "xray 429/404 -> generate_204 tiebreak first (Connected only after a probe)");
        CHECK(avpn::whoamiAction(WhoamiVerdict::CheckLimited, true, true) == WhoamiAction::ConnectUnproven,
              "xray after the tiebreak passed -> Connected without the mark (no second tiebreak)");
        CHECK(avpn::whoamiAction(WhoamiVerdict::Inconclusive, false, false) == WhoamiAction::Tiebreak,
              "awg inconclusive -> tiebreak");
        CHECK(avpn::whoamiAction(WhoamiVerdict::Inconclusive, true, false) == WhoamiAction::Tiebreak,
              "xray inconclusive -> tiebreak");
        CHECK(avpn::whoamiAction(WhoamiVerdict::Inconclusive, true, true) == WhoamiAction::ConnectUnproven,
              "inconclusive after the tiebreak cannot loop");
        CHECK(avpn::whoamiAction(avpn::whoamiTiebreakVerdict(true, 1), true, true) == WhoamiAction::ConnectUnproven,
              "xray 429 then 204 passed -> Connected without the mark");
        CHECK(avpn::whoamiAction(avpn::whoamiTiebreakVerdict(false, 2), true, true) == WhoamiAction::FailPath,
              "xray 429 then 204 failed -> next path");
    }

    // --- next step: retry / tiebreak / finish (review items 3 and 7; floor 19.11 - the shared spacing) ---
    {
        const qint64 plenty = 5000;
        WhoamiObservation none;            // no HTTP answer, no byte (no route / DNS yet / refused / reset)
        WhoamiObservation bypass = good(); // answered by the physical path
        bypass.node = 0;
        WhoamiObservation answered502;
        answered502.httpStatus = 502;
        WhoamiObservation limited;
        limited.httpStatus = 429;
        WhoamiObservation stalled = good();
        stalled.bytesReceived = 5 * 1024;
        stalled.complete = false;
        CHECK(avpn::whoamiNotYet(none) && !avpn::whoamiNotYet(bypass) && !avpn::whoamiNotYet(answered502),
              "not yet = no HTTP answer and no byte");
        avpn::WhoamiNext n = avpn::whoamiNext(WhoamiVerdict::Inconclusive, none, 0, 0, plenty);
        CHECK(n.step == WhoamiStep::Retry && n.delayMs == 300, "first try got nothing -> retry after 300 ms (not 1 s)");
        n = avpn::whoamiNext(WhoamiVerdict::Inconclusive, none, 0, 1, plenty);
        CHECK(n.step == WhoamiStep::Retry && n.delayMs == 600, "second empty try -> retry after 600 ms");
        n = avpn::whoamiNext(WhoamiVerdict::Inconclusive, none, 0, 2, plenty);
        CHECK(n.step == WhoamiStep::Retry && n.delayMs == 1200,
              "empty tries do not hit the answered-request cap - the budget bounds them");
        CHECK(avpn::whoamiNext(WhoamiVerdict::Inconclusive, none, 0, 0, 300 + avpn::kWhoamiMinAttemptMs - 1).step
                  == WhoamiStep::Tiebreak,
              "no answer, no room for the spacing + one attempt -> generate_204 tiebreak");
        CHECK(avpn::whoamiNext(WhoamiVerdict::Inconclusive, none, 0, 0, 300 + avpn::kWhoamiMinAttemptMs).step
                  == WhoamiStep::Retry,
              "no answer, exactly spacing + one attempt left -> retry");
        n = avpn::whoamiNext(WhoamiVerdict::BypassVpn, bypass, 1, 0, plenty);
        CHECK(n.step == WhoamiStep::Retry && n.delayMs == 300,
              "first bypass answer -> one retry on the short spacing (routes may not be applied yet)");
        CHECK(avpn::whoamiNext(WhoamiVerdict::BypassVpn, bypass, 2, 1, plenty).step == WhoamiStep::Finish,
              "second bypass answer -> bypass is final (answered cap)");
        CHECK(avpn::whoamiNext(WhoamiVerdict::BypassVpn, bypass, 1, 2, plenty).step == WhoamiStep::Retry,
              "bypass after empty tries: only answered tries count toward the cap");
        CHECK(avpn::whoamiNext(WhoamiVerdict::BypassVpn, bypass, 1, 0, avpn::kWhoamiMinAttemptMs).step
                  == WhoamiStep::Finish,
              "bypass: budget for an attempt but not for the spacing + attempt -> final (no doomed retry)");
        CHECK(avpn::whoamiNext(WhoamiVerdict::Inconclusive, answered502, 1, 0, plenty).step == WhoamiStep::Tiebreak,
              "an HTTP answer that decides nothing (502) -> tiebreak, no retry");
        CHECK(avpn::whoamiNext(WhoamiVerdict::CheckLimited, limited, 1, 0, plenty).step == WhoamiStep::Finish,
              "429 is never retried (rate limit)");
        CHECK(avpn::whoamiNext(WhoamiVerdict::NoData, stalled, 1, 0, plenty).step == WhoamiStep::Finish,
              "a stalled 200 is a verdict, not a retry");
        CHECK(avpn::whoamiNext(WhoamiVerdict::Works, good(), 1, 0, plenty).step == WhoamiStep::Finish, "works is final");
        CHECK(avpn::whoamiNext(WhoamiVerdict::Inconclusive, none, 0, 0, plenty).delayMs
                  == avpn::decideDataCheckRetry(true, 0, plenty).delayMs,
              "one spacing for every data check (DataCheckRetry.h, the provider check uses it too)");
        // Phone 26.11 (Android, split routes): a try sent before the system made our VPN network the app's default -
        // a cut transfer (the measured "whoami no data" at ~1.4 s), a short body or "past the VPN" - is "not yet"
        n = avpn::whoamiNext(WhoamiVerdict::NoData, stalled, 1, 0, plenty, /*sentBeforeUsable=*/true);
        CHECK(n.step == WhoamiStep::Retry && n.delayMs == 300, "a cut before the network was usable -> retry, not no-data");
        CHECK(avpn::whoamiNext(WhoamiVerdict::BypassVpn, bypass, 2, 1, plenty, true).step == WhoamiStep::Retry,
              "past the VPN before the network was usable -> not yet (not the answered cap)");
        CHECK(avpn::whoamiNext(WhoamiVerdict::NoData, stalled, 1, 0, 300 + avpn::kWhoamiMinAttemptMs - 1, true).step
                  == WhoamiStep::Tiebreak,
              "before usable, no room for another try -> the tiebreak, never a no-data verdict");
        CHECK(avpn::whoamiNext(WhoamiVerdict::Works, good(), 1, 0, plenty, true).step == WhoamiStep::Finish,
              "works is final even if sent early");
        CHECK(avpn::whoamiNext(WhoamiVerdict::NoData, stalled, 1, 0, plenty, /*sentBeforeUsable=*/false).step
                  == WhoamiStep::Finish,
              "a cut on a usable network is still the path's verdict");
        // Round 60 review: the step's verdict is what the facade finishes with (it executes the step, finishWhoami ->
        // whoamiAction). An early try {nothing, a cut 200, past the VPN} x {retry fits, does not fit}: never a final
        // NoData / BypassVpn - a retry, or the tiebreak (Inconclusive -> generate_204).
        {
            struct Early { WhoamiVerdict v; WhoamiObservation o; const char *what; };
            const Early early[] = {{WhoamiVerdict::Inconclusive, none, "nothing"},
                                   {WhoamiVerdict::NoData, stalled, "cut 200"},
                                   {WhoamiVerdict::BypassVpn, bypass, "past the VPN"}};
            for (const Early &e : early) {
                for (const qint64 budgetLeft : {plenty, qint64(300 + avpn::kWhoamiMinAttemptMs - 1)}) {
                    const avpn::WhoamiNext x = avpn::whoamiNext(e.v, e.o, 1, 0, budgetLeft, /*sentBeforeUsable=*/true);
                    const bool fits = budgetLeft == plenty;
                    CHECK(x.step == (fits ? WhoamiStep::Retry : WhoamiStep::Tiebreak), e.what);
                    CHECK(x.verdict != WhoamiVerdict::NoData && x.verdict != WhoamiVerdict::BypassVpn,
                          "an early try is never a final no-data / bypass");
                    if (!fits)
                        CHECK(x.verdict == WhoamiVerdict::Inconclusive
                                  && avpn::whoamiAction(x.verdict, false, false) == avpn::WhoamiAction::Tiebreak,
                              "no retry left -> the same tiebreak the not-yet case reaches");
                }
            }
            // a try sent after the network was usable keeps today's rules exactly (and so does every platform but
            // Android, where sentBeforeUsable is always false)
            for (const bool usableArg : {false}) {
                Q_UNUSED(usableArg)
                const avpn::WhoamiNext cut = avpn::whoamiNext(WhoamiVerdict::NoData, stalled, 1, 0, plenty, false);
                CHECK(cut.step == WhoamiStep::Finish && cut.verdict == WhoamiVerdict::NoData, "a cut on a usable network is no-data");
                const avpn::WhoamiNext byp = avpn::whoamiNext(WhoamiVerdict::BypassVpn, bypass, 2, 1, plenty, false);
                CHECK(byp.step == WhoamiStep::Finish && byp.verdict == WhoamiVerdict::BypassVpn, "second bypass is final");
                const avpn::WhoamiNext byp1 = avpn::whoamiNext(WhoamiVerdict::BypassVpn, bypass, 1, 0, plenty, false);
                CHECK(byp1.step == WhoamiStep::Retry, "first bypass is retried");
                const avpn::WhoamiNext nothingLeft =
                    avpn::whoamiNext(WhoamiVerdict::Inconclusive, none, 0, 0, 300 + avpn::kWhoamiMinAttemptMs - 1, false);
                CHECK(nothingLeft.step == WhoamiStep::Tiebreak && nothingLeft.verdict == WhoamiVerdict::Inconclusive,
                      "nothing, no room -> the tiebreak, as before");
                const avpn::WhoamiNext w = avpn::whoamiNext(WhoamiVerdict::Works, good(), 1, 0, plenty, false);
                CHECK(w.step == WhoamiStep::Finish && w.verdict == WhoamiVerdict::Works, "works is final");
                const avpn::WhoamiNext lim = avpn::whoamiNext(WhoamiVerdict::CheckLimited, limited, 1, 0, plenty, false);
                CHECK(lim.step == WhoamiStep::Finish && lim.verdict == WhoamiVerdict::CheckLimited, "429 keeps its verdict");
                const avpn::WhoamiNext inc = avpn::whoamiNext(WhoamiVerdict::Inconclusive, answered502, 1, 0, plenty, false);
                CHECK(inc.step == WhoamiStep::Tiebreak && inc.verdict == WhoamiVerdict::Inconclusive, "502 -> tiebreak");
            }
        }
        // the wait for usability stays inside the attempt owner's grace (dataCheckMs + checkGraceMs backstop)
        CHECK(avpn::whoamiUsableWaitMs(1500) == 1200 && avpn::whoamiUsableWaitMs(200) == 0,
              "the wait ends 300 ms inside the owner's grace; no grace, no wait");
    }

    // --- floor 19.11: the whoami loop as the facade runs it, on a fake clock (AvpnEngineQml::whoamiAttempt) ---
    // The first request goes at 0 ms after the tunnel is up (it went at 800 ms); a fresh tunnel that does not route
    // yet costs only the short spacing, and a tunnel that routes at once costs nothing.
    {
        struct Run {
            WhoamiVerdict verdict = WhoamiVerdict::Inconclusive;
            WhoamiStep last = WhoamiStep::Finish;
            int requests = 0;
            qint64 decidedAtMs = 0;
        };
        // routesAtMs: from then on a request reaches our exit; before it, an instant connection error.
        const auto run = [](qint64 routesAtMs, qint64 transferMs, int checkBudgetMs) {
            Run r;
            const qint64 whoamiBudget = avpn::whoamiBudgetMs(checkBudgetMs);
            qint64 t = 0;
            int answered = 0;
            for (int guard = 0; guard < 20; ++guard) {
                if (avpn::whoamiAttemptGate(r.requests, whoamiBudget - t, checkBudgetMs - t) != avpn::WhoamiGate::Send) {
                    r.last = WhoamiStep::Tiebreak;
                    break;
                }
                ++r.requests;
                WhoamiObservation o;
                if (t >= routesAtMs) {
                    o = good();
                    t += transferMs;
                } else {
                    t += 5; // HostNotFound / unreachable: no answer, no byte
                }
                const WhoamiVerdict v = avpn::whoamiVerdict(o);
                if (!avpn::whoamiNotYet(o))
                    ++answered;
                const avpn::WhoamiNext next = avpn::whoamiNext(v, o, answered, r.requests - 1, whoamiBudget - t);
                r.verdict = v;
                r.last = next.step;
                if (next.step != WhoamiStep::Retry)
                    break;
                t += next.delayMs;
            }
            r.decidedAtMs = t;
            return r;
        };
        Run r = run(0, 900, 4000);
        CHECK(r.verdict == WhoamiVerdict::Works && r.requests == 1 && r.decidedAtMs == 900,
              "routes ready at Connected: works one transfer after Connected (was 800 + transfer)");
        r = run(200, 900, 4000);
        CHECK(r.verdict == WhoamiVerdict::Works && r.requests == 2 && r.decidedAtMs == 5 + 300 + 900,
              "routes 200 ms late: one empty try, works at ~1.2 s - still earlier than the old 800 ms wait + transfer");
        r = run(700, 900, 4000);
        CHECK(r.verdict == WhoamiVerdict::Works && r.requests == 3 && r.decidedAtMs == 5 + 300 + 5 + 600 + 900,
              "routes 700 ms late (the old wait's worst case): works within the default 4 s check");
        r = run(100000, 900, 4000);
        CHECK(r.verdict == WhoamiVerdict::Inconclusive && r.last == WhoamiStep::Tiebreak && r.decidedAtMs < 2400,
              "never routes: empty tries end in the generate_204 tiebreak inside the whoami share");
        r = run(100000, 900, 1500);
        CHECK(r.last == WhoamiStep::Tiebreak && r.requests == 0,
              "the 1.5 s floor budget: the whoami share (900 ms) is below one attempt -> tiebreak (as before)");
    }
    // whoami gets at most ~60 % of the verify budget, the rest is the tiebreak's (review item 3)
    CHECK(avpn::whoamiBudgetMs(12000) == 7200, "whoami budget = 60 % of 12 s");
    CHECK(avpn::whoamiBudgetMs(3000) == 1800, "whoami budget = 60 % of the 3 s floor");
    CHECK(12000 - avpn::whoamiBudgetMs(12000) >= 4000, "at least 4 s left for generate_204 at the default budget");
    CHECK(avpn::whoamiBudgetMs(3000) >= avpn::kWhoamiMinAttemptMs + 300 + 5,
          "at a 3 s budget one empty try and one retry fit (no 800 ms settle delay any more)");

    // --- helpers ---
    CHECK(avpn::whoamiFailsPath(WhoamiVerdict::NoData) && avpn::whoamiFailsPath(WhoamiVerdict::BypassVpn),
          "no data / bypass move to the next path");
    CHECK(!avpn::whoamiFailsPath(WhoamiVerdict::Works) && !avpn::whoamiFailsPath(WhoamiVerdict::CheckLimited)
              && !avpn::whoamiFailsPath(WhoamiVerdict::Inconclusive),
          "works / limited / inconclusive keep the path");
    {
        bool present = false;
        CHECK(avpn::parseWhoamiNode("11", &present) == 11 && present, "node header 11");
        CHECK(avpn::parseWhoamiNode(" 0 ", &present) == 0 && present, "node header 0");
        CHECK(avpn::parseWhoamiNode("", &present) == -1 && !present, "node header missing");
        CHECK(avpn::parseWhoamiNode("eleven", &present) == -1 && present, "node header garbage");
        CHECK(avpn::parseWhoamiNode("-3", &present) == -1 && present, "negative node header");
    }
    CHECK(avpn::whoamiVerdictName(WhoamiVerdict::Works) == QLatin1String("works")
              && avpn::whoamiVerdictName(WhoamiVerdict::NoData) == QLatin1String("no_data")
              && avpn::whoamiVerdictName(WhoamiVerdict::BypassVpn) == QLatin1String("bypass")
              && avpn::whoamiVerdictName(WhoamiVerdict::CheckLimited) == QLatin1String("limited")
              && avpn::whoamiVerdictName(WhoamiVerdict::Inconclusive) == QLatin1String("inconclusive"),
          "verdict names (QML pathCheck contract)");
    // The failover reason must not be a health-DEAD reason: the ladder goes straight to step 3.
    CHECK(avpn::whoamiFailoverReason(WhoamiVerdict::NoData) != QLatin1String("dead (failover)")
              && avpn::whoamiFailoverReason(WhoamiVerdict::BypassVpn) != QLatin1String("dead (failover)"),
          "failover reason skips rebind/re-up of the same node");

    // --- whoami edge (#8): xray -> always the alternate edge, awg -> the active API address ---
    {
        const QString api = QStringLiteral("https://api.tribevpn.com");
        const QString alt = QStringLiteral("https://vpn.wellwon.hk");
        CHECK(avpn::whoamiBaseUrl(api, /*xray=*/true, /*devBackend=*/false) == alt,
              "xray: whoami never goes to api.tribevpn.com (= the xray entry, routed past the tunnel)");
        CHECK(avpn::whoamiBaseUrl(alt, true, false) == alt, "xray: already on the alternate edge -> it");
        CHECK(avpn::whoamiBaseUrl(api, false, false) == api, "awg: the active API address");
        CHECK(avpn::whoamiBaseUrl(alt, false, false) == alt, "awg: the active API address (edge-walked)");
        CHECK(avpn::whoamiBaseUrl(QStringLiteral("https://dev.example:8443"), true, true)
                  == QLatin1String("https://dev.example:8443"),
              "xray on a dev backend (AVPN_API_URL) -> the dev base, not the prod edge");
        CHECK(QString::fromLatin1(avpn::kWhoamiXrayEdge) == alt, "alternate edge = the baked vpn.wellwon.hk");

        // The live probe (QualityProbe: card ms, ONLINE, the Xray death detector feedProbeResult) pings
        // the edge whoami uses: on Xray api.tribevpn.com is the entry host, routed outside the tunnel,
        // so a ping there answers even when the Xray exit is dead (review of 138).
        const QString ping = QStringLiteral("/v1/ping");
        const QString dev = QStringLiteral("https://dev.example:8443");
        CHECK(avpn::liveProbePingUrl(api, true, false) == avpn::whoamiBaseUrl(api, true, false) + ping
                  && avpn::liveProbePingUrl(api, true, false) == alt + ping,
              "xray: live probe pings the whoami edge, not api.tribevpn.com (= the xray entry)");
        CHECK(avpn::liveProbePingUrl(alt, true, false) == alt + ping, "xray: already on the alternate edge -> it");
        CHECK(avpn::liveProbePingUrl(api, false, false) == api + ping, "awg: live probe keeps the active API address");
        CHECK(avpn::liveProbePingUrl(alt, false, false) == alt + ping,
              "awg: live probe keeps the active API address (edge-walked)");
        CHECK(avpn::liveProbePingUrl(dev, true, true) == avpn::whoamiBaseUrl(dev, true, true) + ping
                  && avpn::liveProbePingUrl(dev, true, true) == dev + ping,
              "xray on a dev backend (AVPN_API_URL) -> the dev base, as whoami");
    }

    std::printf("%s: %d/%d checks\n", failures ? "whoami_verdict_check: FAILED" : "whoami_verdict_check: OK",
                total - failures, total);
    return failures ? 1 : 0;
}
