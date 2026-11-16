// AVPN upstream nodes (plan provider-pool v2, D7/D9): the data-check verdict (UpstreamVerdict.h) and the
// policy-tier rule (UpstreamTierRule.h), with seeded property tests for the tier rule.
// Build/run: build_upstream_policy.sh
#include "../TuningStore.h"
#include "../UpstreamTierRule.h"
#include "../UpstreamVerdict.h"

#include <QCoreApplication>

#include <cstdio>
#include <random>

using namespace avpn;

static int g_fail = 0, g_total = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        ++g_total;                                                                                 \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                           \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

// --- verdict ------------------------------------------------------------------------------------------

// A clean, fast, complete check through a provider exit on another network.
static UpstreamCheckInput good()
{
    UpstreamCheckInput in;
    in.bytesRequested = in.bytesReceived = 131072;
    in.digestOk = true;
    in.elapsedMs = 900;
    in.ttfbMs = 300;
    in.maxStallMs = 100;
    in.egressClass = QStringLiteral("other");
    in.egressAsn = 64501;
    in.egressNetToken = QStringLiteral("net-b");
    in.accessAsn = 64500;
    in.accessNetToken = QStringLiteral("net-a");
    return in;
}

static bool is(const UpstreamVerdictResult &r, UpstreamVerdict v, const char *reason, bool passes)
{
    const bool ok = r.verdict == v && r.reason == QLatin1String(reason) && r.passes == passes;
    if (!ok)
        std::printf("   got %s/%s/%d, expected %s/%s/%d\n", upstreamVerdictName(r.verdict), qPrintable(r.reason),
                    int(r.passes), upstreamVerdictName(v), reason, int(passes));
    return ok;
}

static void verdict()
{
    CHECK(is(judgeUpstreamCheck(good()), UpstreamVerdict::Works, "verified_net_token", true));
    // Data rules.
    UpstreamCheckInput in = good();
    in.bytesRequested = 0;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NoData, "bad_request", false));
    in = good();
    in.bytesReceived = 0;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NoData, "no_first_byte", false));
    in = good();
    in.ttfbMs = 3001;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NoData, "ttfb_timeout", false));
    in.ttfbMs = 3000;
    CHECK(judgeUpstreamCheck(in).passes); // the limit itself is inside
    in = good();
    in.maxStallMs = 1501;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NoData, "stalled", false));
    in = good();
    in.bytesReceived = 131071;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NoData, "incomplete", false));
    in = good();
    in.bytesReceived = 131073;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NoData, "oversize", false));
    in = good();
    in.digestOk = false;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NoData, "digest_mismatch", false));
    in = good();
    in.elapsedMs = 5001;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NoData, "total_timeout", false));
    // A stalled transfer that never completed reads as stalled, not incomplete (the stall is the fact).
    in = good();
    in.bytesReceived = 16384;
    in.maxStallMs = 4000;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NoData, "stalled", false));
    // Not measured timings are not judged.
    in = good();
    in.ttfbMs = in.maxStallMs = in.elapsedMs = -1;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::Works, "verified_net_token", true));
    // Slow: complete, verified, past the soft time.
    in = good();
    in.elapsedMs = 3001;
    UpstreamVerdictResult r = judgeUpstreamCheck(in);
    CHECK(is(r, UpstreamVerdict::Slow, "slow", true) && r.slow && r.pathReason == QLatin1String("verified_net_token"));
    in.elapsedMs = 3000;
    CHECK(judgeUpstreamCheck(in).verdict == UpstreamVerdict::Works);

    // Path rules.
    in = good();
    in.egressNetToken = in.accessNetToken;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NotThroughProvider, "egress_is_access_net", false));
    in = good();
    in.egressAsn = in.accessAsn;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NotThroughProvider, "egress_is_access_asn", false));
    in.egressNetToken.clear();
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NotThroughProvider, "egress_is_access_asn", false));
    // tribe-node is impossible for an upstream node: never "works", whatever else is known.
    in = good();
    in.egressClass = QStringLiteral("tribe-node");
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NotThroughProvider, "egress_tribe_node", false));
    in.egressNetToken.clear();
    in.egressAsn = 0; // nothing else known: still not "unverifiable", still not a pass
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NotThroughProvider, "egress_tribe_node", false));
    // Positive proofs.
    in = good();
    in.egressNetToken.clear();
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::Works, "verified_asn", true));
    in.egressAsn = 0;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::Unverifiable, "unverifiable", true));
    in.egressClass = QStringLiteral("upstream-known");
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::Works, "verified_upstream_class", true));
    // b above c: an equal net token wins over the class.
    in = good();
    in.egressClass = QStringLiteral("upstream-known");
    in.egressNetToken = in.accessNetToken;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NotThroughProvider, "egress_is_access_net", false));
    // c above d: a provider's Russian exit in the user's own ASN, the exit known as upstream: passes
    // (tokens differ, and also when tokens are unknown).
    in = good();
    in.egressClass = QStringLiteral("upstream-known");
    in.egressAsn = in.accessAsn;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::Works, "verified_upstream_class", true));
    in.egressNetToken.clear();
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::Works, "verified_upstream_class", true));
    // d: the same equal ASN without the class is a leak, also when the tokens differ.
    in.egressClass = QStringLiteral("other");
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NotThroughProvider, "egress_is_access_asn", false));
    in.egressClass.clear();
    in.egressNetToken = QStringLiteral("net-b");
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NotThroughProvider, "egress_is_access_asn", false));
    // An equal ASN never becomes "unverifiable" or "verified_net_token".
    in.accessNetToken.clear();
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NotThroughProvider, "egress_is_access_asn", false));
    // Unverifiable: one side missing (each way), the strict switch decides.
    for (int side = 0; side < 4; ++side) {
        in = good();
        if (side == 0) { in.accessNetToken.clear(); in.accessAsn = 0; }
        if (side == 1) { in.egressNetToken.clear(); in.egressAsn = 0; }
        if (side == 2) { in.accessNetToken.clear(); in.egressAsn = 0; }
        if (side == 3) { in.egressNetToken.clear(); in.accessAsn = 0; }
        in.egressClass.clear();
        CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::Unverifiable, "unverifiable", true));
        in.strictUnverifiable = true;
        CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::Unverifiable, "unverifiable", false));
        in.elapsedMs = 4000;
        CHECK(judgeUpstreamCheck(in).slow && judgeUpstreamCheck(in).verdict == UpstreamVerdict::Unverifiable);
    }
    // An unknown class string is no evidence.
    in = good();
    in.egressClass = QStringLiteral("tribe-node-v2");
    in.egressNetToken.clear();
    in.egressAsn = 0;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::Unverifiable, "unverifiable", true));
    // Data failures win over every path fact.
    in = good();
    in.egressClass = QStringLiteral("tribe-node");
    in.digestOk = false;
    CHECK(judgeUpstreamCheck(in).reason == QLatin1String("digest_mismatch"));
    // Strict switch from the server.
    TuningStore::reset();
    CHECK(!upstreamUnverifiableStrictTuned());
    TuningStore::set({}, {{QStringLiteral("upstream_unverifiable_strict"), true}});
    CHECK(upstreamUnverifiableStrictTuned());
    TuningStore::reset();
}

// --- tier rule ----------------------------------------------------------------------------------------

static TierCandidate cand(const char *id, int tier, int rank = 0, bool eligible = true, double crowd = 0)
{
    TierCandidate c;
    c.id = QLatin1String(id);
    c.tier = tier;
    c.rank = rank;
    c.eligible = eligible;
    c.crowdScore = crowd;
    return c;
}

static void tierExamples()
{
    const QList<TierCandidate> pool{cand("own1", 0, 1), cand("own2", 0, 2), cand("own3", 0, 3),
                                    cand("a1", 1, 0), cand("a2", 1, 1), cand("b1", 2, 0)};
    const int cap = 10, k = 2;
    TierAttempt at;
    TierDecision d = decideOpenTiers(pool, at, k, cap);
    CHECK(d.maxOpenTier == 0 && d.openTiers == QList<int>({0}) && d.order == QStringList({"own1", "own2", "own3"}));
    at.failed << "own1";
    CHECK(decideOpenTiers(pool, at, k, cap).maxOpenTier == 0);           // 1 < min(2, 3)
    at.failed << "own2";
    d = decideOpenTiers(pool, at, k, cap);
    CHECK(d.maxOpenTier == 1 && d.order == QStringList({"own3", "a1", "a2"})); // K reached: tier 1 opens
    // A running try in tier 0 blocks tier 1.
    at.inFlight << "own3";
    CHECK(decideOpenTiers(pool, at, k, cap).maxOpenTier == 0);
    at.inFlight.clear();
    // Fresh own failures on this network count as defined failures.
    TierAttempt fresh;
    fresh.freshOwnFailure << "own1" << "own3";
    CHECK(decideOpenTiers(pool, fresh, k, cap).maxOpenTier == 1);
    CHECK(!decideOpenTiers(pool, fresh, k, cap).order.contains("own1"));
    // Tier 1 exhausted (both failed, size 2 = min(K, 2)) -> tier 2.
    at.failed << "a1";
    CHECK(decideOpenTiers(pool, at, k, cap).maxOpenTier == 1);
    at.failed << "a2";
    d = decideOpenTiers(pool, at, k, cap);
    CHECK(d.maxOpenTier == 2 && d.order == QStringList({"own3", "b1"}));
    // A tier of one: one failure exhausts it (min(K, 1)).
    QList<TierCandidate> small{cand("own", 0), cand("up", 1)};
    TierAttempt one;
    one.failed << "own";
    CHECK(decideOpenTiers(small, one, 6, cap).maxOpenTier == 1);
    // No eligible candidate in tier 0 -> tier 0 does not exist, tier 1 is the first.
    QList<TierCandidate> noOwn{cand("own", 0, 0, /*eligible=*/false), cand("up", 1)};
    CHECK(decideOpenTiers(noOwn, {}, k, cap).openTiers == QList<int>({1}));
    CHECK(decideOpenTiers({}, {}, k, cap).maxOpenTier == -1 && decideOpenTiers({}, {}, k, cap).order.isEmpty());
    // Gaps in tier numbers.
    QList<TierCandidate> gaps{cand("x", 0), cand("y", 3), cand("z", 7)};
    TierAttempt gx;
    gx.failed << "x";
    CHECK(decideOpenTiers(gaps, gx, k, cap).openTiers == QList<int>({0, 3}));
    // Crowd evidence and ranking never count: a terrible crowd score stays a candidate.
    QList<TierCandidate> crowd{cand("own1", 0, 0, true, -1e9), cand("own2", 0, 0, true, -1e9), cand("up", 1)};
    CHECK(decideOpenTiers(crowd, {}, k, cap).maxOpenTier == 0);
    // Last-known-good and ranking only inside the tier.
    QList<TierCandidate> lkg{cand("own1", 0, 5), cand("own2", 0, 1), cand("up1", 1, 0), cand("up2", 1, 9)};
    TierAttempt both;
    both.failed << "own1";
    d = decideOpenTiers(lkg, both, 1, cap, QStringLiteral("up2"));
    CHECK(d.order == QStringList({"own2", "up2", "up1"}));  // LKG first inside tier 1, never above tier 0
    d = decideOpenTiers(lkg, {}, 1, cap, QStringLiteral("up2"));
    CHECK(d.order == QStringList({"own2", "own1"}));        // tier 1 closed: the LKG is not even listed
    QList<TierCandidate> byCrowd{cand("p", 0, 0, true, 1), cand("q", 0, 0, true, 9)};
    CHECK(decideOpenTiers(byCrowd, {}, 1, cap).order == QStringList({"q", "p"}));
    // K clamp: strictly below the data-plane fail cap.
    CHECK(upstreamTierK(6, 4) == 3 && upstreamTierK(3, 4) == 3 && upstreamTierK(0, 4) == 1);
    CHECK(upstreamTierK(6, 1) == 1 && upstreamTierK(6, 0) == 1 && upstreamTierK(2, 10) == 2);
    TuningStore::reset();
    CHECK(upstreamTierKTuned(10) == 6 && upstreamTierKTuned(4) == 3);
    TuningStore::set({{QStringLiteral("upstream_tier_k"), 2}}, {});
    CHECK(upstreamTierKTuned(10) == 2);
    TuningStore::set({{QStringLiteral("upstream_tier_k"), -5}}, {});
    CHECK(upstreamTierKTuned(10) == 6);
    TuningStore::reset();
}

// Seeded random pools: the properties the picker relies on.
static void tierProperties()
{
    std::mt19937 rng(20261114);
    const auto rnd = [&rng](int n) { return int(rng() % unsigned(n)); };
    int checked = 0;
    for (int iter = 0; iter < 3000; ++iter) {
        QList<TierCandidate> pool;
        const int n = 1 + rnd(12);
        for (int i = 0; i < n; ++i)
            pool << cand(qPrintable(QStringLiteral("c%1").arg(i)), rnd(4), rnd(5), rnd(6) != 0, double(rnd(100)));
        TierAttempt at;
        for (const TierCandidate &c : pool) {
            const int f = rnd(5);
            if (f == 0) at.failed << c.id;
            else if (f == 1) at.freshOwnFailure << c.id;
            else if (f == 2) at.inFlight << c.id;
        }
        const int cap = 1 + rnd(8);
        const int k = rnd(10);
        const int kk = upstreamTierK(k, cap);
        const TierDecision d = decideOpenTiers(pool, at, k, cap);
        const auto failed = [&at](const QString &id) { return at.failed.contains(id) || at.freshOwnFailure.contains(id); };

        // P1: no higher tier is open while a lower one is not exhausted.
        for (int t : d.openTiers) {
            if (t == d.maxOpenTier)
                continue;
            int size = 0, failures = 0, open = 0;
            bool running = false;
            for (const TierCandidate &c : pool) {
                if (!c.eligible || c.tier != t) continue;
                ++size;
                if (failed(c.id)) ++failures;
                else { ++open; running = running || at.inFlight.contains(c.id); }
            }
            CHECK(open == 0 || (failures >= qMin(kk, size) && !running));
        }
        // P2: the lowest eligible tier is always open; open tiers are a prefix of the present tiers.
        int lowest = 1000;
        for (const TierCandidate &c : pool)
            if (c.eligible) lowest = qMin(lowest, c.tier);
        CHECK(lowest == 1000 ? d.maxOpenTier == -1 : (!d.openTiers.isEmpty() && d.openTiers.first() == lowest));
        // P3: the order holds only open-tier, eligible, not-failed candidates, by tier.
        int prevTier = -1;
        for (const QString &id : d.order) {
            const auto it = std::find_if(pool.begin(), pool.end(), [&id](const TierCandidate &c) { return c.id == id; });
            CHECK(it != pool.end() && it->eligible && !failed(id) && it->tier <= d.maxOpenTier && it->tier >= prevTier);
            prevTier = it != pool.end() ? it->tier : prevTier;
        }
        // P4: monotone - one more failure (a running or untried candidate fails) never closes a tier.
        for (const TierCandidate &c : pool) {
            if (failed(c.id)) continue;
            TierAttempt more = at;
            more.inFlight.remove(c.id);
            more.failed << c.id;
            CHECK(decideOpenTiers(pool, more, k, cap).maxOpenTier >= d.maxOpenTier);
        }
        // P5: K >= cap behaves exactly as cap - 1.
        CHECK(decideOpenTiers(pool, at, cap + rnd(20), cap).maxOpenTier == decideOpenTiers(pool, at, cap - 1, cap).maxOpenTier);
        // P6: crowd scores and ranks never change which tiers are open.
        QList<TierCandidate> shuffled = pool;
        for (TierCandidate &c : shuffled) { c.crowdScore = -c.crowdScore - rnd(1000); c.rank = rnd(100); }
        CHECK(decideOpenTiers(shuffled, at, k, cap).openTiers == d.openTiers);
        // P7: a last-known-good never changes the open tiers, never moves out of its tier.
        if (!pool.isEmpty()) {
            const QString lkg = pool.at(rnd(pool.size())).id;
            const TierDecision dl = decideOpenTiers(pool, at, k, cap, lkg);
            CHECK(dl.openTiers == d.openTiers && QSet<QString>(dl.order.begin(), dl.order.end())
                                                     == QSet<QString>(d.order.begin(), d.order.end()));
        }
        ++checked;
    }
    CHECK(checked == 3000);
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    verdict();
    tierExamples();
    tierProperties();
    if (g_fail) {
        std::printf("upstream_policy_check: %d of %d FAILED\n", g_fail, g_total);
        return 1;
    }
    std::printf("upstream_policy_check: OK (%d checks)\n", g_total);
    return 0;
}
