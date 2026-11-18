// AVPN upstream nodes (plan provider-pool v2, D7): the data-check verdict (UpstreamVerdict.h). The policy-tier rule
// was replaced by the path engine's order (path/PathSelect.h, tests/path_engine_check.cpp).
// Build/run: build_upstream_policy.sh
#include "../TuningStore.h"
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
    // Decision of 18.11 (owner's iPhone: 131072 bytes in 3.5 s, first byte at 3.1 s, judged no_data): a body that
    // arrived whole within the total limit is data - slow, whatever its first byte or stalls.
    in = good();
    in.ttfbMs = 3100;
    in.elapsedMs = 3500;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::Slow, "slow", true));
    in.ttfbMs = 3000;
    in.elapsedMs = 900;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::Works, "verified_net_token", true)); // the limit itself is inside
    in = good();
    in.maxStallMs = 1501;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::Slow, "slow", true));
    // An incomplete body is named by its cause.
    in = good();
    in.bytesReceived = 16384;
    in.ttfbMs = 3001;
    CHECK(is(judgeUpstreamCheck(in), UpstreamVerdict::NoData, "ttfb_timeout", false));
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

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    verdict();
    if (g_fail) {
        std::printf("upstream_policy_check: %d of %d FAILED\n", g_fail, g_total);
        return 1;
    }
    std::printf("upstream_policy_check: OK (%d checks)\n", g_total);
    return 0;
}
