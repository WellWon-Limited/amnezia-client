// AVPN upstream nodes (lane L6b fix): the iOS bridge's list of terminal codes (platforms/ios/IosNativePolicy.h
// upstreamTerminalCodeKnown, read by the ObjC status path) and the engine's list (UpstreamStatusWire.h
// upstreamStatusTerminalCodeKnown, contract section 5) are the same set. Before the fix renew_rejected (the
// shared lease machine ends a renewing session with it, UpstreamLeaseMachine.h) was missing on iOS: the code
// read as "", the app left the node with no notice and no journal code.
// Build and run: tests/build_ios_terminal_codes.sh (QtCore + the iOS policy header, plain C++).
#include "../../../platforms/ios/IosNativePolicy.h"
#include "../UpstreamEngine.h"
#include "../UpstreamStatusWire.h"

#include <cstdio>

static int g_fail = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                           \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

int main()
{
    const char *contract[] = {"disabled", "lease_gone", "not_entitled", "over_quota", "no_seat_reacquire",
                              "standby_unconfirmed", "renew_rejected"};
    for (const char *c : contract) {
        CHECK(avpn_ios::upstreamTerminalCodeKnown(c));
        CHECK(avpn::upstreamStatusTerminalCodeKnown(QString::fromLatin1(c)));
    }
    // Not terminal codes (or unknown): both lists refuse them alike.
    const char *others[] = {"", "no_seat", "no_seat_standby", "rate_limited", "renewed", "RENEW_REJECTED", "renew_rejected "};
    for (const char *c : others) {
        CHECK(!avpn_ios::upstreamTerminalCodeKnown(c));
        CHECK(avpn::upstreamStatusTerminalCodeKnown(QString::fromLatin1(c)) == avpn_ios::upstreamTerminalCodeKnown(c));
    }

    // The status reply of the extension: a terminal renew_rejected keeps its code through the iOS
    // normalisation, so the engine's decision carries it to the leave path and the notice.
    avpn_ios::UpstreamStatusFields f;
    f.present = true;
    f.state = "terminal";
    f.code = "renew_rejected";
    const avpn_ios::UpstreamStatusFields n = avpn_ios::normalizeUpstreamStatus(f);
    CHECK(n.state == "terminal");
    CHECK(n.code == "renew_rejected");
    const QJsonObject upstream{{QStringLiteral("state"), QString::fromStdString(n.state)},
                               {QStringLiteral("code"), QString::fromStdString(n.code)}};
    const avpn::UpstreamStatusDecision d = avpn::decideUpstreamStatus(upstream, 0);
    CHECK(d.valid);
    CHECK(d.leaveCode == QLatin1String("renew_rejected"));
    CHECK(avpn::upstreamNoticeFor(d.leaveCode) == avpn::UpstreamNotice::Unavailable);

    // An unknown terminal code still leaves (the owner already stopped the core), but with no code.
    f.code = "something_new";
    CHECK(avpn_ios::normalizeUpstreamStatus(f).code.empty());

    if (g_fail) {
        std::printf("ios_terminal_codes_check: %d FAILED\n", g_fail);
        return 1;
    }
    std::printf("ios_terminal_codes_check: OK\n");
    return 0;
}
