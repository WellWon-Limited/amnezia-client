// Round mac-B review M2: the macOS quit hands only an UP AmneziaWG session to the daemon (QuitSessionPolicy.h).
// Build + run: tests/build_quit_session_policy.sh (--mutate: each rule broken in a copy of the header must fail here).
#include "QuitSessionPolicy.h"

#include <cstdio>

using avpn::QuitSessionAction;
using avpn::quitSessionAction;

static int g_fail = 0, g_checks = 0;
#define CHECK(cond, what)                                                                  \
    do {                                                                                   \
        ++g_checks;                                                                        \
        if (!(cond)) {                                                                     \
            ++g_fail;                                                                      \
            std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, what);                    \
        }                                                                                  \
    } while (0)

int main()
{
    // an AmneziaWG session after its handshake (Connected): the daemon keeps it, the next launch adopts it
    CHECK(quitSessionAction(true, true, true) == QuitSessionAction::ReleaseToDaemon, "AmneziaWG up: handed to the daemon");
    // an AmneziaWG attempt still in progress (Connecting / Reconnecting): nobody would finish it - ended like a stop
    CHECK(quitSessionAction(true, true, false) == QuitSessionAction::EndSession, "AmneziaWG connecting: ended");
    // own Xray (tun2socks is this process's child): ends up or not
    CHECK(quitSessionAction(true, false, true) == QuitSessionAction::EndSession, "Xray up: ended");
    CHECK(quitSessionAction(true, false, false) == QuitSessionAction::EndSession, "Xray connecting: ended");
    // no protocol here (nothing started, or an adopted session the daemon holds): nothing to do
    CHECK(quitSessionAction(false, false, false) == QuitSessionAction::Nothing, "no protocol: nothing");
    CHECK(quitSessionAction(false, true, true) == QuitSessionAction::Nothing, "no protocol, adopted up: nothing");
    if (g_fail) {
        std::fprintf(stderr, "quit_session_policy_check: %d of %d checks FAILED\n", g_fail, g_checks);
        return 1;
    }
    std::printf("quit_session_policy_check: OK (%d checks)\n", g_checks);
    return 0;
}
