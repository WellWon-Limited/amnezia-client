// Round mac-B (test Mac 25.11.2026, build 141): every AmneziaWG connect looped - the path engine's network key moved the
// moment our own tunnel came up (wifi:<router|subnet> -> wifi:<|subnet>), the attempt owner restarted the leg on the
// "new network", the tunnel went down, the key came back. The network key must name the PHYSICAL network: unchanged
// when any tunnel comes up or goes down (our AmneziaWG, our Xray, a provider session, another app's VPN), changed by
// a real network change. Behaviour of the pure rule UplinkMonitor.h uplinkPhysicalFacts with the readings the macOS
// sources gave on the test Mac (netfacts, round mac-B logs: hashes only - the values below are stand-ins of the same
// shape), through the key (path/NetworkKey.h localNetworkKey) and the generation owner (NetworkTracker).
// Build + run: tests/build_network_key_physical.sh (--mutate: the 9fb35ab7b rule and single breaks must fail here).
#include "UplinkMonitor.h"
#include "path/NetworkKey.h"

#include <cstdio>

using namespace avpn;
using avpn::path::NetMedium;
using avpn::path::NetworkObservation;
using avpn::path::NetworkTracker;

static int g_fail = 0, g_checks = 0;
static void check(bool ok, const char *what, int line)
{
    ++g_checks;
    if (!ok) {
        ++g_fail;
        std::fprintf(stderr, "FAIL line %d: %s\n", line, what);
    }
}
#define CHECK(cond, what) check((cond), (what), __LINE__)

namespace {
const UplinkRouteIface kEn0{QStringLiteral("en0"), UplinkIfaceMedium::Wifi};
const UplinkRouteIface kEn7{QStringLiteral("en7"), UplinkIfaceMedium::Ethernet};
const QString kRouterA = QStringLiteral("en0=192.168.1.1");
const QString kSubnetA = QStringLiteral("192.168.1.0/24");

// No tunnel on the home Wi-Fi: the path satisfied over en0 with the router; the route table's default via en0 and
// en0's scoped default; the Wi-Fi service's router.
UplinkReading home()
{
    UplinkReading r;
    r.pathKind = QStringLiteral("wifi");
    r.pathStatus = 1;
    r.pathInterfaces = {QStringLiteral("en0/1/14"), QStringLiteral("en0/1/14")};
    r.pathGateways = {QStringLiteral("1002000ac0a80101")};
    r.routeIfaces = {kEn0, kEn0};
    r.serviceRouters = {kRouterA};
    return r;
}
// Our Xray (tun2socks utun22, split routes 1/8..128/1) - measured: the path and the routes as without a tunnel.
UplinkReading ownXray() { return home(); }
// A provider session rides the same Xray transport (tun2socks): the same reading.
UplinkReading providerSession() { return home(); }
// Our AmneziaWG (utun4, 0/1 + 128/1, the bypass routes) - measured: the path UNSATISFIED (status 2) with utun4 in its
// list (dropped as virtual) and NO gateway; only the unscoped default via en0 left in the route table.
UplinkReading ownAwg()
{
    UplinkReading r = home();
    r.pathStatus = 2;
    r.pathInterfaces = {QStringLiteral("en0/1/14")};
    r.pathGateways = {};
    r.routeIfaces = {kEn0};
    return r;
}
// AmneziaWG while the daemon is still adding its routes: the path already unsatisfied, the kind no longer named by it.
UplinkReading ownAwgSettling()
{
    UplinkReading r = ownAwg();
    r.pathKind.clear();
    return r;
}
// Another app's VPN (an NE tunnel utun9 as the default): the path "unsatisfied reason 0" (28.09) without a gateway,
// en0's scoped default kept, and the VPN's own service with its router on utun9.
UplinkReading foreignVpn()
{
    UplinkReading r = home();
    r.pathStatus = 2;
    r.pathInterfaces = {QStringLiteral("en0/1/14")};
    r.pathGateways = {};
    r.routeIfaces = {kEn0};
    r.serviceRouters = {kRouterA, QStringLiteral("utun9=10.8.0.1")};
    return r;
}
// Real changes: another Wi-Fi (another router), Ethernet instead of Wi-Fi, Wi-Fi off.
UplinkReading otherWifi()
{
    UplinkReading r = home();
    r.serviceRouters = {QStringLiteral("en0=10.0.0.1")};
    r.pathGateways = {QStringLiteral("1002000a0a000001")};
    return r;
}
UplinkReading ethernet()
{
    UplinkReading r;
    r.pathKind = QStringLiteral("ethernet");
    r.pathStatus = 1;
    r.pathInterfaces = {QStringLiteral("en7/3/20")};
    r.pathGateways = {QStringLiteral("1002000ac0a80101")};
    r.routeIfaces = {kEn7};
    r.serviceRouters = {QStringLiteral("en7=192.168.1.1")};
    return r;
}
UplinkReading wifiOff()
{
    UplinkReading r;
    r.pathStatus = 2;
    return r;
}

NetworkObservation observe(const UplinkReading &r, const QString &subnet, bool uplinkUp)
{
    const UplinkPhysicalFacts f = uplinkPhysicalFacts(r);
    NetworkObservation o;
    if (f.kind == QLatin1String("wifi"))
        o.medium = NetMedium::Wifi;
    else if (f.kind == QLatin1String("ethernet"))
        o.medium = NetMedium::Ethernet;
    o.gateway = f.gatewayHash;
    o.subnet = subnet;
    return path::withPhysicalUplink(o, /*authoritative=*/true, uplinkUp);
}
QString keyOf(const UplinkReading &r) { return path::localNetworkKey(observe(r, kSubnetA, true)); }
bool sameFacts(const UplinkReading &a, const UplinkReading &b)
{
    const UplinkPhysicalFacts x = uplinkPhysicalFacts(a), y = uplinkPhysicalFacts(b);
    return x.hash == y.hash && x.kind == y.kind && x.gatewayHash == y.gatewayHash;
}
} // namespace

int main()
{
    // the facts of the home Wi-Fi are known: a router hash, the kind
    const UplinkPhysicalFacts h = uplinkPhysicalFacts(home());
    CHECK(h.kind == QLatin1String("wifi") && h.gatewayHash.size() == 16, "home Wi-Fi: kind wifi and a router hash");
    CHECK(keyOf(home()).startsWith(QLatin1String("wifi:")) && keyOf(home()) != QLatin1String("wifi:-"), "home key");

    // T1 our own tunnel of every transport, and another app's: the facts and the key are those of the home Wi-Fi
    CHECK(sameFacts(ownXray(), home()) && keyOf(ownXray()) == keyOf(home()), "own Xray up: the same network");
    CHECK(sameFacts(providerSession(), home()) && keyOf(providerSession()) == keyOf(home()),
          "provider session up: the same network");
    CHECK(sameFacts(ownAwg(), home()), "own AmneziaWG up: the same physical facts (path unsatisfied, no gateway)");
    CHECK(keyOf(ownAwg()) == keyOf(home()), "own AmneziaWG up: the same network key");
    CHECK(sameFacts(ownAwgSettling(), home()) && keyOf(ownAwgSettling()) == keyOf(home()),
          "own AmneziaWG settling (the path names no kind): the same network");
    CHECK(sameFacts(foreignVpn(), home()) && keyOf(foreignVpn()) == keyOf(home()),
          "another app's VPN (its utun service and router): the same network");

    // T2 real changes move the key
    CHECK(keyOf(otherWifi()) != keyOf(home()), "another Wi-Fi (another router): another key");
    CHECK(uplinkPhysicalFacts(otherWifi()).hash != h.hash, "another Wi-Fi: the Scanner's generation element moves too");
    CHECK(keyOf(ethernet()).startsWith(QLatin1String("eth:")) && keyOf(ethernet()) != keyOf(home()),
          "Ethernet instead of Wi-Fi: another key");
    CHECK(!sameFacts(wifiOff(), home()) && uplinkPhysicalFacts(wifiOff()).gatewayHash.isEmpty(),
          "Wi-Fi off: the facts move, no router");
    CHECK(path::localNetworkKey(observe(wifiOff(), QString(), false)).isEmpty(), "Wi-Fi off: no network (empty key)");

    // T3 the generation owner across a session: home -> AmneziaWG up/down (x3) -> Xray -> provider -> foreign VPN:
    // one network, one generation; Wi-Fi off and back: "no network", then the SAME key again; another network: new
    NetworkTracker t;
    t.observe(observe(home(), kSubnetA, true));
    const QString k0 = t.current().local;
    const quint64 g0 = t.current().generation;
    for (int i = 0; i < 3; ++i) {
        CHECK(!t.observe(observe(ownAwg(), kSubnetA, true)), "AmneziaWG up: no network change");
        CHECK(!t.observe(observe(ownAwgSettling(), kSubnetA, true)), "AmneziaWG settling: no network change");
        CHECK(!t.observe(observe(home(), kSubnetA, true)), "AmneziaWG down: no network change");
    }
    CHECK(!t.observe(observe(ownXray(), kSubnetA, true)), "Xray up: no network change");
    CHECK(!t.observe(observe(providerSession(), kSubnetA, true)), "provider session: no network change");
    CHECK(!t.observe(observe(foreignVpn(), kSubnetA, true)), "another app's VPN: no network change");
    CHECK(t.current().generation == g0 && t.current().local == k0, "after every tunnel: the first generation and key");
    CHECK(t.observe(observe(wifiOff(), QString(), false)) && !t.current().usable(), "Wi-Fi off: no network");
    CHECK(t.observe(observe(home(), kSubnetA, true)) && t.current().local == k0, "Wi-Fi back: the same key as before");
    CHECK(t.current().generation == g0 + 2, "Wi-Fi off and on: two generations, no more");
    CHECK(!t.observe(observe(ownAwg(), kSubnetA, true)), "AmneziaWG up after the return: no network change");
    CHECK(t.observe(observe(otherWifi(), kSubnetA, true)) && t.current().local != k0, "another Wi-Fi: a new network");

    if (g_fail) {
        std::fprintf(stderr, "network_key_physical_check: %d of %d checks FAILED\n", g_fail, g_checks);
        return 1;
    }
    std::printf("network_key_physical_check: OK (%d checks)\n", g_checks);
    return 0;
}
