// AVPN (upstream nodes, release C, lane P1): the Android status event and the hand-over message
// (UpstreamStatusWire.h; ~/avpn-build/plans/provider-pool/android-ipc-contract.md). QtCore only. Proves:
//  - the decode of {"upstream":{...}} with the contract's types, and what an ill-typed field reads as;
//  - the normalize and change rules are the iOS bridge's (IosNativePolicy.h) on the same inputs - one shape;
//  - the macOS in-process owner's statusJson decodes to itself (the three owners speak one object);
//  - the decoded map drives decideUpstreamStatus exactly as the iOS map does (terminal -> leave);
//  - the hand-over message is the iOS provider message.
#include "../UpstreamLeaseOwner.h"
#include "../UpstreamStatusWire.h"
#include "platforms/ios/IosNativePolicy.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <cstdio>
#include <string>
#include <vector>

using namespace avpn;

static int g_fail = 0, g_ok = 0;
static void check(bool ok, const char *what)
{
    if (ok) {
        ++g_ok;
        return;
    }
    std::printf("FAIL %s\n", what);
    ++g_fail;
}

static QByteArray event(const QJsonObject &up)
{
    return QJsonDocument(QJsonObject{{QStringLiteral("upstream"), up}}).toJson(QJsonDocument::Compact);
}

static QJsonObject activeObject()
{
    return QJsonObject{{"state", "active"},           {"code", ""},
                       {"seq", 12},                   {"renewed_ms_ago", 41000},
                       {"expires_in_ms", 859000},     {"revision", 1763123456999.0},
                       {"config_changed", false},     {"applied_bytes", 123456789},
                       {"shadow_bytes", 0},           {"meter_scope", "tunnel"}};
}

static void decodeContractTypes()
{
    const UpstreamTunnelStatus s = decodeUpstreamStatusEvent(event(activeObject()));
    check(s.present, "active: present");
    check(s.state == "active" && s.code.isEmpty(), "active: state/code");
    check(s.seq == 12 && s.renewedMsAgo == 41000 && s.expiresInMs == 859000, "active: seq/renewed/expires");
    check(s.revision == 1763123456999LL, "active: revision (13 digits, exact)");
    check(!s.configChanged && s.appliedBytes == 123456789 && s.shadowBytes == 0, "active: bytes");
    check(s.meterScope == "tunnel", "active: scope");

    // Not an event.
    check(!decodeUpstreamStatusEvent("").present, "empty: absent");
    check(!decodeUpstreamStatusEvent("not json").present, "garbage: absent");
    check(!decodeUpstreamStatusEvent("[1,2]").present, "array root: absent");
    check(!decodeUpstreamStatusEvent(R"({"state":"active"})").present, "bare object without upstream: absent");
    check(!decodeUpstreamStatusEvent(R"({"upstream":"active"})").present, "upstream not an object: absent");

    // Ill-typed fields read as the iOS bridge reads them (string -> "", number -> default).
    QJsonObject bad{{"state", 3},          {"code", true},          {"seq", "12"},
                    {"renewed_ms_ago", "x"}, {"expires_in_ms", 1.5}, {"revision", -4},
                    {"config_changed", 1},  {"applied_bytes", -1},   {"shadow_bytes", 1e300},
                    {"meter_scope", 7}};
    const UpstreamTunnelStatus b = decodeUpstreamStatusEvent(event(bad));
    check(b.present && b.state == "none" && b.code.isEmpty(), "bad: state none, code empty");
    check(b.seq == 0 && b.renewedMsAgo == -1 && b.expiresInMs == 0, "bad: number defaults");
    check(b.revision == 0 && !b.configChanged && b.appliedBytes == 0 && b.shadowBytes == 0, "bad: floors");
    check(b.meterScope == "tunnel", "bad: scope tunnel");

    // Terminal codes.
    QJsonObject t = activeObject();
    t["state"] = "terminal";
    t["code"] = "lease_gone";
    const UpstreamTunnelStatus tk = decodeUpstreamStatusEvent(event(t));
    check(tk.state == "terminal" && tk.code == "lease_gone", "terminal known code kept");
    t["code"] = "Gone!";
    check(decodeUpstreamStatusEvent(event(t)).code.isEmpty(), "terminal unknown code reads as empty");
    QJsonObject a = activeObject();
    a["code"] = "lease_gone";
    check(decodeUpstreamStatusEvent(event(a)).code.isEmpty(), "code on a non-terminal state dropped");
    a["meter_scope"] = "proxy";
    check(decodeUpstreamStatusEvent(event(a)).meterScope == "proxy", "proxy scope kept");
    // Unknown extra keys (an additive node_id later) are ignored.
    a["node_id"] = "up:p1";
    check(decodeUpstreamStatusEvent(event(a)).present, "extra key ignored");
}

// The normalize and change rules against the iOS bridge's, field for field.
static avpn_ios::UpstreamStatusFields toIos(const UpstreamTunnelStatus &f)
{
    avpn_ios::UpstreamStatusFields i;
    i.present = f.present;
    i.state = f.state.toStdString();
    i.code = f.code.toStdString();
    i.seq = f.seq;
    i.renewedMsAgo = f.renewedMsAgo;
    i.expiresInMs = f.expiresInMs;
    i.revision = f.revision;
    i.configChanged = f.configChanged;
    i.appliedBytes = f.appliedBytes;
    i.shadowBytes = f.shadowBytes;
    i.meterScope = f.meterScope.toStdString();
    return i;
}

static bool same(const UpstreamTunnelStatus &q, const avpn_ios::UpstreamStatusFields &i)
{
    return q.present == i.present && q.state.toStdString() == i.state && q.code.toStdString() == i.code
           && q.seq == i.seq && q.renewedMsAgo == i.renewedMsAgo && q.expiresInMs == i.expiresInMs
           && q.revision == i.revision && q.configChanged == i.configChanged && q.appliedBytes == i.appliedBytes
           && q.shadowBytes == i.shadowBytes && q.meterScope.toStdString() == i.meterScope;
}

static void parityWithIos()
{
    const char *states[] = {"none", "pending", "active", "terminal", "weird", ""};
    const char *codes[] = {"", "disabled", "lease_gone", "not_entitled", "over_quota", "no_seat_reacquire",
                           "standby_unconfirmed", "renew_rejected", "unknown_code"};
    const char *scopes[] = {"proxy", "tunnel", "", "PROXY"};
    const qint64 nums[] = {-5, -1, 0, 7};
    std::vector<UpstreamTunnelStatus> all;
    for (const char *st : states)
        for (const char *c : codes)
            for (const char *sc : scopes)
                for (qint64 n : nums) {
                    UpstreamTunnelStatus f;
                    f.present = true;
                    f.state = QString::fromLatin1(st);
                    f.code = QString::fromLatin1(c);
                    f.meterScope = QString::fromLatin1(sc);
                    f.seq = f.renewedMsAgo = f.expiresInMs = f.revision = f.appliedBytes = f.shadowBytes = n;
                    f.configChanged = n > 0;
                    all.push_back(f);
                }
    // renew_rejected (the shared lease machine's code after 422s in a row): the iOS list keeps it too since the
    // Scanner engine lane (it was dropped there before) - the two rules are now identical on every input.
    int mismatches = 0, renewRejectedKept = 0;
    for (const UpstreamTunnelStatus &f : all) {
        const UpstreamTunnelStatus q = normalizeUpstreamTunnelStatus(f);
        const avpn_ios::UpstreamStatusFields i = avpn_ios::normalizeUpstreamStatus(toIos(f));
        if (f.state == QLatin1String("terminal") && f.code == QLatin1String("renew_rejected")
            && q.code == QLatin1String("renew_rejected") && i.code == "renew_rejected")
            ++renewRejectedKept;
        if (!same(q, i))
            ++mismatches;
    }
    check(mismatches == 0, "normalize: identical to IosNativePolicy.h on every input");
    check(renewRejectedKept == 4 * 4, "normalize: renew_rejected kept on every terminal input by both rules");

    // Change rule on pairs of normalized statuses (a sample of the cross product).
    int changeMismatches = 0;
    for (size_t i = 0; i < all.size(); i += 7)
        for (size_t j = 0; j < all.size(); j += 11) {
            const UpstreamTunnelStatus a = normalizeUpstreamTunnelStatus(all[i]);
            const UpstreamTunnelStatus b = normalizeUpstreamTunnelStatus(all[j]);
            if (upstreamTunnelStatusChanged(a, b) != avpn_ios::upstreamStatusChanged(toIos(a), toIos(b)))
                ++changeMismatches;
        }
    UpstreamTunnelStatus none; // not present
    UpstreamTunnelStatus first = normalizeUpstreamTunnelStatus(all.front());
    if (upstreamTunnelStatusChanged(none, first) != avpn_ios::upstreamStatusChanged(toIos(none), toIos(first)))
        ++changeMismatches;
    if (upstreamTunnelStatusChanged(first, none) != avpn_ios::upstreamStatusChanged(toIos(first), toIos(none)))
        ++changeMismatches;
    check(changeMismatches == 0, "change rule: identical to IosNativePolicy.h");

    // The rule itself: ms counters alone are quiet, a renewal (seq) is not.
    UpstreamTunnelStatus x = decodeUpstreamStatusEvent(event(activeObject()));
    UpstreamTunnelStatus y = x;
    y.renewedMsAgo += 4000;
    y.expiresInMs -= 4000;
    y.appliedBytes += 10;
    check(!upstreamTunnelStatusChanged(x, y), "only ms/bytes moved: quiet");
    y.seq += 1;
    check(upstreamTunnelStatusChanged(x, y), "seq moved: emitted");
    check(upstreamTunnelStatusChanged(UpstreamTunnelStatus(), x), "first event: emitted");
}

// The macOS in-process owner's object is the same object: decoded and mapped back, nothing changes.
static void macOwnerRoundTrip()
{
    UpstreamLeaseOwner owner;
    const QJsonObject mac = owner.statusJson(1000);
    const UpstreamTunnelStatus s = decodeUpstreamStatusEvent(event(mac));
    check(s.present && s.state == "none" && s.renewedMsAgo == -1, "mac owner (idle) decodes");
    const QJsonObject back = QJsonObject::fromVariantMap(upstreamTunnelStatusMap(s));
    check(back.keys() == mac.keys(), "mac owner: the same keys");
    bool valuesEqual = true;
    for (const QString &k : mac.keys())
        if (back.value(k).toVariant() != mac.value(k).toVariant())
            valuesEqual = false;
    check(valuesEqual, "mac owner: the same values");
    const QJsonObject act = QJsonObject::fromVariantMap(upstreamTunnelStatusMap(decodeUpstreamStatusEvent(event(activeObject()))));
    check(act.keys() == activeObject().keys(), "active: the same keys after the map");
}

// The map drives the engine's decision like the iOS map (AvpnEngineQml::applyUpstreamTunnelStatus).
static void engineDecision()
{
    QJsonObject t = activeObject();
    t["state"] = "terminal";
    t["code"] = "over_quota";
    UpstreamStatusDecision d =
        decideUpstreamStatus(QJsonObject::fromVariantMap(upstreamTunnelStatusMap(decodeUpstreamStatusEvent(event(t)))), 0);
    check(d.valid && d.state == "terminal" && d.leaveCode == "over_quota", "terminal over_quota leaves with its code");
    t["code"] = "renew_rejected";
    d = decideUpstreamStatus(QJsonObject::fromVariantMap(upstreamTunnelStatusMap(decodeUpstreamStatusEvent(event(t)))), 0);
    check(d.leaveCode == "renew_rejected", "terminal renew_rejected leaves with its code");
    check(upstreamNoticeFor(d.leaveCode) == UpstreamNotice::Unavailable, "renew_rejected: the user is told");
    t["code"] = "Gone!";
    d = decideUpstreamStatus(QJsonObject::fromVariantMap(upstreamTunnelStatusMap(decodeUpstreamStatusEvent(event(t)))), 0);
    check(d.leaveCode == "terminal", "terminal unknown code still leaves");
    QJsonObject a = activeObject();
    d = decideUpstreamStatus(QJsonObject::fromVariantMap(upstreamTunnelStatusMap(decodeUpstreamStatusEvent(event(a)))),
                             1763123456000LL);
    check(d.leaveCode.isEmpty() && d.refreshRevision == 1763123456999LL, "active newer revision: refresh, no leave");
    d = decideUpstreamStatus(QJsonObject::fromVariantMap(upstreamTunnelStatusMap(decodeUpstreamStatusEvent(event(a)))),
                             1763123456999LL);
    check(d.refreshRevision == 0, "active same revision: no refresh");
}

static void handOverMessage()
{
    check(upstreamLeaseSetMessage(QJsonObject()).isEmpty(), "empty lease: no message");
    const QJsonObject lease{{"lease_id", "L"}, {"renew_token", "tlr1.T"}, {"api_base", "https://h"},
                            {"renew_after_s", 300}, {"ttl_s", 900}, {"expires_in_ms", 900000.0},
                            {"seq", 1.0}, {"epoch", 7.0}, {"revision", 5.0}, {"meter_scope", "tunnel"},
                            {"meter_tags", QJsonArray{"out"}}};
    const QByteArray m = upstreamLeaseSetMessage(lease);
    const QJsonObject o = QJsonDocument::fromJson(m).object();
    check(o.keys() == QStringList({"action", "upstream_lease"}), "message: two keys");
    check(o.value("action").toString() == "upstream_lease_set", "message: the iOS action name");
    check(o.value("upstream_lease").toObject() == lease, "message: the lease verbatim");
    check(!m.contains('\n'), "message: compact");
}

int main()
{
    decodeContractTypes();
    parityWithIos();
    macOwnerRoundTrip();
    engineDecision();
    handOverMessage();
    std::printf("upstream_status_wire_check: %d ok, %d failed\n", g_ok, g_fail);
    return g_fail == 0 ? 0 : 1;
}
