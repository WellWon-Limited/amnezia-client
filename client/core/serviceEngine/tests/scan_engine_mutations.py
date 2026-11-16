#!/usr/bin/env python3
# Scanner engine lane (L6b): mutation pass on the connect-path guards (DebugSnapshot.h, ServiceEngine hint), the
# schema-5 report rules (DoctorReport.h) and the iOS terminal codes. Usage: QT_ROOT=... python3 scan_engine_mutations.py [M01 ...]
# Each mutation breaks one rule in the source, runs the test scripts that pin it and expects a failure;
# the original file is restored after every run (also on error).
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
T = os.path.join(ROOT, "tests")
ENV = dict(os.environ, QT_ROOT=os.environ.get("QT_ROOT", os.path.expanduser("~/Qt/6.11.1/macos")))

M = [
    ("M01 cancel after connected allowed", "DebugSnapshot.h",
     "    if (a.reachedConnected || dataFlowingNow)\n        return ScanCancel::IgnoreAfterConnected;\n", "",
     ["build_facade_policy.sh"]),
    ("M02 stale record of another process cancels (relaunch)", "DebugSnapshot.h",
     "    if (a.processEpoch != processEpoch)\n        return ScanCancel::IgnoreOtherProcess;\n", "",
     ["build_facade_policy.sh"]),
    ("M03 cancel of a superseded attempt", "DebugSnapshot.h",
     "    if (a.intentSerial != intentSerial)\n        return ScanCancel::IgnoreSuperseded;\n", "",
     ["build_facade_policy.sh"]),
    ("M04 cancel when nothing is pending", "DebugSnapshot.h",
     "    if (!wantConnected)\n        return ScanCancel::IgnoreNotPending;\n    return ScanCancel::Stop;", "    return ScanCancel::Stop;",
     ["build_facade_policy.sh"]),
    ("M05 cancel without an own attempt", "DebugSnapshot.h",
     "    if (!a.active())\n        return ScanCancel::IgnoreNoAttempt;\n", "",
     ["build_facade_policy.sh"]),
    ("M06 row tap without force (F4)", "DebugSnapshot.h",
     "    bool forceConnect = true;\n    bool userOrigin = true;\n};\ninline ScannerRowConnect",
     "    bool forceConnect = false;\n    bool userOrigin = true;\n};\ninline ScannerRowConnect",
     ["build_facade_policy.sh", "build_facade_engine.sh"]),
    ("M07 row tap with the VPN off skips start()'s bookkeeping", "DebugSnapshot.h",
     "    r.userStartBookkeeping = !tunnelUpOrComingUp;", "    r.userStartBookkeeping = false;",
     ["build_facade_policy.sh"]),
    ("M08 row tap not user origin", "DebugSnapshot.h",
     "    bool forceConnect = true;\n    bool userOrigin = true;\n};\ninline ScannerRowConnect",
     "    bool forceConnect = true;\n    bool userOrigin = false;\n};\ninline ScannerRowConnect",
     ["build_facade_policy.sh"]),
    ("M09 forced connect ignored with the tunnel down", "DebugSnapshot.h",
     "    if (tunnelUp || forceConnect)\n        return {true, tunnelUp};", "    if (tunnelUp)\n        return {true, tunnelUp};",
     ["build_facade_policy.sh", "build_facade_engine.sh"]),
    ("M10 switch absent treated as on", "DebugSnapshot.h",
     "    s.scanner = flag(QLatin1String(kScannerSwitchKey), false);", "    s.scanner = flag(QLatin1String(kScannerSwitchKey), true);",
     ["build_facade_policy.sh"]),
    ("M11 other switches read without the scanner switch", "DebugSnapshot.h",
     "    if (!s.scanner)\n        return s;\n    s.returnHome", "    s.returnHome",
     ["build_facade_policy.sh"]),
    ("M12 connect-on-open compiled default off", "DebugSnapshot.h",
     "    s.connectOnOpen = flag(QLatin1String(kScannerConnectOnOpenKey), true);",
     "    s.connectOnOpen = flag(QLatin1String(kScannerConnectOnOpenKey), false);",
     ["build_facade_policy.sh"]),
    ("M13 desktop host connects for a scan", "DebugSnapshot.h",
     "    if (!hostNeedsVpn)\n        return ScanOpenConnect::IgnoreNoVpnNeeded;\n", "",
     ["build_facade_policy.sh"]),
    ("M14 connect-on-open doubles a user start", "DebugSnapshot.h",
     "    if (wantConnected || tunnelUpOrComingUp)\n        return ScanOpenConnect::IgnoreAlreadyOn;\n", "",
     ["build_facade_policy.sh"]),
    ("M15 row tap with the switch off", "DebugSnapshot.h",
     "    if (!scannerOn)\n        return ScanRowGate::IgnoreSwitchOff;\n", "",
     ["build_facade_policy.sh"]),
    ("M16 «Подключено» not latched", "DebugSnapshot.h",
     "    if (a.active() && dataFlowingNow)\n        a.reachedConnected = true;", "    (void)dataFlowingNow;",
     ["build_facade_policy.sh"]),
    ("M17 the node the ladder left is not reported", "DebugSnapshot.h",
     "    if (!engineNode.isEmpty() && engineNode != a.lastNode) {\n        fail(a.lastNode);",
     "    if (!engineNode.isEmpty() && engineNode != a.lastNode) {",
     ["build_facade_policy.sh"]),
    ("M18 attempt node shown as live on a switch's down phase", "DebugSnapshot.h",
     "    v.live = up || (switching && nativeUp && !pendingSwitch.isEmpty());", "    v.live = up;",
     ["build_facade_policy.sh"]),
    ("M19 hint retries a row failed in this session", "ServiceEngine.cpp",
     "        if (sessionExclusions().contains(n->nodeId) || m_attemptExcluded.contains(n->nodeId))\n            continue;\n        return n;",
     "        if (m_attemptExcluded.contains(n->nodeId))\n            continue;\n        return n;",
     ["build_facade_engine.sh"]),
    ("M20 hint survives a new user attempt", "ServiceEngine.h",
     "        clearAttemptOrder(); // AVPN Scanner: a hint belongs to the attempt it was given for", "",
     ["build_facade_engine.sh"]),
    ("M21 ladder step 3 ignores the hint", "ServiceEngine.cpp",
     "    if (const SubscriptionNode *hinted = hintedCandidate(m_currentNodeId)) {\n        candidate = *hinted;\n    } else if",
     "    if (false) {\n    } else if",
     ["build_facade_engine.sh"]),
    ("M22 connect() ignores the hint", "ServiceEngine.cpp",
     "    if (!candidate)\n        if (const SubscriptionNode *hinted = hintedCandidate(QString())) {",
     "    if (false)\n        if (const SubscriptionNode *hinted = hintedCandidate(QString())) {",
     ["build_facade_engine.sh"]),
    ("M23 hint kept after data passed", "ServiceEngine.cpp",
     "    clearAttemptOrder(); // AVPN Scanner: data passed - the tap's attempt is over", "",
     ["build_facade_engine.sh"]),
    ("M24 hint TTL ignored", "ServiceEngine.cpp",
     "    if (m_attemptOrderUntilMs < 0 || nowMs() > m_attemptOrderUntilMs)\n        return {};\n    return m_attemptOrder;",
     "    return m_attemptOrder;",
     ["build_facade_engine.sh"]),
    ("M25 bare network class accepted", "DoctorReport.h",
     "    if (k.size() > 48 || !detail::matches(QLatin1String(detail::kNetworkKeyPattern), k))\n        return false;",
     "    if (k.size() > 48)\n        return false;",
     ["build_doctor_check.sh"]),
    ("M26 address-like node id accepted", "DoctorReport.h",
     "matches(QStringLiteral(\"[0-9]{1,10}(:[a-z0-9_]{1,16}){0,2}\"), id)", "!id.isEmpty()",
     ["build_doctor_check.sh"]),
    ("M27 missing mode accepted", "DoctorReport.h",
     "    if (!o.value(QStringLiteral(\"mode\")).isString() || !matches(QLatin1String(kCodePattern), o.value(QStringLiteral(\"mode\")).toString()))\n        return fail(why, QStringLiteral(\"mode\"));\n",
     "",
     ["build_doctor_check.sh"]),
    ("M28 over 256 KiB accepted", "DoctorReport.h",
     "    if (checkReportBytes(o) > kCheckReportMaxBytes)\n        return fail(why, QStringLiteral(\"size\"));\n", "",
     ["build_doctor_check.sh"]),
    ("M29 unknown summary key accepted", "DoctorReport.h",
     "        if (!keys.contains(it.key()))\n            return fail(why, QStringLiteral(\"scan.unknown_key:\") + it.key().left(32));\n", "",
     ["build_doctor_check.sh"]),
    ("M30 shade «sent» with only the text acked", "DoctorReport.h",
     "    const bool logDone = logPart.isEmpty() || logPart == QLatin1String(\"acked\");",
     "    const bool logDone = true;",
     ["build_doctor_check.sh", "build_scan_report_flow.sh"]),
    ("M31 alternatives stage kept in schema 5", "DoctorReport.h",
     "        if (!checkStageIds().contains(s.id) || seen.contains(s.id) || arr.size() >= kCheckStageMax)",
     "        if (seen.contains(s.id) || arr.size() >= kCheckStageMax)",
     ["build_doctor_check.sh"]),
    ("M32 iOS drops renew_rejected again", "../../platforms/ios/IosNativePolicy.h",
     " || c == \"renew_rejected\";", ";",
     ["build_ios_terminal_codes.sh", "build_upstream_status_wire.sh"]),
    # second pass
    ("M33 awg input takes the IPv6 address first", "DebugSnapshot.h",
     "        if (!a.contains(QLatin1Char(':'))) {", "        if (a.contains(QLatin1Char(':'))) {",
     ["build_scan_awg_input.sh"]),
    ("M34 awg input ignores the platform default mtu", "DebugSnapshot.h",
     "    out.mtu = node.mtu > 0 ? node.mtu : defaultMtu;", "    out.mtu = node.mtu;",
     ["build_scan_awg_input.sh"]),
    ("M35 awg input passes a host name endpoint (DNS)", "DebugSnapshot.h",
     "    out.endpoint = endpointIsIpLiteral(node.endpoint) ? node.endpoint.trimmed() : QString();",
     "    out.endpoint = node.endpoint.trimmed();",
     ["build_scan_awg_input.sh"]),
    ("M36 awg input header key not hex", "DebugSnapshot.h",
     "QByteArray::fromBase64(a.headerProtectionKey.trimmed().toLatin1()).toHex())", "a.headerProtectionKey.trimmed().toLatin1())",
     ["build_scan_awg_input.sh"]),
    ("M37 awg input for an upstream stub", "DebugSnapshot.h",
     "    if (node.upstream.has_value() || node.xray.has_value() ||", "    if (node.xray.has_value() ||",
     ["build_scan_awg_input.sh"]),
    ("M38 awg input without a tunnel address", "DebugSnapshot.h",
     "    if (address.isEmpty())\n        return false;\n    out.privateKey", "    out.privateKey",
     ["build_scan_awg_input.sh"]),
    ("M39 speed sample: a failed digest counted as speed", "DoctorReport.h",
     "    if (!digestOk || bytes <= 0 || ms <= 0) {", "    if (bytes <= 0 || ms <= 0) {",
     ["build_doctor_check.sh"]),
    ("M40 speed sample: transport failure skipped", "DoctorReport.h",
     "        if (error == QLatin1String(\"transport\")) {", "        if (false) {",
     ["build_doctor_check.sh"]),
    ("M41 speed sample: Mbit/s miscomputed", "DoctorReport.h",
     "    const double mbit = double(bytes) * 8.0 / double(ms) / 1000.0;", "    const double mbit = double(bytes) / double(ms) / 1000.0;",
     ["build_doctor_check.sh"]),
    ("M42 probe child counted as our tunnel", "MacServiceInstaller.h",
     "    return t.size() == 2 || t.at(2) != QLatin1String(\"probe\");", "    return true;",
     ["build_mac_service_match.sh"]),
    ("M43 any amneziawg-go path counted as ours", "MacServiceInstaller.h",
     "    if (t.size() < 2 || t.at(1) != binaryPath)", "    if (t.size() < 2 || !t.at(1).endsWith(QStringLiteral(\"amneziawg-go\")))",
     ["build_mac_service_match.sh"]),
    ("M44 service plan ignores a stopped service", "DebugSnapshot.h",
     "    p.act = !running || p.needInstall;", "    p.act = p.needInstall;",
     ["build_facade_policy.sh"]),
    ("M45 service plan keeps an outdated service without asking", "DebugSnapshot.h",
     "    p.needInstall = !installed || (outdated && !(p.outdatedOnly && upgradeDeclined));", "    p.needInstall = !installed;",
     ["build_facade_policy.sh"]),
    ("M46 network kind from the tunnel's medium first", "DebugSnapshot.h",
     "    ScanKindPick p;\n    if (!pathKind.isEmpty()) {",
     "    ScanKindPick p;\n    if (!platformMedium.isEmpty()) {\n        p.kind = platformMedium;\n        return p;\n    }\n    if (!pathKind.isEmpty()) {",
     ["build_facade_policy.sh"]),
    ("M51 interface list wins over the monitor", "DebugSnapshot.h",
     "    if (!pathKind.isEmpty()) {\n        p.kind = pathKind;",
     "    if (!pathKind.isEmpty() && interfacesKind.isEmpty()) {\n        p.kind = pathKind;",
     ["build_facade_policy.sh"]),
    ("M52 disagreement of monitor and list not flagged", "DebugSnapshot.h",
     "        p.disagree = !interfacesKind.isEmpty() && interfacesKind != pathKind;", "        p.disagree = false;",
     ["build_facade_policy.sh"]),
    ("M47 virtual interfaces count as the uplink", "DebugSnapshot.h",
     "        if (!i.up || physicalIfaceNameVirtual(i.name))", "        if (!i.up)",
     ["build_facade_policy.sh"]),
    ("M48 link-local address counts as routable", "DebugSnapshot.h",
     "!a.startsWith(QLatin1String(\"169.254.\")) && ", "",
     ["build_facade_policy.sh"]),
    ("M49 refusal: queue full shown as busy", "DebugSnapshot.h",
     "    if (why == QLatin1String(\"queue_full\") || why == QLatin1String(\"full\"))\n        return QStringLiteral(\"queue_full\");\n", "",
     ["build_facade_policy.sh"]),
    ("M50 Scanner's update restarts the service under the tunnel", "DebugSnapshot.h",
     "    return !(p.needInstall && vpnOnOrComing);", "    return true;",
     ["build_facade_policy.sh"]),
    # third pass (review F1, queue lane F3/F4)
    ("M53 sent_unsaved not counted as sent", "DoctorReport.h",
     "    if (result == QLatin1String(\"delivered\") || result == QLatin1String(\"sent_unsaved\"))",
     "    if (result == QLatin1String(\"delivered\"))",
     ["build_doctor_check.sh"]),
    ("M54 not_saved shown as queued", "DoctorReport.h",
     "    if (result == QLatin1String(\"not_saved\") || result == QLatin1String(\"unknown\"))\n        return CheckDelivery::NotSaved;",
     "    if (result == QLatin1String(\"not_saved\") || result == QLatin1String(\"unknown\"))\n        return CheckDelivery::Queued;",
     ["build_doctor_check.sh"]),
    ("M55 rejected report shown as queued", "DoctorReport.h",
     "    if (result == QLatin1String(\"rejected\"))\n        return CheckDelivery::Rejected;",
     "    if (result == QLatin1String(\"rejected\"))\n        return CheckDelivery::Queued;",
     ["build_doctor_check.sh", "build_scan_report_flow.sh"]),
    ("M56 unsaved at the bound shown as queued", "DoctorReport.h",
     "    if (result == QLatin1String(\"unsaved_sending\"))\n        return CheckDelivery::NotSaved;", "",
     ["build_doctor_check.sh"]),
    ("M57 not_saved refusal mapped to unavailable", "DebugSnapshot.h",
     " || why == QLatin1String(\"not_saved\")", "",
     ["build_facade_policy.sh"]),
    ("M58 light fact without its ask id", "DebugSnapshot.h",
     "    if (ask.bound)\n        scanner.lightFactFor(ask.askId, f);", "    if (ask.bound)\n        scanner.lightFactFor(0, f);",
     ["build_facade_policy.sh"]),
    ("M59 late light fact of an older ask delivered", "DebugSnapshot.h",
     "    if (ask.epoch != epochNow)\n        return false;\n    if (ask.bound)", "    if (ask.bound)",
     ["build_facade_policy.sh"]),
    ("M60 every 404 asks for a config refresh", "DebugSnapshot.h",
     "    if (lastAskMs > 0 && nowMs - lastAskMs < kScannerOffRefreshMs)\n        return false;\n", "",
     ["build_facade_policy.sh"]),
    ("M61 scanner_off asks for no refresh", "DebugSnapshot.h",
     "    lastAskMs = nowMs;\n    config.refreshIfStale(0);", "    lastAskMs = nowMs;",
     ["build_facade_policy.sh"]),
    ("M61b scanner_off refreshes only a config older than a minute", "DebugSnapshot.h",
     "    config.refreshIfStale(0);", "    config.refreshIfStale(kScannerOffRefreshMs);",
     ["build_facade_policy.sh"]),
]


def run(script):
    p = subprocess.run(["bash", os.path.join(T, script)], cwd=T, env=ENV,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if p.returncode != 0 and " error: " in p.stdout:
        return 99  # did not compile: not a caught rule break
    return p.returncode


def main():
    only = set(sys.argv[1:])
    caught = 0
    rows = []
    for name, rel, old, new, scripts in M:
        if only and name.split()[0] not in only:
            continue
        path = os.path.normpath(os.path.join(ROOT, rel))
        orig = open(path, encoding="utf-8").read()
        if orig.count(old) != 1:
            rows.append((name, "NOT APPLIED (pattern count %d)" % orig.count(old), []))
            continue
        try:
            open(path, "w", encoding="utf-8").write(orig.replace(old, new))
            codes = [(s, run(s)) for s in scripts]
        finally:
            open(path, "w", encoding="utf-8").write(orig)
        ok = any(c not in (0, 99) for _, c in codes)
        caught += ok
        rows.append((name, "CAUGHT" if ok else "SURVIVED", codes))
    for name, verdict, codes in rows:
        print("%-62s %-9s %s" % (name, verdict, " ".join("%s=%d" % (s, c) for s, c in codes)))
    print("caught %d of %d" % (caught, len(rows)))
    return 0 if caught == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
