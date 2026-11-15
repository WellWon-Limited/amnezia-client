#!/usr/bin/env python3
"""Mutation test of the pure data-watch rule (recipes/awg-apple/tribe/TribeDataWatch.swift).

Every mutant changes ONE rule of the function. A mutant is KILLED when the behavioural unit test
(tests/TribeDataWatchTests.swift, the package's build gate) fails on it. A mutant that survives is a
rule no test pins. Usage:  python3 tribe_data_watch_mutants.py [id-prefix ...]
Exit code 0 = no survivor outside the ACCEPTED list (each with its reason).
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "..", "tribe", "TribeDataWatch.swift")
TESTS = os.path.join(HERE, "..", "tests", "TribeDataWatchTests.swift")

# (id, exact text that occurs ONCE in the source, replacement, what rule is broken)
MUTANTS = [
    ("off-01", "guard policy.enabled else {\n            // Kill switch", "guard policy.enabled || true else {\n            // Kill switch", "kill switch ignored: the watch runs with the flag off"),
    ("off-02", "if self != TribeDataWatch() { self = TribeDataWatch() }", "", "state survives the kill switch"),
    ("hs-01", "let rxData = handshakeChanged ? TribeDataWatch.minus(deltaRx, policy.handshakeRxAllowanceBytes) : deltaRx", "let rxData = deltaRx", "a handshake response counts as data"),
    ("hs-02", "let txDemand = handshakeChanged ? TribeDataWatch.minus(deltaTx, policy.handshakeTxAllowanceBytes) : deltaTx", "let txDemand = deltaTx", "handshake bytes count as demand"),
    ("hs-03", "let handshakeChanged = sample.lastHandshakeSec > (countersReset ? 0 : lastHandshake)", "let handshakeChanged = sample.lastHandshakeSec > lastHandshake", "a new device's first handshake is not seen as one"),
    ("hs-04", "value > allowance ? value - allowance : 0", "value >= allowance ? value - allowance + 1 : 0", "allowance boundary off by one"),
    ("rst-01", "let countersReset = restartPending || sample.txBytes < previous.txBytes || sample.rxBytes < previous.rxBytes", "let countersReset = restartPending", "an unannounced counter drop is not recognised"),
    ("rst-02", "let countersReset = restartPending || sample.txBytes < previous.txBytes || sample.rxBytes < previous.rxBytes", "let countersReset = sample.txBytes < previous.txBytes || sample.rxBytes < previous.rxBytes", "an announced in-place restart is ignored"),
    ("rst-03", "let deltaRx = countersReset ? sample.rxBytes : sample.rxBytes - previous.rxBytes", "let deltaRx = countersReset ? sample.rxBytes &+ 20000 : sample.rxBytes - previous.rxBytes", "a counter drop is taken for inbound progress"),
    ("slp-01", "let slept = (sample.wall - previous.wall) - (sample.uptime - previous.uptime) > TribeDataWatchPolicy.sleepJumpSeconds", "let slept = false", "sleep is not detected"),
    ("slp-02", "wakeGraceUntil = now + policy.wakeGraceSeconds", "wakeGraceUntil = now", "no wake grace"),
    ("slp-03", "            windowStart = nil\n            windowTx = 0\n            suspectStart = nil\n            wakeGraceUntil", "            suspectStart = nil\n            wakeGraceUntil", "the cycle is not restarted after sleep"),
    ("q-01", "let quiet = !env.pathSatisfied || now < startGraceUntil", "let quiet = now < startGraceUntil", "an unsatisfied path is judged"),
    ("q-02", "|| now < startGraceUntil || now < wakeGraceUntil", "|| now < wakeGraceUntil", "no start grace"),
    ("q-03", "|| now < wakeGraceUntil || now < pathGraceUntil", "|| now < wakeGraceUntil", "no quiet time after a path change"),
    ("q-04", "startGraceUntil = uptime + policy.startGraceSeconds", "startGraceUntil = uptime", "start grace of zero"),
    ("win-01", "if rxData > 0 {\n            windowStart = quiet ? nil : now", "if rxData > 1_000_000_000 {\n            windowStart = quiet ? nil : now", "inbound data does not restart the cycle"),
    ("win-02", "if now - start >= policy.cycleSeconds {", "if now - start >= policy.cycleSeconds / 2 {", "a cycle of half the length"),
    ("win-03", "if now - start >= policy.cycleSeconds {", "if now - start > policy.cycleSeconds {", "cycle length boundary"),
    ("win-04", "if windowTx >= policy.cycleMinTxBytes {", "if windowTx >= 0 {", "no demand needed for a dead cycle"),
    ("win-05", "if windowTx >= policy.cycleMinTxBytes {", "if windowTx > policy.cycleMinTxBytes + 24 {", "demand threshold boundary"),
    ("win-06", "            windowTx &+= txDemand\n            if now - start", "            windowTx &+= deltaTx &+ 4096\n            if now - start", "demand counted from thin air"),
    ("chn-01", "chain > 0, start - previousEnd <= policy.cycleChainGapSeconds {", "chain > 0, start - previousEnd < policy.cycleChainGapSeconds {", "chain gap boundary"),
    ("chn-02", "chain > 0, start - previousEnd <= policy.cycleChainGapSeconds {", "chain > 0 {", "the chain never breaks on a pause"),
    ("chn-03", "&& chain >= policy.deadCycles && chainLive", "&& chain >= policy.deadCycles - 1 && chainLive", "one dead cycle fewer is enough"),
    ("chn-04", "&& chain >= policy.deadCycles && chainLive", "&& chain >= policy.deadCycles + 1 && chainLive", "one dead cycle more is needed"),
    ("chn-05", "&& chain >= policy.deadCycles && chainLive", "&& chain >= policy.deadCycles", "a stale chain is judged"),
    ("ep-01", "&& episodeTx >= policy.minEpisodeTxBytes\n", "\n", "no episode demand needed"),
    ("ep-03", "now - end >= TribeDataWatchPolicy.episodeIdleSeconds {", "now - end >= TribeDataWatchPolicy.episodeIdleSeconds * 1000 {", "an idle episode never closes"),
    ("ep-04", "now - end >= TribeDataWatchPolicy.episodeIdleSeconds {", "now - end >= TribeDataWatchPolicy.episodeIdleSeconds / 2 {", "an episode closes after half the idle time"),
    ("ep-05", "if episodeRxData >= policy.recoverRxBytes { closeEpisode() }", "if episodeRxData > 0 { closeEpisode() }", "any drop of data closes the episode"),
    ("ep-06", "if episodeStart != nil { episodeTx &+= txDemand }", "", "the episode's demand is not counted after its first cycle"),
    ("heal-01", "&& healRecent >= policy.minHealSteps\n", "\n", "the node is judged without being treated"),
    ("heal-02", "&& healRecent >= policy.minHealSteps\n", "&& healRecent > policy.minHealSteps\n", "one heal step more is needed"),
    ("heal-03", "healTimes.removeAll { now - $0 > TribeDataWatchPolicy.healWindowSeconds }", "", "old heal steps count forever"),
    ("heal-04", "for _ in 0..<Swift.min(env.healSteps - seen, 16) { healTimes.append(now) }", "", "heal steps are never seen (only steps after the first cycle's end could count)"),
    ("heal-05", "healTimes.removeAll { now - $0 > TribeDataWatchPolicy.healWindowSeconds }", "healTimes.removeAll { now - $0 > policy.cycleSeconds }", "heal steps count only inside the last cycle"),
    ("pas-01", "&& healRecent >= policy.minHealSteps\n            && !quiet", "&& healRecent >= policy.minHealSteps", "the passive rule is met inside a quiet period"),
    ("san-01", "var sanityOk = !policy.sanityRequired || verdict == .noData", "var sanityOk = true", "the bypass check is never required"),
    ("san-02", "var sanityOk = !policy.sanityRequired || verdict == .noData", "var sanityOk = verdict == .noData", "the policy bit cannot drop the bypass check"),
    ("san-03", "case .noReply: next = .network", "case .noReply: sanityOk = true", "a silent network is judged as a dead tunnel"),
    ("san-04", "case .captive: next = .captive", "case .captive: sanityOk = true", "a login page is judged as a dead tunnel"),
    ("san-05", "let usable = env.sanityAt.map { now >= $0 && now - $0 <= maxAge } ?? false", "let usable = env.sanityAt != nil", "a stale bypass result is evidence"),
    ("san-06", "? TribeDataWatchPolicy.sanityRecheckSeconds : TribeDataWatchPolicy.sanityMaxAgeSeconds", "? TribeDataWatchPolicy.sanityMaxAgeSeconds : TribeDataWatchPolicy.sanityMaxAgeSeconds", "the bypass check is repeated every 30 s while the network is down"),
    ("san-07", "var sanityOk = !policy.sanityRequired || verdict == .noData", "var sanityOk = !policy.sanityRequired", "a standing no_data keeps asking the bypass check"),
    ("prb-01", "if outcome == .silent {\n                        next = .noData", "if outcome == .silent {\n                        next = .unconfirmed", "a silent probe does not confirm"),
    ("prb-02", "if outcome == .silent {\n                        next = .noData", "if outcome != .answered {\n                        next = .noData", "a probe that never left confirms like a silent one"),
    ("prb-03", "if concerned && outcome == .answered {", "if concerned && outcome == .answered && false {", "an answered probe does not refute"),
    ("prb-04", "if let at = env.probeAt, at >= requested, TribeDataWatch.isOutcome(env.probe) {", "if env.probeAt != nil, TribeDataWatch.isOutcome(env.probe) {", "a result from before the request is taken"),
    ("prb-05", "let undisturbed = rxDataSinceProbe == 0 && !disturbedSinceProbe && !quiet && episodeStart != nil", "let undisturbed = episodeStart != nil", "a disturbed wait is judged"),
    ("prb-06", "} else if !policy.probeEnabled || env.probe == .unavailable {", "} else if env.probe == .unavailable {", "the probe runs although the policy switched it off"),
    ("prb-07", "} else if !policy.probeEnabled || env.probe == .unavailable {", "} else if !policy.probeEnabled {", "a probe is asked for where there is none"),
    ("prb-08", "} else if probesInEpisode < policy.probeMaxPerEpisode && probeTimes.count < policy.probeMaxPerHour {", "} else if probeTimes.count < policy.probeMaxPerHour {", "no probe limit per episode"),
    ("prb-09", "} else if probesInEpisode < policy.probeMaxPerEpisode && probeTimes.count < policy.probeMaxPerHour {", "} else if probesInEpisode < policy.probeMaxPerEpisode {", "no probe limit per hour"),
    ("prb-10", "} else if now - requested > policy.probeTimeoutSeconds + TribeDataWatchPolicy.probeLostSlackSeconds {", "} else if now - requested > 1_000_000 {", "a lost probe is waited for forever"),
    ("prb-11", "refutedCount += 1\n                    report = .refuted\n                    chain = 0", "refutedCount += 1\n                    report = .refuted", "a refuted chain is asked again at once"),
    ("prb-12", "} else if answeredInEpisode {", "} else if false {", "out of probes after an answer becomes unconfirmed"),
    ("prb-13", "probeTimes.removeAll { now - $0 >= TribeDataWatchPolicy.probeHourSeconds }", "", "the hourly limit never frees up"),
    ("prb-14", "let keptProbeTimes = probeTimes\n        self = TribeDataWatch()\n        probeTimes = keptProbeTimes", "self = TribeDataWatch()", "a device start refills the hourly limit"),
    ("prb-15", "} else if probeRequestedAt != nil {\n                    if verdict == .none { next = .suspect } // waiting for the probe", "} else if false {", "a second probe is asked while one is in flight"),
    ("prb-16", "lastProbeLatencyMs = outcome == .answered ? env.probeLatencyMs : 0", "lastProbeLatencyMs = 0", "the latency of an answered probe is lost"),
    ("prb-17", "} else if verdict == .noData {\n                    // Already judged", "} else if false {\n                    // Already judged", "a standing no_data keeps probing"),
    ("low-01", "lowRxDue = suspectTx >= policy.suspectMinTxBytes && suspectRxData < policy.suspectMaxRxBytes", "lowRxDue = suspectRxData < policy.suspectMaxRxBytes", "the low-inbound trigger fires without demand"),
    ("low-02", "lowRxDue = suspectTx >= policy.suspectMinTxBytes && suspectRxData < policy.suspectMaxRxBytes", "lowRxDue = suspectTx >= policy.suspectMinTxBytes", "the low-inbound trigger ignores the inbound bound"),
    ("low-03", "lowRxDue = suspectTx >= policy.suspectMinTxBytes && suspectRxData < policy.suspectMaxRxBytes", "lowRxDue = suspectTx >= policy.suspectMinTxBytes && suspectRxData <= policy.suspectMaxRxBytes + 32", "inbound bound boundary"),
    ("low-04", "if lowRxDue && episodeStart == nil && startProbe == nil", "if lowRxDue && startProbe == nil", "the low-inbound trigger probes inside the passive rule's episode"),
    ("low-05", "if now - start >= policy.suspectWindowSeconds {", "if now - start >= policy.suspectWindowSeconds / 3 {", "a suspect window of a third"),
    ("low-06", "report = .probe // low-inbound trigger", "report = nil // low-inbound trigger", "the result of a low-inbound probe is not journaled"),
    ("rec-01", "if rxDataSinceVerdict >= policy.recoverRxBytes { justRecovered = true }", "if rxDataSinceVerdict > 0 { justRecovered = true }", "a drop of data recovers the verdict"),
    ("rec-02", "if rxDataSinceVerdict >= policy.recoverRxBytes { justRecovered = true }", "", "the verdict never recovers"),
    ("rec-03", "verdict = next == .recovered ? .none : next", "verdict = next", "`recovered` stays as a state"),
    ("rep-01", "let wouldSwitch = next == .noData && !appAlive", "let wouldSwitch = next == .noData", "the shadow mark ignores a living app"),
    ("rep-02", "let wouldSwitch = next == .noData && !appAlive", "let wouldSwitch = TribeDataWatch.isFinal(next) && !appAlive", "an unconfirmed or network verdict marks a switch"),
    ("rep-03", "let appAlive = env.appSeenAt.map { now >= $0 && now - $0 <= policy.appAliveSeconds } ?? false", "let appAlive = env.appSeenAt.map { now >= $0 && now - $0 < policy.appAliveSeconds } ?? false", "app-alive boundary"),
    ("rep-04", "report = .wouldSwitch // the app fell asleep", "report = nil // the app fell asleep", "the shadow mark turning on is not reported"),
    ("rep-05", "if next != .none { report = report == .refuted ? .refuted : .verdict }", "report = report == .refuted ? .refuted : .verdict", "a verdict going away quietly is reported"),
    ("rep-06", "} else if wouldSwitch && !lastWouldSwitch && report == nil {", "} else if wouldSwitch && report == nil {", "the shadow mark is reported on every sample"),
    ("path-01", "if interfaceChanged {\n            // Another network", "if false {\n            // Another network", "a verdict survives a change of network"),
    ("path-02", "guard uptime >= pathCoolUntil else { return }", "", "no cool-down: a flapping path blinds the watch"),
    ("path-03", "if uptime + policy.pathStableSeconds >= ceiling {", "if false {", "a series of path changes extends the quiet time without a ceiling"),
    ("path-04", "pathCoolUntil = ceiling + Swift.max(policy.pathStableSeconds, policy.cycleSeconds * Double(policy.deadCycles))", "pathCoolUntil = ceiling + policy.pathStableSeconds", "the cool-down is shorter than a chain of cycles"),
    ("path-05", "        windowStart = nil\n        windowTx = 0\n        suspectStart = nil\n    }", "        suspectStart = nil\n    }", "a path change does not restart the cycle"),
    ("pol-01", "policy.cycleSeconds = number(numbers[\"ios_tw_cycle_s\"], fallback: policy.cycleSeconds, min: 10, max: 120)", "policy.cycleSeconds = number(numbers[\"ios_tw_cycle_s\"], fallback: policy.cycleSeconds, min: 1, max: 120)", "lower clamp of the cycle length"),
    ("pol-02", "return Swift.min(max, Swift.max(min, parsed.rounded(.towardZero)))", "return parsed.rounded(.towardZero)", "no clamps at all"),
    ("pol-03", "guard let parsed = value, parsed.isFinite else { return fallback }", "guard let parsed = value else { return fallback }", "NaN and infinity pass"),
    ("pol-04", "CFGetTypeID(number) == CFBooleanGetTypeID()", "false", "a JSON boolean is read as a number"),
    ("pol-05", "if let value = raw as? NSNumber { return isBoolean(value) ? value.boolValue : value.intValue == 1 }", "if let value = raw as? NSNumber { return value.intValue != 0 }", "any non-zero number switches a flag on"),
    ("pol-06", "return text == \"1\" || text == \"true\"", "return !text.isEmpty", "any string switches a flag on"),
    ("pol-07", "policy.enabled = flag(features[\"ios_tunnel_watch\"])", "policy.enabled = flag(features[\"ios_tunnel_watch_switch\"])", "the wrong flag switches the watch on"),
    ("pol-08", "min: 1000, max: 15000) / 1000", "min: 1000, max: 15000)", "probe timeout in the wrong unit"),
    ("pol-09", "(build 139 behaviour).\n    public var enabled = false", "(build 139 behaviour).\n    public var enabled = true", "the watch is on by default"),
    ("snap-01", "snapshot.passive = lastPassive", "snapshot.passive = false", "snapshot: passive"),
    ("snap-02", "snapshot.probe = probeRequestedAt != nil ? .pending : lastProbe", "snapshot.probe = lastProbe", "snapshot: a probe in flight is not shown"),
    ("snap-03", "snapshot.refuted = refutedCount", "snapshot.refuted = 0", "snapshot: refuted count"),
    ("snap-04", "\"passive\": passive ? \"no_data\" : \"none\"", "\"passive\": passive", "status block: passive label"),
    ("snap-05", "guard policy.enabled else { return snapshot }", "", "a disabled watch shows its old state"),
]

# Survivors that are accepted, each with the reason no behavioural test can or should kill it.
ACCEPTED = {}


def run(cmd, timeout=180):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)


def main():
    wanted = sys.argv[1:]
    source = open(SOURCE, encoding="utf-8").read()
    survivors, invalid, killed = [], [], 0
    with tempfile.TemporaryDirectory(prefix="tribe-data-watch-mutants.") as work:
        main_swift = os.path.join(work, "main.swift")
        with open(main_swift, "w", encoding="utf-8") as f:
            f.write(open(TESTS, encoding="utf-8").read())
        binary = os.path.join(work, "test")
        base = run(["xcrun", "swiftc", "-Onone", SOURCE, main_swift, "-o", binary])
        if base.returncode != 0 or run([binary]).returncode != 0:
            print("the unmutated source does not pass its own test: fix that first")
            return 2
        for mutant_id, old, new, what in MUTANTS:
            if wanted and not any(mutant_id.startswith(w) for w in wanted):
                continue
            if source.count(old) != 1:
                invalid.append((mutant_id, "the text to mutate occurs %d times" % source.count(old)))
                continue
            mutated = os.path.join(work, "TribeDataWatch.swift")
            with open(mutated, "w", encoding="utf-8") as f:
                f.write(source.replace(old, new))
            build = run(["xcrun", "swiftc", "-Onone", mutated, main_swift, "-o", binary])
            if build.returncode != 0:
                invalid.append((mutant_id, "does not compile"))
                continue
            try:
                result = run([binary], timeout=120)
                alive = result.returncode == 0
            except subprocess.TimeoutExpired:
                alive = False
            if alive:
                survivors.append((mutant_id, what))
                print("SURVIVED %-8s %s" % (mutant_id, what))
            else:
                killed += 1
                print("killed   %-8s %s" % (mutant_id, what))
    unexpected = [s for s in survivors if s[0] not in ACCEPTED]
    print("\nmutants: %d killed, %d survived (%d accepted), %d invalid" % (killed, len(survivors), len(survivors) - len(unexpected), len(invalid)))
    for mutant_id, why in invalid:
        print("INVALID  %-8s %s" % (mutant_id, why))
    for mutant_id, what in survivors:
        if mutant_id in ACCEPTED:
            print("accepted %-8s %s -- %s" % (mutant_id, what, ACCEPTED[mutant_id]))
    return 1 if unexpected or invalid else 0


if __name__ == "__main__":
    sys.exit(main())
