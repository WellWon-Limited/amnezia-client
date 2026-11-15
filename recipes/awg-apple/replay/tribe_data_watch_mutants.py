#!/usr/bin/env python3
"""Mutation test of the pure data-watch rule (recipes/awg-apple/tribe/TribeDataWatch.swift).

Every mutant changes ONE rule of the function. A mutant is KILLED when a behavioural test of the
package's build gate fails on it: tests/TribeDataWatchTests.swift, or - asked only when the first
one passes - tests/TribeDataWatchLadderTests.swift (the rule next to the real stall ladder). A mutant
that survives is a rule no test pins. The ids "rev-M.." in the texts are the mutants of the
independent review of stage 1.
Usage:  python3 tribe_data_watch_mutants.py [anchors] [id-prefix ...]
  anchors - only check that every mutant's text occurs exactly once (fast).
Exit code 0 = no survivor outside the ACCEPTED list (each with its reason).
"""
import os
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "..", "tribe", "TribeDataWatch.swift")
TESTS = os.path.join(HERE, "..", "tests", "TribeDataWatchTests.swift")
LADDER_TESTS = os.path.join(HERE, "..", "tests", "TribeDataWatchLadderTests.swift")
ROAMING = os.path.join(HERE, "..", "tribe", "TribeRoaming.swift")

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
    ("rst-04", "let deltaRx = countersReset ? sample.rxBytes : sample.rxBytes - previous.rxBytes", "let deltaRx = countersReset ? 0 : sample.rxBytes - previous.rxBytes", "rev-M08: the bytes of a restarted device are dropped"),
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
    ("chn-06", "let chainLive = lastDeadCycleEnd.map { now - $0 <= policy.cycleChainGapSeconds + policy.cycleSeconds } ?? false", "let chainLive = lastDeadCycleEnd != nil", "rev-M10: the chain never ages"),
    ("ep-01", "&& episodeTx >= policy.minEpisodeTxBytes\n", "\n", "no episode demand needed"),
    ("ep-03", "now - end >= TribeDataWatchPolicy.episodeIdleSeconds {", "now - end >= TribeDataWatchPolicy.episodeIdleSeconds * 1000 {", "an idle episode never closes"),
    ("ep-04", "now - end >= TribeDataWatchPolicy.episodeIdleSeconds {", "now - end >= TribeDataWatchPolicy.episodeIdleSeconds / 2 {", "an episode closes after half the idle time"),
    ("ep-05", "if episodeRxData >= policy.recoverRxBytes { closeEpisode() }", "if episodeRxData > 0 { closeEpisode() }", "any drop of data closes the episode"),
    ("ep-06", "if episodeStart != nil { episodeTx &+= txDemand }", "", "the episode's demand is not counted after its first cycle"),
    ("pas-01", "&& episodeTx >= policy.minEpisodeTxBytes\n            && !quiet", "&& episodeTx >= policy.minEpisodeTxBytes", "the passive rule is met inside a quiet period"),
    ("san-01", "var sanityOk = !policy.sanityRequired\n", "var sanityOk = true\n", "the bypass check is never required"),
    ("san-02", "var sanityOk = !policy.sanityRequired\n", "var sanityOk = false\n", "the policy bit cannot drop the bypass check"),
    ("san-03", "case .noReply: next = .network", "case .noReply: sanityOk = true", "a silent network is judged as a dead tunnel"),
    ("san-04", "case .captive: next = .captive", "case .captive: sanityOk = true", "a login page is judged as a dead tunnel"),
    ("san-05", "let usable = env.sanityAt.map { now >= $0 && now - $0 <= maxAge } ?? false", "let usable = env.sanityAt != nil", "a stale bypass result is evidence"),
    ("san-06", "? TribeDataWatchPolicy.sanityRecheckSeconds : TribeDataWatchPolicy.sanityMaxAgeSeconds", "? TribeDataWatchPolicy.sanityMaxAgeSeconds : TribeDataWatchPolicy.sanityMaxAgeSeconds", "the bypass check is repeated every 30 s while the network is down"),
    ("san-07", "} else if passive && verdict == .noData {", "} else if false {", "a standing no_data keeps asking the bypass check and the probe"),
    ("san-08", "} else if sanityTimes.count < policy.sanityMaxPerHour {", "} else if true {", "no hourly cap on requests outside the tunnel"),
    ("san-09", "                    sanityTimes.append(now)\n", "", "requests outside the tunnel are not counted"),
    ("san-10", "let waiting = sanityAskedAt.map { now - $0 < TribeDataWatchPolicy.sanityAskTimeoutSeconds } ?? false", "let waiting = false", "the bypass check is asked again on every sample while its answer is awaited"),
    ("san-11", "                } else if !TribeDataWatch.isFinal(verdict) {\n                    next = .unconfirmed // the network cannot be checked any more this hour\n", "", "with the cap spent the verdict stays `suspect` for ever"),
    ("san-12", "        sanityTimes.removeAll { now - $0 >= hour }\n", "", "the cap on requests outside the tunnel never frees up"),
    ("san-13", "} else if passive && verdict == .unconfirmed && !canProbe {", "} else if false {", "rev-A4: `unconfirmed` keeps asking the bypass check"),
    ("prb-01", "} else if outcome == .silent && undisturbed {\n                    passive = true\n                    judged = .probe", "} else if outcome == .silent && undisturbed {\n                    passive = true", "a silent probe does not confirm"),
    ("prb-02", "} else if outcome == .silent && undisturbed {", "} else if (outcome == .silent || outcome == .notSent) && undisturbed {", "rev-M04: a probe that never left confirms like a silent one"),
    ("prb-02b", "} else if outcome == .silent && undisturbed {", "} else if (outcome == .silent || outcome == .staged) && undisturbed {", "a probe that was only staged confirms like a silent one"),
    ("prb-03", "} else if outcome == .answered {\n                    // The path passes data", "} else if false {\n                    // The path passes data", "an answered probe does not refute"),
    ("prb-03b", "let concerned = reason == .passive\n", "let concerned = true\n", "rev-M01: any probe result judges the rule"),
    ("prb-04", "if let at = env.probeAt, at >= requested, TribeDataWatch.isOutcome(env.probe) {", "if env.probeAt != nil, TribeDataWatch.isOutcome(env.probe) {", "a result from before the request is taken"),
    ("prb-05", "let undisturbed = rxDataSinceProbe == 0 && !disturbedSinceProbe && !quiet && episodeStart != nil", "let undisturbed = episodeStart != nil", "a disturbed wait is judged"),
    ("prb-05b", "let undisturbed = rxDataSinceProbe == 0 && !disturbedSinceProbe && !quiet && episodeStart != nil", "let undisturbed = !disturbedSinceProbe && !quiet && episodeStart != nil", "rev-M02: silence is judged although data came in during the wait"),
    ("prb-05c", "let undisturbed = rxDataSinceProbe == 0 && !disturbedSinceProbe && !quiet && episodeStart != nil", "let undisturbed = rxDataSinceProbe == 0 && !quiet && episodeStart != nil", "a wait that was disturbed and is calm again is judged"),
    ("prb-06", "let probeUsable = policy.probeEnabled && env.probe != .unavailable", "let probeUsable = env.probe != .unavailable", "the probe runs although the policy switched it off"),
    ("prb-07", "let probeUsable = policy.probeEnabled && env.probe != .unavailable", "let probeUsable = policy.probeEnabled", "a probe is asked for where there is none"),
    ("prb-08", "            && probesInEpisode < policy.probeMaxPerEpisode && probeTimes.count < policy.probeMaxPerHour\n", "            && probeTimes.count < policy.probeMaxPerHour\n", "no probe limit per episode"),
    ("prb-09", "            && probesInEpisode < policy.probeMaxPerEpisode && probeTimes.count < policy.probeMaxPerHour\n", "            && probesInEpisode < policy.probeMaxPerEpisode\n", "rev-M05: no probe limit per hour"),
    ("prb-10", "} else if now - requested > policy.probeTimeoutSeconds + TribeDataWatchPolicy.probeLostSlackSeconds {", "} else if now - requested > 1_000_000 {", "a lost probe is waited for forever"),
    ("prb-11", "refutedCount += 1\n                    report = .refuted\n                    chain = 0", "refutedCount += 1\n                    report = .refuted", "a refuted chain is asked again at once"),
    ("prb-10b", "outcome = .notSent // the provider never reported back", "outcome = .silent // the provider never reported back", "rev-M16: a lost probe report reads as silence"),
    ("prb-12", "} else if passive && !canProbe && answeredInEpisode && probeRequestedAt == nil {", "} else if false {", "out of probes after an answer: the bypass check is asked and the verdict becomes unconfirmed"),
    ("prb-13", "        probeTimes.removeAll { now - $0 >= hour }\n", "", "the hourly limit never frees up"),
    ("prb-14", "        (probeTimes, lowRxProbeTimes, lowRxNotBefore, lowRxBackoff, sanityTimes, refutedCount, disturbedCount, lastReported) = kept\n", "", "rev-M06: a device start refills the hourly limits"),
    ("prb-15", "                if probeRequestedAt != nil {\n                    if verdict == .none { next = .suspect } // waiting for the probe\n                } else if !probeUsable {", "                if !probeUsable {", "a second probe is asked while one is in flight"),
    ("prb-16", "lastProbeLatencyMs = outcome == .answered ? env.probeLatencyMs : 0", "lastProbeLatencyMs = 0", "the latency of an answered probe is lost"),
    ("prb-18", "if quiet || countersReset || handshakeChanged { disturbedSinceProbe = true }", "if countersReset || handshakeChanged { disturbedSinceProbe = true }", "rev-M03: a quiet period during the wait is not remembered"),
    ("prb-19", "if quiet || countersReset || handshakeChanged { disturbedSinceProbe = true }", "if quiet || countersReset { disturbedSinceProbe = true }", "rev-A2: a new handshake during the wait does not void the probe"),
    ("prb-20", "if quiet || countersReset || handshakeChanged { disturbedSinceProbe = true }", "if quiet || handshakeChanged { disturbedSinceProbe = true }", "rev-A2: a device restart during the wait does not void the probe"),
    ("prb-22", "about no one path.\n        if probeRequestedAt != nil { disturbedSinceProbe = true }\n", "about no one path.\n", "rev-A2: a path event during the wait does not void the probe"),
    ("prb-23", "        nextProbeNotBefore = Swift.max(nextProbeNotBefore, uptime + policy.startGraceSeconds)\n", "", "rev-A2: a probe is asked inside the start grace after a restart"),
    ("prb-24", "} else if now < nextProbeNotBefore {", "} else if false {", "the pause before a re-probe is ignored"),
    ("prb-25", "                    disturbedCount += 1\n                    report = .disturbed\n", "                    report = .probe\n", "rev-A2: a void probe is not counted and reported as disturbed"),
    ("prb-26", "                    disturbedCount += 1\n", "", "the count of void probes stays zero"),
    ("prb-27", "if outcome == .noSession { refundProbe(reason) } // nothing was injected", "", "a refused start spends the probe budget"),
    ("prb-28", "                    report = .disturbed\n                    nextProbeNotBefore = now + TribeDataWatchPolicy.probeRetryGapSeconds\n", "                    report = .disturbed\n                    nextProbeNotBefore = now + 86400\n", "a void probe is never asked again"),
    ("hsj-01", "} else if outcome == .noSession && undisturbed && handshakeSilent {", "} else if outcome == .noSession && undisturbed {", "no session is judged at once, without a whole chain of handshake silence"),
    ("hsj-02", "} else if outcome == .noSession && undisturbed && handshakeSilent {", "} else if false {", "a node that never shakes hands is never judged"),
    ("hsj-03", "let handshakeSilent = sessionEpoch.map { now - $0 >= policy.cycleSeconds * Double(policy.deadCycles) } ?? false", "let handshakeSilent = sessionEpoch.map { now - $0 >= policy.cycleSeconds } ?? false", "one cycle of handshake silence is enough"),
    ("hsj-04", "if handshakeChanged || (countersReset && !announcedRestart) { sessionEpoch = now }", "if countersReset && !announcedRestart { sessionEpoch = now }", "a fresh handshake does not restart the handshake silence"),
    ("hsj-05", "        nextProbeNotBefore = Swift.max(nextProbeNotBefore, uptime + policy.startGraceSeconds)\n        sessionEpoch = uptime\n", "        nextProbeNotBefore = Swift.max(nextProbeNotBefore, uptime + policy.startGraceSeconds)\n", "a restarted device is judged by the silence of the previous one"),
    ("hsj-06", "                    passive = true\n                    judged = .handshake", "                    passive = true\n                    judged = .probe", "the journal names the wrong evidence"),
    ("hsj-07", "                } else if outcome == .noSession && undisturbed {\n                    // The engine is still trying its first handshakes: wait for a whole chain.\n                    nextProbeNotBefore = now + TribeDataWatchPolicy.probeRetryGapSeconds\n", "", "a refused start during the first handshakes is counted as a void probe"),
    ("late-01", "            if verdict == .noData && evidence == .probe {\n                refutedCount += 1", "            if false {\n                refutedCount += 1", "rev-A2: an answer after the poll does not take the verdict back"),
    ("late-02", "            if verdict == .noData && evidence == .probe {\n                refutedCount += 1", "            if verdict == .noData {\n                refutedCount += 1", "a late answer to an old probe refutes a verdict the handshake made"),
    ("late-03", "            lateAnswerSeenAt = late\n", "", "one late answer refutes every later verdict"),
    ("late-04", "                verdict = episodeStart != nil ? .suspect : .none\n                evidence = .none\n", "                evidence = .none\n", "the verdict stays after it was refuted late"),
    ("low-01", "lowRxDue = suspectTx >= policy.suspectMinTxBytes && suspectRxData < policy.suspectMaxRxBytes", "lowRxDue = suspectRxData < policy.suspectMaxRxBytes", "the low-inbound trigger fires without demand"),
    ("low-02", "lowRxDue = suspectTx >= policy.suspectMinTxBytes && suspectRxData < policy.suspectMaxRxBytes", "lowRxDue = suspectTx >= policy.suspectMinTxBytes", "the low-inbound trigger ignores the inbound bound"),
    ("low-03", "lowRxDue = suspectTx >= policy.suspectMinTxBytes && suspectRxData < policy.suspectMaxRxBytes", "lowRxDue = suspectTx >= policy.suspectMinTxBytes && suspectRxData <= policy.suspectMaxRxBytes + 32", "inbound bound boundary"),
    ("low-04", "if lowRxDue && episodeStart == nil && startProbe == nil", "if lowRxDue && startProbe == nil", "the low-inbound trigger probes inside the passive rule's episode"),
    ("low-05", "if now - start >= policy.suspectWindowSeconds {", "if now - start >= policy.suspectWindowSeconds / 3 {", "a suspect window of a third"),
    ("low-06", "report = .probe // the low-inbound trigger's own result", "report = nil // the low-inbound trigger's own result", "the result of a low-inbound probe is not journaled"),
    ("low-07", "            && lowRxProbeTimes.count < policy.probeLowRxMaxPerHour && now >= lowRxNotBefore {", "            && now >= lowRxNotBefore {", "rev-A5: the low-inbound trigger has no hourly budget"),
    ("low-08", "            && lowRxProbeTimes.count < policy.probeLowRxMaxPerHour && now >= lowRxNotBefore {", "            && lowRxProbeTimes.count < policy.probeLowRxMaxPerHour {", "rev-A5: no back-off after a low-inbound probe"),
    ("low-09", "        case .lowRx:\n            lowRxProbeTimes.append(now)\n        }\n    }\n\n    /// The start was refused", "        case .lowRx:\n            probeTimes.append(now)\n        }\n    }\n\n    /// The start was refused", "rev-A5: the low-inbound trigger spends the dead-path budget"),
    ("low-10", "                        lowRxBackoff = Swift.min(lowRxBackoff * 2, TribeDataWatchPolicy.lowRxBackoffMaxSeconds)\n", "", "the back-off after an answered probe does not grow"),
    ("low-11", "lowRxBackoff = Swift.min(lowRxBackoff * 2, TribeDataWatchPolicy.lowRxBackoffMaxSeconds)", "lowRxBackoff = lowRxBackoff * 2", "the back-off grows without a ceiling"),
    ("low-12", "                    if outcome != .answered { lowRxBackoff = TribeDataWatchPolicy.lowRxBackoffBaseSeconds }\n", "", "the back-off is not reset by a probe that was not answered"),
    ("low-13", "        lowRxProbeTimes.removeAll { now - $0 >= hour }\n", "", "the low-inbound budget never frees up"),
    ("rec-01", "if rxDataSinceVerdict >= policy.recoverRxBytes { justRecovered = true }", "if rxDataSinceVerdict > 0 { justRecovered = true }", "a drop of data recovers the verdict"),
    ("rec-02", "if rxDataSinceVerdict >= policy.recoverRxBytes { justRecovered = true }", "", "the verdict never recovers"),
    ("rec-03", "verdict = next == .recovered ? .none : next", "verdict = next", "`recovered` stays as a state"),
    ("rep-01", "let wouldSwitch = next == .noData && !appAlive", "let wouldSwitch = next == .noData", "the shadow mark ignores a living app"),
    ("rep-02", "let wouldSwitch = next == .noData && !appAlive", "let wouldSwitch = TribeDataWatch.isFinal(next) && !appAlive", "an unconfirmed or network verdict marks a switch"),
    ("rep-03", "let appAlive = env.appSeenAt.map { now >= $0 && now - $0 <= policy.appAliveSeconds } ?? false", "let appAlive = env.appSeenAt.map { now >= $0 && now - $0 < policy.appAliveSeconds } ?? false", "app-alive boundary"),
    ("rep-04", "report = .wouldSwitch // the app fell asleep", "report = nil // the app fell asleep", "the shadow mark turning on is not reported"),
    ("rep-05", "        if next != lastReported {\n", "        if next != lastReported && next != .none {\n", "rev-A7: the end of a verdict is not told (the outputs keep the old one)"),
    ("rep-07", "        if next != lastReported {\n", "        if next != verdict {\n", "rev-A7: a verdict dropped between two samples (another network) is not told"),
    ("rep-06", "} else if wouldSwitch && !lastWouldSwitch && report == nil {", "} else if wouldSwitch && report == nil {", "the shadow mark is reported on every sample"),
    ("path-01", "if interfaceChanged {\n            // Another network", "if false {\n            // Another network", "a verdict survives a change of network"),
    ("path-06", "            closeEpisode()\n            probeRequestedAt = nil\n", "            closeEpisode()\n", "rev-M11: the probe of the previous network judges the new one"),
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
    ("snap-06", "snapshot.disturbed = disturbedCount", "snapshot.disturbed = 0", "snapshot: void probes"),
    ("snap-07", "snapshot.evidence = verdict == .noData ? evidence : .none", "snapshot.evidence = .none", "snapshot: what confirmed the verdict"),
    ("snap-08", "snapshot.lowRxProbesLastHour = lowRxProbeTimes.count", "snapshot.lowRxProbesLastHour = probeTimes.count", "snapshot: the low-inbound budget"),
    ("snap-09", "snapshot.sanityLastHour = sanityTimes.count", "snapshot.sanityLastHour = 0", "snapshot: requests outside the tunnel"),
    ("pol-10", "fallback: Double(policy.probeLowRxMaxPerHour), min: 0, max: 12))", "fallback: Double(policy.probeLowRxMaxPerHour), min: 0, max: 1200))", "upper clamp of the low-inbound budget"),
    ("pol-11", "fallback: Double(policy.sanityMaxPerHour), min: 1, max: 60))", "fallback: Double(policy.sanityMaxPerHour), min: 1, max: 6000))", "upper clamp of the cap on requests outside the tunnel"),
    ("pol-12", "    public var probeLowRxMaxPerHour = 2\n", "    public var probeLowRxMaxPerHour = 12\n", "default of the low-inbound budget"),
    ("pol-13", "    public var sanityMaxPerHour = 12\n", "    public var sanityMaxPerHour = 110\n", "default of the cap on requests outside the tunnel"),
    ("snap-04", "\"passive\": passive ? \"no_data\" : \"none\"", "\"passive\": passive", "status block: passive label"),
    ("snap-05", "guard policy.enabled else { return snapshot }", "", "a disabled watch shows its old state"),
]

# Survivors that are accepted, each with the reason no behavioural test can or should kill it.
ACCEPTED = {}


def run(cmd, timeout=300):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)


def passes(binary):
    try:
        return run([binary], timeout=120).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def build_and_pass(rule, work, tag):
    """None = does not compile; True = both test binaries pass on this rule source."""
    first = os.path.join(work, tag + "-rule")
    if run(["xcrun", "swiftc", "-Onone", rule, os.path.join(work, "rule", "main.swift"), "-o", first]).returncode != 0:
        return None
    if not passes(first):
        return False
    second = os.path.join(work, tag + "-ladder")
    if run(["xcrun", "swiftc", "-Onone", rule, ROAMING, os.path.join(work, "ladder", "main.swift"), "-o", second]).returncode != 0:
        return None
    return passes(second)


def main():
    args = sys.argv[1:]
    anchors_only = "anchors" in args
    wanted = [a for a in args if a != "anchors"]
    source = open(SOURCE, encoding="utf-8").read()
    chosen = [m for m in MUTANTS if not wanted or any(m[0].startswith(w) for w in wanted)]
    ids = [m[0] for m in MUTANTS]
    if len(set(ids)) != len(ids):
        print("duplicate mutant ids: %s" % sorted(i for i in set(ids) if ids.count(i) > 1))
        return 2
    if anchors_only:
        bad = [(m[0], source.count(m[1])) for m in chosen if source.count(m[1]) != 1]
        for mutant_id, count in bad:
            print("INVALID  %-8s the text to mutate occurs %d times" % (mutant_id, count))
        print("anchors: %d mutants, %d invalid" % (len(chosen), len(bad)))
        return 1 if bad else 0
    survivors, invalid, killed = [], [], 0
    with tempfile.TemporaryDirectory(prefix="tribe-data-watch-mutants.") as work:
        for name, path in (("rule", TESTS), ("ladder", LADDER_TESTS)):
            os.makedirs(os.path.join(work, name))
            with open(os.path.join(work, name, "main.swift"), "w", encoding="utf-8") as f:
                f.write(open(path, encoding="utf-8").read())
        if build_and_pass(SOURCE, work, "base") is not True:
            print("the unmutated source does not pass its own tests: fix that first")
            return 2

        def one(mutant):
            mutant_id, old, new, what = mutant
            if source.count(old) != 1:
                return (mutant_id, what, "invalid", "the text to mutate occurs %d times" % source.count(old))
            os.makedirs(os.path.join(work, mutant_id))
            mutated = os.path.join(work, mutant_id, "TribeDataWatch.swift")
            with open(mutated, "w", encoding="utf-8") as f:
                f.write(source.replace(old, new))
            verdict = build_and_pass(mutated, work, mutant_id)
            if verdict is None:
                return (mutant_id, what, "invalid", "does not compile")
            return (mutant_id, what, "survived" if verdict else "killed", "")

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(one, chosen))
    for mutant_id, what, state, why in results:
        if state == "invalid":
            invalid.append((mutant_id, why))
        elif state == "survived":
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
