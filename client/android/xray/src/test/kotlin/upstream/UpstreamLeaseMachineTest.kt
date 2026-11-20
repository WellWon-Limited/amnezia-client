package org.amnezia.vpn.protocol.xray.upstream

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.amnezia.vpn.protocol.xray.upstream.UpstreamLeaseActionKind.LEAVE_NODE
import org.amnezia.vpn.protocol.xray.upstream.UpstreamLeaseActionKind.RESTART_BYTE_COUNTERS
import org.amnezia.vpn.protocol.xray.upstream.UpstreamLeaseActionKind.SEND_ACQUIRE
import org.amnezia.vpn.protocol.xray.upstream.UpstreamLeaseActionKind.SEND_RELEASE
import org.amnezia.vpn.protocol.xray.upstream.UpstreamLeaseActionKind.SEND_RENEW

// AVPN upstream nodes (lane A2): the service mode of the machine (adopt + RENEW_UNTIL_GONE), the cases of
// the Swift twin's testAdoptAndRenew .. testPendingHandOver (tests/UpstreamLeaseTests.swift).
class UpstreamLeaseMachineTest {

    private fun machine() = UpstreamLeaseMachine(expiryPolicy = UpstreamExpiryPolicy.RENEW_UNTIL_GONE)

    @Test
    fun adoptAndRenew() {
        val m = machine()
        var s = m.adopt(lease(), "3f9c2a7b1d4e8f60", K_T)
        assertTrue(s.actions.isEmpty(), "adopt sends nothing")
        assertTrue(m.phase == UpstreamLeasePhase.ACTIVE && m.lastAcceptedSeq == 5L && m.accountingEpoch == 7L, "adopt state")
        assertEquals(K_T + 900_000, m.deadlineMs, "deadline = now + expires_in")
        assertEquals(K_T + 300_000, s.wakeAtMs, "first renewal after renew_after_s")
        m.onTunnelBytes(1000, 200)
        assertTrue(m.tick(K_T + 299_999).actions.isEmpty(), "not due yet")
        s = m.tick(K_T + 300_000)
        val renew = assertNotNull(s.find(SEND_RENEW), "renew due")
        assertEquals(UpstreamMeterReport(6, 1000, 200, UpstreamMeterScope.TUNNEL, 7), renew.meter, "report 6 with deltas and epoch")
        assertEquals(UpstreamLeaseRoute("tlr1.TOKEN", "https://t.example.net"), renew.route, "route from envelope")
        assertEquals(-1, s.wakeAtMs, "nothing scheduled while in flight")
        // The first answer anchors the server clock: deadline = sent + ttl.
        s = m.onRenewReply(renew.requestId, renewOk(6, K_S0 + 900_000, applied = 900, shadow = 300), K_T + 300_100)
        assertEquals(K_T + 300_000 + 900_000, m.deadlineMs, "re-anchored deadline")
        assertTrue(m.lastAcceptedSeq == 6L && m.lastRenewOkMs == K_T + 300_100, "seq 6 accepted")
        assertTrue(m.appliedBytesTotal == 900L && m.shadowBytesTotal == 300L, "applied/shadow totals")
        assertEquals(K_T + 300_100 + 300_000, s.wakeAtMs, "next renewal scheduled")
        // Later renewals move the deadline by the difference of two server times.
        m.onTunnelBytes(1500, 260)
        s = m.tick(K_T + 600_100)
        val renew2 = assertNotNull(s.find(SEND_RENEW), "second renew")
        assertTrue(renew2.meter.seq == 7L && renew2.meter.rxDelta == 500L && renew2.meter.txDelta == 60L, "second deltas")
        m.onRenewReply(renew2.requestId, renewOk(7, K_S0 + 1_200_000), K_T + 600_200)
        assertEquals(K_T + 1_500_000, m.deadlineMs, "deadline moved by the server delta (+300 s)")
    }

    @Test
    fun renewUntilGonePastDeadline() {
        val m = machine()
        m.adopt(lease(), "p", K_T)
        m.onTunnelBytes(10, 5)
        var s = m.tick(K_T + 300_000)
        var req = s.find(SEND_RENEW)!!
        var now = K_T + 300_000
        val sentSeqs = mutableSetOf<Long>()
        // The API is unreachable: the same report is retried (15, 30, 60, 120 s ...) and NEVER an acquire.
        while (now < K_T + 1_500_000) {
            sentSeqs += req.meter.seq
            s = m.onRenewReply(req.requestId, transportFailure(), now + 10)
            assertTrue(s.find(SEND_ACQUIRE) == null && s.find(LEAVE_NODE) == null, "transport never leaves or acquires")
            assertTrue(s.wakeAtMs >= 0, "retry scheduled")
            now = s.wakeAtMs
            m.onTunnelBytes(10 + (now - K_T), 5)
            s = m.tick(now)
            assertNull(s.find(SEND_ACQUIRE), "no acquire past the deadline")
            req = assertNotNull(s.find(SEND_RENEW), "retry sends at $now")
        }
        assertEquals(setOf(6L), sentSeqs, "every retry carries the same seq")
        assertTrue(req.meter.rxDelta == 10L && req.meter.txDelta == 5L, "retries carry the same deltas")
        assertEquals(UpstreamLeasePhase.ACTIVE, m.phase, "still active past the deadline")
        s = m.onRenewReply(req.requestId, refused("lease_gone"), now + 50)
        assertEquals("lease_gone", s.find(LEAVE_NODE)?.reason, "lease_gone is terminal")
        assertTrue(m.phase == UpstreamLeasePhase.LEFT && m.leaveReason == "lease_gone", "phase left")
        s = m.tick(now + 1_000_000)
        assertTrue(s.actions.isEmpty() && s.wakeAtMs == -1L, "nothing after terminal")
        // Round 17 R2: no more renewals, but the final report is still owed: one release (the in-doubt report), once.
        val fin = m.disconnect(now + 1_000_001).find(SEND_RELEASE)
        assertTrue(fin != null && fin.meter.seq == 6L && fin.meter.rxDelta >= 10L, "the final report is still released after a terminal answer")
        assertNull(m.disconnect(now + 1_000_002).find(SEND_RELEASE), "released once")
    }

    @Test
    fun immediateResendAtDeadline() {
        val m = machine()
        m.adopt(lease(renewAfter = 450, expiresIn = 900_000), "p", K_T)
        var s = m.tick(K_T + 450_000)
        val first = s.find(SEND_RENEW)!!
        // retry_after 900 s would land past the deadline (K_T + 900 000): the report still goes out AT it.
        s = m.onRenewReply(first.requestId, refused("rate_limited", 900), K_T + 450_100)
        assertEquals(K_T + 900_000, s.wakeAtMs, "wake at the deadline")
        s = m.tick(K_T + 900_000)
        val atDeadline = assertNotNull(s.find(SEND_RENEW), "resent at the deadline")
        assertEquals(first.meter.seq, atDeadline.meter.seq, "same seq")
        s = m.onRenewReply(atDeadline.requestId, transportFailure(), K_T + 900_010)
        assertEquals(K_T + 900_010 + 30_000, s.wakeAtMs, "then the normal backoff (2nd failure = 30 s)")
        s = m.tick(K_T + 930_010)
        val late = s.find(SEND_RENEW)!!
        m.onRenewReply(late.requestId, renewOk(6, K_S0 + 1_830_000), K_T + 930_100)
        assertTrue(m.phase == UpstreamLeasePhase.ACTIVE && m.lastAcceptedSeq == 6L, "a renewal past the deadline keeps the session")
        assertTrue(m.deadlineMs > K_T + 930_010, "deadline moved past now")
    }

    @Test
    fun terminalAndRetryableCodes() {
        for (code in listOf("not_entitled", "over_quota", "disabled", "lease_gone")) {
            val m = machine()
            m.adopt(lease(), "p", K_T)
            val r = m.tick(K_T + 300_000).find(SEND_RENEW)!!
            val s = m.onRenewReply(r.requestId, refused(code), K_T + 300_100)
            assertTrue(s.find(LEAVE_NODE)?.reason == code && m.phase == UpstreamLeasePhase.LEFT, "$code is terminal")
        }
        for (code in listOf("no_seat", "rate_limited", "upstream_unavailable", "unknown")) {
            val m = machine()
            m.adopt(lease(), "p", K_T)
            val r = m.tick(K_T + 300_000).find(SEND_RENEW)!!
            val s = m.onRenewReply(r.requestId, refused(code, 42), K_T + 300_100)
            assertTrue(s.find(LEAVE_NODE) == null && m.phase == UpstreamLeasePhase.ACTIVE, "$code is retried")
            assertEquals(K_T + 300_100 + 42_000, s.wakeAtMs, "$code: retry_after honoured")
            val again = m.tick(s.wakeAtMs).find(SEND_RENEW)
            assertEquals(r.meter, again?.meter, "$code: the retry resends the same report")
        }
        // Lab 14.11 D2: three renewals rejected as malformed in a row leave (renew_rejected).
        val m = machine()
        m.adopt(lease(), "p", K_T)
        var s = m.tick(K_T + 300_000)
        val rejected = UpstreamRenewReply(UpstreamReplyKind.REFUSED, error = UpstreamErrorReply(UpstreamErrorCode.INVALID_REQUEST))
        for (i in 1..3) {
            s = m.onRenewReply(s.find(SEND_RENEW)!!.requestId, rejected, m.deadlineMs - 100_000)
            if (i < 3) s = m.tick(s.wakeAtMs)
        }
        assertEquals("renew_rejected", s.find(LEAVE_NODE)?.reason, "renew_rejected after three in a row")
    }

    @Test
    fun rebaselineEpochAndRelease() {
        val m = machine()
        m.adopt(lease(epoch = 7), "p", K_T)
        m.onTunnelBytes(100, 10)
        var r = m.tick(K_T + 300_000).find(SEND_RENEW)!!
        assertEquals(7L, r.meter.epoch, "report carries the envelope epoch")
        val s = m.onRenewReply(r.requestId, renewOk(6, K_S0 + 900_000, rebaseline = true, epoch = 8), K_T + 300_050)
        assertNotNull(s.find(RESTART_BYTE_COUNTERS), "rebaseline restarts the counters")
        assertEquals(8L, m.accountingEpoch, "rebaseline epoch kept")
        m.baselineBytes(150, 15)
        m.onTunnelBytes(400, 40)
        r = m.tick(K_T + 600_050).find(SEND_RENEW)!!
        assertEquals(UpstreamMeterReport(7, 250, 25, UpstreamMeterScope.TUNNEL, 8), r.meter, "after rebaseline: new epoch, bytes from the baseline")
        // Disconnect with that report unanswered: one release under its seq with the newer bytes added.
        m.onTunnelBytes(500, 45)
        val rel = m.disconnect(K_T + 600_100).find(SEND_RELEASE)
        assertEquals(UpstreamMeterReport(7, 350, 30, UpstreamMeterScope.TUNNEL, 8), rel?.meter, "release merges the in-doubt report")
        assertEquals(UpstreamLeasePhase.RELEASED, m.phase, "released")
        val clean = machine()
        clean.adopt(lease(seq = 9), "p", K_T)
        clean.onTunnelBytes(77, 7)
        assertEquals(UpstreamMeterReport(10, 77, 7, UpstreamMeterScope.TUNNEL, 7), clean.disconnect(K_T + 1000).find(SEND_RELEASE)?.meter,
            "clean release = seq + 1")
    }

    @Test
    fun pendingHandOver() {
        val m = machine()
        m.beginPending("p", K_T)
        assertEquals(UpstreamLeasePhase.PROVISIONAL, m.phase, "pending")
        val s = m.tick(K_T + 10_000)
        assertTrue(s.actions.isEmpty() && s.wakeAtMs == -1L, "pending sends nothing")
        m.onTunnelBytes(4000, 300)
        m.adopt(lease(seq = 0), "p", K_T + 20_000)
        assertEquals(UpstreamLeasePhase.ACTIVE, m.phase, "hand-over activates")
        m.onTunnelBytes(5000, 400)
        val r = m.tick(K_T + 320_000).find(SEND_RENEW)
        assertTrue(r?.meter?.seq == 1L && r.meter.rxDelta == 5000L && r.meter.txDelta == 400L, "first report includes the bytes since tunnel start")
        m.adopt(lease(seq = 50), "p", K_T + 330_000)
        assertEquals(0L, m.lastAcceptedSeq, "a second hand-over while active is ignored")
        // Disconnect while pending: nothing to release.
        val p = machine()
        p.beginPending("p", K_T)
        assertNull(p.disconnect(K_T + 1).find(SEND_RELEASE), "no release without a lease")
    }

    @Test
    fun sleepJumpAndClockBack() {
        // The device slept 2 h past the TTL: the next tick sends ONE fresh report (seq + 1, every byte since the
        // last renewal), never an acquire; a clock reading earlier than the last one counts as the last one.
        val m = machine()
        m.adopt(lease(seq = 3), "p", K_T)
        m.onTunnelBytes(100, 10)
        var s = m.tick(K_T + 300_000)
        val first = s.find(SEND_RENEW)!!
        s = m.onRenewReply(first.requestId, renewOk(4, K_S0 + 900_000), K_T + 300_100)
        m.onTunnelBytes(900, 90)
        val woke = K_T + 300_100 + 2 * 3_600_000
        s = m.tick(woke)
        val after = assertNotNull(s.find(SEND_RENEW), "one report at wake-up")
        assertEquals(UpstreamMeterReport(5, 800, 80, UpstreamMeterScope.TUNNEL, 7), after.meter, "fresh report after the sleep")
        assertNull(s.find(SEND_ACQUIRE), "never an acquire")
        s = m.onRenewReply(after.requestId, transportFailure(), woke + 10)
        assertEquals(woke + 10, s.wakeAtMs, "past the deadline: the pending report goes out once more at once")
        s = m.tick(woke + 10)
        val atDeadline = assertNotNull(s.find(SEND_RENEW), "the one immediate resend past the deadline")
        assertEquals(after.meter, atDeadline.meter, "same report")
        s = m.onRenewReply(atDeadline.requestId, transportFailure(), woke + 20)
        assertEquals(woke + 20 + 30_000, s.wakeAtMs, "then the normal backoff (2nd failure = 30 s)")
        s = m.tick(woke - 3_600_000) // clock went back: read as the last value
        assertTrue(s.actions.isEmpty() && s.wakeAtMs == woke + 20 + 30_000, "clock back = the last value, nothing due")
        s = m.onRenewReply(m.tick(woke + 30_020).find(SEND_RENEW)!!.requestId, refused("lease_gone"), woke + 30_030)
        assertEquals("lease_gone", s.find(LEAVE_NODE)?.reason, "the server freed the seat during the sleep: terminal")
    }
}
