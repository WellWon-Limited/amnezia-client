package org.amnezia.vpn.protocol.xray.upstream

import android.net.TrafficStats
import android.os.Build
import android.os.Process

// AVPN upstream nodes (plan provider-pool, release C, lane A2; contract section 4, decision A-4): the byte
// source of the renew deltas. First version: meter_scope "tunnel" from the tunnel interface counters (the
// same source as utils/net/TrafficStats.kt). The UpstreamMeter interface is the seam a per-outbound source
// (libXray root export TribeOutboundStatsJSON, lane A0; the Swift UpstreamProxyMeter.swift) replaces it
// with later: it answers proxyAvailable = true and sums `meter_tags` for scope "proxy".

data class UpstreamByteTotals(val rx: Long, val tx: Long)

interface UpstreamMeter {
    // Whether this source can measure scope "proxy" (per-outbound counters of the running core).
    val proxyAvailable: Boolean
        get() = false

    // Cumulative totals of the lease's scope since tunnel start; null = no read this time (nothing
    // changes). "tunnel" = the tunnel interface; "proxy" = the core's counters summed over `tags`.
    fun totals(scope: UpstreamMeterScope, tags: List<String>): UpstreamByteTotals?
}

object UpstreamMeterPlan {
    // Scope of a lease (fixed for its life): "proxy" only when the envelope asks for it, names its tags and
    // the running meter really measures per outbound; anything else is "tunnel" (Swift UpstreamMeterPlan).
    fun scope(requested: UpstreamMeterScope, meterTags: List<String>, proxyAvailable: Boolean): UpstreamMeterScope =
        if (requested == UpstreamMeterScope.PROXY && meterTags.isNotEmpty() && proxyAvailable) {
            UpstreamMeterScope.PROXY
        } else {
            UpstreamMeterScope.TUNNEL
        }
}

// Tunnel interface counters. API >= 31: TrafficStats.getRx/TxBytes(iface) of the tun interface - they
// start at 0 when the interface is created (establish()), so they are "since tunnel start" as they are.
// Below 31 the interface read does not exist: the app UID's own counters (the encrypted bytes the core
// sends to the provider plus this app's other traffic) minus a baseline taken when this object is built -
// an approximation, reported as "tunnel" like the rest. UNSUPPORTED (-1) = no read.
class TunnelInterfaceMeter internal constructor(
    private val read: () -> UpstreamByteTotals?,
    private val baseline: UpstreamByteTotals?,
) : UpstreamMeter {

    constructor(iface: String = DEFAULT_IFACE) : this(platformReader(iface), platformBaseline())

    override fun totals(scope: UpstreamMeterScope, tags: List<String>): UpstreamByteTotals? {
        val now = read() ?: return null
        val base = baseline ?: return now
        // A counter below its baseline (reset by the system): read as restarted from 0.
        return UpstreamByteTotals(
            if (now.rx >= base.rx) now.rx - base.rx else now.rx,
            if (now.tx >= base.tx) now.tx - base.tx else now.tx,
        )
    }

    companion object {
        const val DEFAULT_IFACE = "tun0"

        // Test seam: any reader, with or without a baseline.
        internal fun forTest(baseline: UpstreamByteTotals?, read: () -> UpstreamByteTotals?) =
            TunnelInterfaceMeter(read, baseline)

        internal fun valid(rx: Long, tx: Long): UpstreamByteTotals? =
            if (rx < 0 || tx < 0) null else UpstreamByteTotals(rx, tx) // TrafficStats.UNSUPPORTED = -1

        private fun platformReader(iface: String): () -> UpstreamByteTotals? =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                { valid(TrafficStats.getRxBytes(iface), TrafficStats.getTxBytes(iface)) }
            } else {
                val uid = Process.myUid()
                ({ valid(TrafficStats.getUidRxBytes(uid), TrafficStats.getUidTxBytes(uid)) })
            }

        private fun platformBaseline(): UpstreamByteTotals? {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) return null
            val uid = Process.myUid()
            return valid(TrafficStats.getUidRxBytes(uid), TrafficStats.getUidTxBytes(uid)) ?: UpstreamByteTotals(0, 0)
        }
    }
}
