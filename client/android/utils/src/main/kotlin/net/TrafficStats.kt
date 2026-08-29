package org.amnezia.vpn.util.net

import android.net.TrafficStats
import android.os.Build
import android.os.Process
import android.os.SystemClock
import java.net.NetworkInterface
import java.util.Collections
import kotlin.math.roundToLong

private const val BYTE = 1L
private const val KiB = BYTE shl 10
private const val MiB = KiB shl 10
private const val GiB = MiB shl 10
private const val TiB = GiB shl 10

class TrafficStats {

    private var lastTrafficData = TrafficData.ZERO
    private var lastTimestamp = 0L

    private val uid = Process.myUid()

    private val getTrafficDataCompat: () -> TrafficData = {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // Android does not guarantee that the active VpnService interface
            // remains tun0 across rapid reconnects.  Prefer any live tun
            // interface and fall back to this service UID if OEM kernels hide
            // per-interface counters.
            val tunnelData = runCatching {
                Collections.list(NetworkInterface.getNetworkInterfaces())
                    .asSequence()
                    .filter { it.name.startsWith("tun") && runCatching { it.isUp }.getOrDefault(false) }
                    .sortedBy { it.name }
                    .map {
                        TrafficData(
                            TrafficStats.getRxBytes(it.name),
                            TrafficStats.getTxBytes(it.name),
                        )
                    }
                    .firstOrNull { it.isSupported() }
            }.getOrNull()
            tunnelData ?: uidTrafficData()
        } else {
            uidTrafficData()
        }
    }

    private fun uidTrafficData(): TrafficData = TrafficData(
        TrafficStats.getUidRxBytes(uid),
        TrafficStats.getUidTxBytes(uid),
    )

    fun reset() {
        lastTrafficData = snapshot()
        lastTimestamp = SystemClock.elapsedRealtime()
    }

    /** Raw monotonic OS counters used by protocol session accumulators. */
    fun snapshot(): TrafficData = getTrafficDataCompat()

    fun isSupported(): Boolean =
        lastTrafficData.isSupported()

    fun getSpeed(): TrafficData {
        val timestamp = SystemClock.elapsedRealtime()
        val elapsedSeconds = (timestamp - lastTimestamp) / 1000.0
        val trafficData = snapshot()
        val speed = trafficData.diff(lastTrafficData, elapsedSeconds)
        lastTrafficData = trafficData
        lastTimestamp = timestamp
        return speed
    }

    class TrafficData(val rx: Long, val tx: Long) {

        fun isSupported(): Boolean =
            rx != TrafficStats.UNSUPPORTED.toLong() && tx != TrafficStats.UNSUPPORTED.toLong()

        private var _rxString: String? = null
        val rxString: String
            get() {
                if (_rxString == null) _rxString = rx.speedToString()
                return _rxString ?: throw AssertionError("Set to null by another thread")
            }

        private var _txString: String? = null
        val txString: String
            get() {
                if (_txString == null) _txString = tx.speedToString()
                return _txString ?: throw AssertionError("Set to null by another thread")
            }

        fun diff(other: TrafficData, elapsedSeconds: Double): TrafficData {
            val rx = ((this.rx - other.rx) / elapsedSeconds).round()
            val tx = ((this.tx - other.tx) / elapsedSeconds).round()
            return if (rx == 0L && tx == 0L) ZERO else TrafficData(rx, tx)
        }

        private fun Double.round() = if (isNaN()) 0L else roundToLong()

        private fun Long.speedToString() =
            when {
                this < KiB -> formatSize(this, BYTE, "B/s")
                this < MiB -> formatSize(this, KiB, "KiB/s")
                this < GiB -> formatSize(this, MiB, "MiB/s")
                this < TiB -> formatSize(this, GiB, "GiB/s")
                else -> formatSize(this, TiB, "TiB/s")
            }

        private fun formatSize(bytes: Long, divider: Long, unit: String): String {
            val s = (bytes.toDouble() / divider * 100).roundToLong() / 100.0
            return "${s.toString().removeSuffix(".0")} $unit"
        }

        companion object {
            val ZERO: TrafficData = TrafficData(0L, 0L)
        }
    }
}
