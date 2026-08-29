package org.amnezia.vpn.protocol

import android.os.Bundle
import org.json.JSONObject

private const val RUNTIME_STATUS_JSON_KEY = "tunnelRuntimeStatusV1"

data class TunnelRuntimeStatus(
    val sessionId: String,
    val protocol: String,
    val runtimeState: String,
    val coreAdapter: String,
    val coreVersion: String,
    val coreAbi: String,
    val runtimeVersionProbed: Boolean,
    val statistics: Statistics,
    val failureReason: String? = null,
) {
    fun toJson(): JSONObject {
        val counterEpoch = statistics.counterEpoch.ifEmpty { sessionId }
        val counters = JSONObject()
            .put("available", statistics.available)
            .put("source", statistics.source)
            .put("epoch", counterEpoch)
            .put("rx_bytes", statistics.rxBytes.toString())
            .put("tx_bytes", statistics.txBytes.toString())
            .put("rx_packets", statistics.rxPackets.toString())
            .put("tx_packets", statistics.txPackets.toString())
            .put("rx_bytes_delta", statistics.rxBytesDelta.toString())
            .put("tx_bytes_delta", statistics.txBytesDelta.toString())
            .put("rx_packets_delta", "0")
            .put("tx_packets_delta", "0")
            .put("reset_count", statistics.counterResetCount.toString())
        val core = JSONObject()
            .put("adapter", coreAdapter)
            .put("version", coreVersion)
            .put("runtime_version_probed", runtimeVersionProbed)
            .put("abi", coreAbi)
        return JSONObject()
            .put("type", TYPE)
            .put("schema", SCHEMA)
            // String avoids JSON/JavaScript precision loss for long-running
            // service generations and gives C++ an opaque stale-session token.
            .put("session_id", sessionId)
            .put("protocol", protocol)
            .put("runtime_state", runtimeState)
            .put("core", core)
            .put("counters", counters)
            .put("rx_bytes", statistics.rxBytes.toString())
            .put("tx_bytes", statistics.txBytes.toString())
            .put(
                "last_handshake_time_sec",
                statistics.lastHandshakeSec.takeIf { protocol == "awg" && it > 0L }?.toString()
                    ?: JSONObject.NULL,
            )
            .also { payload ->
                failureReason?.let { payload.put("failure_reason", it) }
            }
    }

    companion object {
        const val TYPE = "tunnel_runtime_status_v1"
        const val SCHEMA = 1

        fun from(
            sessionId: String,
            protocolState: ProtocolState,
            protocol: Protocol?,
            runtimeStateOverride: String? = null,
            failureReason: String? = null,
        ): TunnelRuntimeStatus? {
            val manifest = protocol?.engineManifest ?: return null
            val runtimeState = when (protocolState) {
                ProtocolState.CONNECTED -> "running"
                ProtocolState.CONNECTING -> "starting"
                ProtocolState.DISCONNECTING -> "stopping"
                ProtocolState.DISCONNECTED -> "stopped"
                ProtocolState.RECONNECTING -> "reconnecting"
                ProtocolState.UNKNOWN -> "unknown"
            }
            return TunnelRuntimeStatus(
                sessionId = sessionId,
                protocol = manifest.protocol,
                runtimeState = runtimeStateOverride ?: runtimeState,
                coreAdapter = manifest.adapter,
                coreVersion = manifest.runtimeCoreVersion ?: manifest.declaredCoreVersion,
                coreAbi = manifest.abi,
                runtimeVersionProbed = manifest.runtimeVersionProbed,
                statistics = protocol.statistics,
                failureReason = failureReason,
            )
        }
    }
}

fun Bundle.putTunnelRuntimeStatus(status: TunnelRuntimeStatus?) {
    if (status != null) putString(RUNTIME_STATUS_JSON_KEY, status.toJson().toString())
}

fun Bundle.getTunnelRuntimeStatusJson(): String? =
    getString(RUNTIME_STATUS_JSON_KEY)?.takeIf { raw ->
        runCatching {
            val value = JSONObject(raw)
            value.optString("type") == TunnelRuntimeStatus.TYPE &&
                value.optInt("schema") == TunnelRuntimeStatus.SCHEMA
        }.getOrDefault(false)
    }

// Reset-safe cumulative session counter.  A raw Android interface/UID counter
// can reset when the TUN is recreated; backwards values rebase with zero delta
// and never underflow into Long.MAX_VALUE-sized traffic spikes.
class SessionTrafficAccumulator(private val source: String) {
    data class Raw(val rxBytes: Long, val txBytes: Long)

    private var counterEpoch = ""
    private var previous: Raw? = null
    private var cumulative = Raw(0L, 0L)
    private var latestDelta = Raw(0L, 0L)
    private var resetCount = 0L

    @Synchronized
    fun start(counterEpoch: String, baseline: Raw?) {
        this.counterEpoch = counterEpoch
        previous = baseline?.takeIf { it.isSupported() }
        cumulative = Raw(0L, 0L)
        latestDelta = Raw(0L, 0L)
        resetCount = 0L
    }

    @Synchronized
    fun sample(raw: Raw?): Statistics {
        if (raw == null || !raw.isSupported()) return Statistics.EMPTY_STATISTICS
        val old = previous
        previous = raw
        if (old == null) {
            return statistics()
        }
        val rxReset = raw.rxBytes < old.rxBytes
        val txReset = raw.txBytes < old.txBytes
        val rxDelta = if (!rxReset) raw.rxBytes - old.rxBytes else 0L
        val txDelta = if (!txReset) raw.txBytes - old.txBytes else 0L
        if (rxReset || txReset) resetCount = saturatingAdd(resetCount, 1L)
        latestDelta = Raw(rxDelta, txDelta)
        cumulative = Raw(
            saturatingAdd(cumulative.rxBytes, rxDelta),
            saturatingAdd(cumulative.txBytes, txDelta),
        )
        return statistics()
    }

    private fun statistics(): Statistics = Statistics.build {
        setRxBytes(cumulative.rxBytes)
        setTxBytes(cumulative.txBytes)
        setSource(source)
        setCounterEpoch(counterEpoch)
        setRxBytesDelta(latestDelta.rxBytes)
        setTxBytesDelta(latestDelta.txBytes)
        setCounterResetCount(resetCount)
    }

    private fun Raw.isSupported(): Boolean = rxBytes >= 0L && txBytes >= 0L

    private fun saturatingAdd(lhs: Long, rhs: Long): Long =
        if (rhs > Long.MAX_VALUE - lhs) Long.MAX_VALUE else lhs + rhs
}
