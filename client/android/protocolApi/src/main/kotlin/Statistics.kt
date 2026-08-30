package org.amnezia.vpn.protocol

import android.os.Bundle

private const val RX_BYTES_KEY = "rxBytes"
private const val TX_BYTES_KEY = "txBytes"
private const val LAST_HANDSHAKE_SEC_KEY = "lastHandshakeSec" // AVPN: возраст WG-хендшейка (unix sec)
private const val AVAILABLE_KEY = "statisticsAvailable"
private const val SOURCE_KEY = "statisticsSource"
private const val COUNTER_EPOCH_KEY = "counterEpoch"
private const val RX_PACKETS_KEY = "rxPackets"
private const val TX_PACKETS_KEY = "txPackets"
private const val RX_BYTES_DELTA_KEY = "rxBytesDelta"
private const val TX_BYTES_DELTA_KEY = "txBytesDelta"
private const val COUNTER_RESET_COUNT_KEY = "counterResetCount"

@Suppress("DataClassPrivateConstructor")
data class Statistics private constructor(
    val rxBytes: Long = 0L,
    val txBytes: Long = 0L,
    val lastHandshakeSec: Long = 0L, // AVPN: 0 = нет/неизвестно (для DEAD-детекта serviceEngine)
    val available: Boolean = false,
    val source: String = "unavailable",
    val counterEpoch: String = "",
    val rxPackets: Long = 0L,
    val txPackets: Long = 0L,
    val rxBytesDelta: Long = 0L,
    val txBytesDelta: Long = 0L,
    val counterResetCount: Long = 0L,
) {

    private constructor(builder: Builder) : this(
        builder.rxBytes,
        builder.txBytes,
        builder.lastHandshakeSec,
        builder.available,
        builder.source,
        builder.counterEpoch,
        builder.rxPackets,
        builder.txPackets,
        builder.rxBytesDelta,
        builder.txBytesDelta,
        builder.counterResetCount,
    )

    @Suppress("SuspiciousEqualsCombination")
    fun isEmpty(): Boolean = !available

    class Builder {
        var rxBytes: Long = 0L
            private set

        var txBytes: Long = 0L
            private set

        var lastHandshakeSec: Long = 0L // AVPN
            private set

        var available: Boolean = false
            private set

        var source: String = "unavailable"
            private set

        var counterEpoch: String = ""
            private set

        var rxPackets: Long = 0L
            private set

        var txPackets: Long = 0L
            private set

        var rxBytesDelta: Long = 0L
            private set

        var txBytesDelta: Long = 0L
            private set

        var counterResetCount: Long = 0L
            private set

        fun setRxBytes(rxBytes: Long) = apply {
            this.rxBytes = rxBytes.coerceAtLeast(0L)
            available = true
        }
        fun setTxBytes(txBytes: Long) = apply {
            this.txBytes = txBytes.coerceAtLeast(0L)
            available = true
        }
        fun setLastHandshakeSec(sec: Long) = apply { this.lastHandshakeSec = sec } // AVPN
        fun setAvailable(available: Boolean) = apply { this.available = available }
        fun setSource(source: String) = apply { this.source = source }
        fun setCounterEpoch(counterEpoch: String) = apply { this.counterEpoch = counterEpoch }
        fun setRxPackets(rxPackets: Long) = apply { this.rxPackets = rxPackets.coerceAtLeast(0L) }
        fun setTxPackets(txPackets: Long) = apply { this.txPackets = txPackets.coerceAtLeast(0L) }
        fun setRxBytesDelta(value: Long) = apply { rxBytesDelta = value.coerceAtLeast(0L) }
        fun setTxBytesDelta(value: Long) = apply { txBytesDelta = value.coerceAtLeast(0L) }
        fun setCounterResetCount(value: Long) = apply { counterResetCount = value.coerceAtLeast(0L) }

        fun build(): Statistics =
            if (available) Statistics(this) else EMPTY_STATISTICS
    }

    companion object {
        val EMPTY_STATISTICS: Statistics = Statistics()

        inline fun build(block: Builder.() -> Unit): Statistics = Builder().apply(block).build()
    }
}

fun Bundle.putStatistics(statistics: Statistics) {
    putLong(RX_BYTES_KEY, statistics.rxBytes)
    putLong(TX_BYTES_KEY, statistics.txBytes)
    putLong(LAST_HANDSHAKE_SEC_KEY, statistics.lastHandshakeSec) // AVPN
    putBoolean(AVAILABLE_KEY, statistics.available)
    putString(SOURCE_KEY, statistics.source)
    putString(COUNTER_EPOCH_KEY, statistics.counterEpoch)
    putLong(RX_PACKETS_KEY, statistics.rxPackets)
    putLong(TX_PACKETS_KEY, statistics.txPackets)
    putLong(RX_BYTES_DELTA_KEY, statistics.rxBytesDelta)
    putLong(TX_BYTES_DELTA_KEY, statistics.txBytesDelta)
    putLong(COUNTER_RESET_COUNT_KEY, statistics.counterResetCount)
}

fun Bundle.getStatistics(): Statistics =
    Statistics.build {
        setRxBytes(getLong(RX_BYTES_KEY))
        setTxBytes(getLong(TX_BYTES_KEY))
        setLastHandshakeSec(getLong(LAST_HANDSHAKE_SEC_KEY)) // AVPN
        // An old service has no explicit availability bit but did put the
        // byte keys.  Zero is still a valid idle sample, never "down".
        setAvailable(if (containsKey(AVAILABLE_KEY)) getBoolean(AVAILABLE_KEY) else containsKey(RX_BYTES_KEY))
        setSource(getString(SOURCE_KEY) ?: "legacy")
        setCounterEpoch(getString(COUNTER_EPOCH_KEY) ?: "")
        setRxPackets(getLong(RX_PACKETS_KEY))
        setTxPackets(getLong(TX_PACKETS_KEY))
        setRxBytesDelta(getLong(RX_BYTES_DELTA_KEY))
        setTxBytesDelta(getLong(TX_BYTES_DELTA_KEY))
        setCounterResetCount(getLong(COUNTER_RESET_COUNT_KEY))
    }
