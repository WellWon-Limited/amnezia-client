package org.amnezia.vpn.protocol.wireguard

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AwgUapiStatisticsTest {
    @Test
    fun parsesCanonicalSignedRange() {
        val statistics = parseAwgUapiStatistics(
            "rx_bytes=9007199254740993\ntx_bytes=9223372036854775807\nlast_handshake_time_sec=1\n",
        )
        assertTrue(statistics.available)
        assertEquals(9_007_199_254_740_993L, statistics.rxBytes)
        assertEquals(Long.MAX_VALUE, statistics.txBytes)
    }

    @Test
    fun malformedDuplicateOrUnsignedOverflowIsUnavailable() {
        listOf(
            "rx_bytes=01\ntx_bytes=2\nlast_handshake_time_sec=1\n",
            "rx_bytes=1\nrx_bytes=2\ntx_bytes=2\nlast_handshake_time_sec=1\n",
            "rx_bytes=18446744073709551615\ntx_bytes=2\nlast_handshake_time_sec=1\n",
            "rx_bytes=1\ntx_bytes=-2\nlast_handshake_time_sec=1\n",
        ).forEach { raw -> assertTrue(parseAwgUapiStatistics(raw).isEmpty()) }
    }
}
