package org.amnezia.vpn.util

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import org.json.JSONObject

// AVPN (android2 P7, 21.11): the service returns the identity of the session it runs - what the start config said.
class TribeSessionTest {

    @Test
    fun metadataOfTheStartConfig() {
        val config = JSONObject(
            """{"protocol":"awg","tribeStartLeg":3,
               "tribeSessionMetadata":{"schema_version":1,"node_id":"12","proto":"awg","endpoint":"node.example:585"}}"""
        )
        val meta = JSONObject(TribeSession.metadataOf(config)!!)
        assertEquals("12", meta.getString("node_id"))
        assertEquals("awg", meta.getString("proto"))
        assertEquals("node.example:585", meta.getString("endpoint"))
        assertEquals(1, meta.getInt("schema_version"))
    }

    @Test
    fun noMetadataIsUnknown() {
        assertNull(TribeSession.metadataOf(null))
        assertNull(TribeSession.metadataOf(JSONObject("""{"protocol":"xray"}""")))
        assertNull(TribeSession.metadataOf(JSONObject("""{"tribeSessionMetadata":{}}""")))
    }
}
