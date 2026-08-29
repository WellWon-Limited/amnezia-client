package org.amnezia.vpn.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class EngineManifestVersionEvidenceTest {
    @Test
    fun awgAcceptsOnlyExactGoModulePrefixGrammar() {
        val declared = EmbeddedEngineManifests.AWG_CORE_VERSION
        assertEquals(declared, EmbeddedEngineManifests.runtimeEvidence(declared, declared, true))
        assertEquals(declared, EmbeddedEngineManifests.runtimeEvidence("v$declared", declared, true))
        assertNull(EmbeddedEngineManifests.runtimeEvidence(" $declared", declared, true))
        assertNull(EmbeddedEngineManifests.runtimeEvidence("v$declared-dirty", declared, true))
        assertNull(EmbeddedEngineManifests.runtimeEvidence("unknown", declared, true))
        assertNull(EmbeddedEngineManifests.runtimeEvidence("1b86b2a", declared, true))
    }

    @Test
    fun xrayRequiresByteExactCoreVersion() {
        val declared = EmbeddedEngineManifests.XRAY_CORE_VERSION
        assertEquals(declared, EmbeddedEngineManifests.runtimeEvidence(declared, declared, false))
        assertNull(EmbeddedEngineManifests.runtimeEvidence("v$declared", declared, false))
        assertNull(EmbeddedEngineManifests.runtimeEvidence("Xray $declared", declared, false))
    }
}
