package org.amnezia.vpn.protocol

import android.os.Bundle

/** AVPN: versioned engine facts carried over the existing service IPC. */
data class EngineManifest(
    val schema: Int = 1,
    val protocol: String,
    val adapter: String,
    val adapterVersion: String,
    val declaredCoreVersion: String,
    val sourceCommit: String,
    val abi: String,
    val capabilities: List<String>,
    val runtimeCoreVersion: String? = null,
    val runtimeVersionProbed: Boolean = false,
)

/** AVPN: single source for Android compile-time engine facts. */
object EmbeddedEngineManifests {
    const val AWG_ADAPTER_VERSION = "3.1.20260814"
    const val AWG_SOURCE_COMMIT = "5c16489e2cd9ed3a0a7a27c7445bba5238132f86"
    const val AWG_CORE_VERSION = "3.1.20260814"
    const val XRAY_ADAPTER_VERSION = "1.0.3-tribe.1"
    const val XRAY_SOURCE_COMMIT = "e8cc06d7427251fa549093e7cc32c28b0f5fbafa"
    const val XRAY_CORE_VERSION = "1.260728.0"

    /**
     * Runtime evidence is deliberately not a general version normalizer.  The
     * AWG Go bridge returns the Go module version (`v3.1...`) for a tagged
     * dependency, while the immutable lock stores `3.1...`.  Accept only that
     * audited one-byte prefix difference (or an already exact value).  Xray's
     * core.Version() is required to byte-match its lock.
     */
    internal fun runtimeEvidence(
        value: String?,
        declared: String,
        allowGoModulePrefix: Boolean,
    ): String? {
        val raw = value ?: return null
        return when {
            raw == declared -> declared
            allowGoModulePrefix && raw == "v$declared" -> declared
            else -> null
        }
    }

    fun awg(runtimeVersion: String?): EngineManifest {
        val evidence = runtimeEvidence(runtimeVersion, AWG_CORE_VERSION, allowGoModulePrefix = true)
        return EngineManifest(
            protocol = "awg",
            adapter = "awg-android",
            adapterVersion = AWG_ADAPTER_VERSION,
            declaredCoreVersion = AWG_CORE_VERSION,
            sourceCommit = AWG_SOURCE_COMMIT,
            abi = "awg-android-jni-uapi-v3.1-protected-start.1",
            capabilities = listOf(
                "awg.random_trailers", "awg.disable_cookies", "uapi.readback",
                "tribe.guarded_settings_owner",
            ),
            runtimeCoreVersion = evidence,
            runtimeVersionProbed = evidence != null,
        )
    }

    fun xray(runtimeVersion: String?): EngineManifest {
        val evidence = runtimeEvidence(runtimeVersion, XRAY_CORE_VERSION, allowGoModulePrefix = false)
        return EngineManifest(
            protocol = "xray",
            adapter = "amnezia-libxray",
            adapterVersion = XRAY_ADAPTER_VERSION,
            declaredCoreVersion = XRAY_CORE_VERSION,
            sourceCommit = XRAY_SOURCE_COMMIT,
            abi = "gomobile-libxray-v2-controller-slot",
            capabilities = listOf(
                "xray.vless.reality.vision.tcp", "xray.embedded", "xray.runtime_version",
                "xray.socket_protection_slot", "tribe.guarded_settings_owner",
            ),
            runtimeCoreVersion = evidence,
            runtimeVersionProbed = evidence != null,
        )
    }
}

private const val ENGINE_SCHEMA = "engine_manifest_schema"
private const val ENGINE_PROTOCOL = "engine_protocol"
private const val ENGINE_ADAPTER = "engine_adapter"
private const val ENGINE_ADAPTER_VERSION = "engine_adapter_version"
private const val ENGINE_DECLARED_CORE_VERSION = "engine_declared_core_version"
private const val ENGINE_SOURCE_COMMIT = "engine_source_commit"
private const val ENGINE_ABI = "engine_abi"
private const val ENGINE_CAPABILITIES = "engine_capabilities"
private const val ENGINE_RUNTIME_CORE_VERSION = "engine_runtime_core_version"
private const val ENGINE_RUNTIME_PROBED = "engine_runtime_version_probed"

fun Bundle.putEngineManifest(manifest: EngineManifest?) {
    if (manifest == null) return
    putInt(ENGINE_SCHEMA, manifest.schema)
    putString(ENGINE_PROTOCOL, manifest.protocol)
    putString(ENGINE_ADAPTER, manifest.adapter)
    putString(ENGINE_ADAPTER_VERSION, manifest.adapterVersion)
    putString(ENGINE_DECLARED_CORE_VERSION, manifest.declaredCoreVersion)
    putString(ENGINE_SOURCE_COMMIT, manifest.sourceCommit)
    putString(ENGINE_ABI, manifest.abi)
    putStringArrayList(ENGINE_CAPABILITIES, ArrayList(manifest.capabilities))
    putString(ENGINE_RUNTIME_CORE_VERSION, manifest.runtimeCoreVersion)
    putBoolean(ENGINE_RUNTIME_PROBED, manifest.runtimeVersionProbed)
}

fun Bundle.getEngineManifest(): EngineManifest? {
    if (getInt(ENGINE_SCHEMA, 0) != 1) return null // AVPN: unknown ABI/schema fails closed.
    return EngineManifest(
        protocol = getString(ENGINE_PROTOCOL) ?: return null,
        adapter = getString(ENGINE_ADAPTER) ?: return null,
        adapterVersion = getString(ENGINE_ADAPTER_VERSION) ?: return null,
        declaredCoreVersion = getString(ENGINE_DECLARED_CORE_VERSION) ?: return null,
        sourceCommit = getString(ENGINE_SOURCE_COMMIT) ?: return null,
        abi = getString(ENGINE_ABI) ?: return null,
        capabilities = getStringArrayList(ENGINE_CAPABILITIES)?.toList() ?: return null,
        runtimeCoreVersion = getString(ENGINE_RUNTIME_CORE_VERSION),
        runtimeVersionProbed = getBoolean(ENGINE_RUNTIME_PROBED, false),
    )
}
