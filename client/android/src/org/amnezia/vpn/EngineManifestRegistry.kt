package org.amnezia.vpn

import android.content.Context
import android.os.Build
import org.amnezia.vpn.protocol.EngineManifest
import org.amnezia.vpn.protocol.wireguard.Wireguard
import org.amnezia.vpn.protocol.xray.Xray
import org.json.JSONArray
import org.json.JSONObject

/** AVPN: reports BOTH embedded engines before a protocol is selected. */
object EngineManifestRegistry {
    private fun EngineManifest.toJson() = JSONObject()
        .put("protocol", protocol)
        .put("adapter", adapter)
        .put("adapterVersion", adapterVersion)
        .put("declaredCoreVersion", declaredCoreVersion)
        .put("sourceCommit", sourceCommit)
        .put("abi", abi)
        .put("capabilities", JSONArray(capabilities))
        .put("runtimeCoreVersion", runtimeCoreVersion ?: JSONObject.NULL)
        .put("runtimeVersionProbed", runtimeVersionProbed)
        .put("versionEvidence", if (runtimeVersionProbed) "runtime_api" else "compile_time_lock_only")

    @Suppress("DEPRECATION")
    fun json(context: Context): String {
        val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
        val appBuild = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo.longVersionCode
        } else {
            packageInfo.versionCode.toLong()
        }
        val engines = JSONArray()
            .put(Wireguard.probeEngineManifest(context).toJson())
            .put(Xray.probeEngineManifest(context).toJson())
        return JSONObject()
            .put("type", "engine_manifest_v1")
            .put("schema", 1)
            .put("app", JSONObject()
                .put("version", packageInfo.versionName ?: "")
                // Android store gating uses the installed package's actual
                // versionCode, never CMAKE_PROJECT_VERSION_TWEAK.
                .put("build", appBuild))
            .put("engines", engines)
            .toString()
    }
}
