package org.amnezia.vpn.util

import android.app.Application
import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlin.reflect.typeOf

private const val TAG = "Prefs"
private const val PREFS_FILE = "org.amnezia.vpn.prefs"
private const val SECURE_PREFS_FILE = "$PREFS_FILE.secure"
// AVPN (emulator round 3, C1): the VPN service processes' own file (ServicePrefs)
private const val SERVICE_PREFS_FILE = "org.amnezia.vpn.service.prefs"
private const val SECURE_SERVICE_PREFS_FILE = "$SERVICE_PREFS_FILE.secure"

private lateinit var prefsApp: Application

// AVPN (emulator round 3, C1): Android's SharedPreferences live per process - a process loads a file once, and each of
// its writes puts that process's WHOLE copy back. A write in one process therefore drops or reverts every key another
// process wrote after this one loaded the file: the notification question's "asked" mark vanished when the VPN service
// (started by the same tap, so it loaded the file before the question was shown) saved its config on the next leg.
// One writing process per file: Prefs is the app's (UI) process's, ServicePrefs the VPN service processes'; any other
// process only reads a file.
open class PrefsFile internal constructor(private val plainName: String, private val secureName: String) {
    val prefs: SharedPreferences
        get() = try {
            EncryptedSharedPreferences(
                prefsApp,
                secureName,
                MasterKey(prefsApp)
            )
        } catch (e: Exception) {
            Log.e(TAG, "Getting Encryption Storage failed: $e, plaintext fallback")
            prefsApp.getSharedPreferences(plainName, Context.MODE_PRIVATE)
        }

    fun contains(key: String): Boolean = prefs.contains(key)

    fun save(key: String, value: Boolean) =
        prefs.edit().putBoolean(key, value).apply()

    fun save(key: String, value: String?) =
        prefs.edit().putString(key, value).apply()

    fun save(key: String, value: Int) =
        prefs.edit().putInt(key, value).apply()

    fun save(key: String, value: Long) =
        prefs.edit().putLong(key, value).apply()

    fun save(key: String, value: Float) =
        prefs.edit().putFloat(key, value).apply()

    inline fun <reified T> load(key: String): T {
        return when (typeOf<T>()) {
            typeOf<Boolean>() -> prefs.getBoolean(key, false)
            typeOf<String>() -> prefs.getString(key, "")
            typeOf<Int>() -> prefs.getInt(key, 0)
            typeOf<Long>() -> prefs.getLong(key, 0L)
            typeOf<Float>() -> prefs.getFloat(key, 0f)
            else -> throw IllegalArgumentException("SharedPreferences does not support type: ${typeOf<T>()}")
        } as T
    }
}

// Written by the app's (UI) process only.
object Prefs : PrefsFile(PREFS_FILE, SECURE_PREFS_FILE) {
    fun init(app: Application) {
        Log.v(TAG, "Init Prefs")
        prefsApp = app
    }
}

// AVPN (C1): written by the VPN service processes only (AmneziaVpnService: the last config and server). A start that
// carries a config sets all of these keys; only the service processes' own keys are here, so no write of theirs can
// drop a key of the app's.
object ServicePrefs : PrefsFile(SERVICE_PREFS_FILE, SECURE_SERVICE_PREFS_FILE)
