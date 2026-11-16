package org.amnezia.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import java.io.File
import java.security.MessageDigest
import org.amnezia.vpn.util.Log

// AVPN (owner decision 2026-11-16): in-app update of the site APK (oss flavor only; Play updates
// itself). C++ (platforms/android/avpn_selfupdate_android.cpp) downloads the APK from /dl/, asks
// inspect() and decides with avpn::ApkUpdate (core/serviceEngine/ApkUpdatePolicy.h), then calls
// install(). Android shows its own confirmation; we never bypass it. After the update Android
// kills the process; TribeUpdateReceiver posts "updated, tap to open" (an app cannot relaunch
// itself from the background on Android 10+).

private const val TAG = "TribeSelfUpdate"
private const val UPDATE_ACTION_STATUS = "org.amnezia.vpn.TRIBE_SELF_UPDATE_STATUS"
private const val UPDATE_PENDING_MARKER = "self_update_pending"
private const val UPDATE_CHANNEL_ID = "tribe_update"
private const val UPDATE_NOTIFICATION_ID = 0x7e1b

object TribeSelfUpdate {
    @Volatile private var statusReceiver: BroadcastReceiver? = null

    @JvmStatic
    fun isSupported(): Boolean = !BuildConfig.IS_PLAY_BUILD

    @JvmStatic
    fun canInstall(context: Context): Boolean = context.packageManager.canRequestPackageInstalls()

    // "Install unknown apps" for Tribe VPN: Android's own screen, the person flips one switch.
    @JvmStatic
    fun openInstallPermission(context: Context) {
        runCatching {
            val intent = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(intent)
        }.onFailure { Log.w(TAG, "Cannot open install permission screen: $it") }
    }

    @JvmStatic
    fun installedVersionCode(context: Context): Long =
        runCatching { context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode }
            .getOrDefault(Long.MAX_VALUE)

    // "ok|<package>|<versionCode>|<versionName>|<1 if signed by our certificate else 0>" or "err|<why>".
    @JvmStatic
    fun inspect(context: Context, path: String): String {
        return runCatching {
            val pm = context.packageManager
            val apk = pm.getPackageArchiveInfo(path, PackageManager.GET_SIGNING_CERTIFICATES)
                ?: return "err|parse"
            val own = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            val match = certDigests(apk.signingInfo).intersect(certDigests(own.signingInfo)).isNotEmpty()
            val name = (apk.versionName ?: "").replace("|", "")
            "ok|${apk.packageName}|${apk.longVersionCode}|$name|${if (match) 1 else 0}"
        }.getOrElse {
            Log.e(TAG, "inspect failed: $it")
            "err|exception"
        }
    }

    // Copies the APK into a PackageInstaller session off the UI thread and commits it. Statuses come
    // back through nativeOnInstallStatus (PackageInstaller.STATUS_*; -1 = waiting for the person).
    @JvmStatic
    fun install(context: Context, path: String, versionName: String): Boolean {
        val app = context.applicationContext
        val file = File(path)
        if (!file.isFile) return false
        registerStatusReceiver(app)
        Thread({
            try {
                val installer = app.packageManager.packageInstaller
                val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
                    setAppPackageName(app.packageName)
                    setInstallReason(PackageManager.INSTALL_REASON_USER)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                        setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
                }
                val sessionId = installer.createSession(params)
                installer.openSession(sessionId).use { session ->
                    file.inputStream().use { input ->
                        session.openWrite("base.apk", 0, file.length()).use { out ->
                            input.copyTo(out)
                            session.fsync(out)
                        }
                    }
                    File(app.filesDir, UPDATE_PENDING_MARKER).writeText(versionName)
                    val intent = Intent(UPDATE_ACTION_STATUS).setPackage(app.packageName)
                    val pending = PendingIntent.getBroadcast(
                        app, sessionId, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
                    )
                    session.commit(pending.intentSender)
                }
                Log.i(TAG, "session $sessionId committed for $versionName")
            } catch (e: Exception) {
                Log.e(TAG, "install session failed: $e")
                File(app.filesDir, UPDATE_PENDING_MARKER).delete()
                report(PackageInstaller.STATUS_FAILURE, e.javaClass.simpleName)
            }
        }, "tribe-self-update").start()
        return true
    }

    private fun registerStatusReceiver(app: Context) {
        if (statusReceiver != null) return
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
                val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: ""
                Log.i(TAG, "installer status $status $message")
                if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
                    @Suppress("DEPRECATION")
                    val confirm: Intent? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                        intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                    else intent.getParcelableExtra(Intent.EXTRA_INTENT)
                    if (confirm == null) {
                        report(PackageInstaller.STATUS_FAILURE, "no confirmation intent")
                        return
                    }
                    runCatching { ctx.startActivity(confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
                        .onFailure { report(PackageInstaller.STATUS_FAILURE, "confirmation: $it"); return }
                    report(status, message)
                    return
                }
                if (status != PackageInstaller.STATUS_SUCCESS) File(ctx.filesDir, UPDATE_PENDING_MARKER).delete()
                report(status, message)
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
            app.registerReceiver(receiver, IntentFilter(UPDATE_ACTION_STATUS), Context.RECEIVER_NOT_EXPORTED)
        else
            app.registerReceiver(receiver, IntentFilter(UPDATE_ACTION_STATUS))
        statusReceiver = receiver
    }

    private fun report(status: Int, message: String) {
        runCatching { nativeOnInstallStatus(status, message) }
            .onFailure { Log.w(TAG, "native status callback unavailable: $it") }
    }

    // All certificates the APK/app presents (current signers + rotation history), as SHA-256 hex.
    private fun certDigests(info: android.content.pm.SigningInfo?): Set<String> {
        if (info == null) return emptySet()
        val sigs = mutableListOf<Signature>()
        info.apkContentsSigners?.let { sigs += it }
        if (!info.hasMultipleSigners()) info.signingCertificateHistory?.let { sigs += it }
        val md = MessageDigest.getInstance("SHA-256")
        return sigs.map { sig -> md.digest(sig.toByteArray()).joinToString("") { "%02x".format(it) } }.toSet()
    }

    // Called by TribeUpdateReceiver after Android replaced the package. Only for updates this app
    // started itself (marker), never for adb / store / site reinstalls.
    internal fun onPackageReplaced(context: Context) {
        File(context.cacheDir, "tribe-update").deleteRecursively()
        val marker = File(context.filesDir, UPDATE_PENDING_MARKER)
        if (!marker.isFile) return
        marker.delete()
        val nm = NotificationManagerCompat.from(context)
        if (!nm.areNotificationsEnabled()) return
        val manager = context.getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(UPDATE_CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(
                    UPDATE_CHANNEL_ID, context.getString(R.string.tribeUpdateChannel), NotificationManager.IMPORTANCE_DEFAULT
                )
            )
        }
        val launch = context.packageManager.getLaunchIntentForPackage(context.packageName) ?: return
        val tap = PendingIntent.getActivity(context, 0, launch, PendingIntent.FLAG_IMMUTABLE)
        val version = runCatching {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName
        }.getOrNull() ?: ""
        val notification = NotificationCompat.Builder(context, UPDATE_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_tribe_status)
            .setContentTitle(context.getString(R.string.tribeUpdateDoneTitle))
            .setContentText(context.getString(R.string.tribeUpdateDoneText, version.split('.').take(3).joinToString(".")))
            .setContentIntent(tap)
            .setAutoCancel(true)
            .build()
        runCatching { nm.notify(UPDATE_NOTIFICATION_ID, notification) }
            .onFailure { Log.w(TAG, "update notification failed: $it") }
    }

    @JvmStatic private external fun nativeOnInstallStatus(status: Int, message: String)
}

// Declared only in the oss manifest (client/android/oss/AndroidManifest.xml).
class TribeUpdateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) TribeSelfUpdate.onPackageReplaced(context)
    }
}
