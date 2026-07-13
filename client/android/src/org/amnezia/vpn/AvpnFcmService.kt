// AVPN (Task 9, FCM-волна 2026-07-13) — Android-половина пуш-моста: зеркало iOS
// AvpnPushController.mm. Токен/входящие/тап уходят в C++ singleton avpn::AvpnPushBridge
// через JNI-статики, зарегистрированные в platforms/android/avpn_fcm_bridge.cpp.
// ЖИВУЧЕСТЬ: natives поднимаются ПОЗЖЕ Kotlin-слоя (cold start: Activity → Qt → движок),
// поэтому всё, что прилетело раньше, копится в pending* и флашится из start().
package org.amnezia.vpn

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

class AvpnFcmService : FirebaseMessagingService() {

    // Новый/обновлённый FCM registration token (зеркало iOS didRegisterForRemoteNotifications).
    override fun onNewToken(token: String) {
        super.onNewToken(token)
        deliverToken(token)
    }

    // Входящий пуш при ЖИВОМ приложении (foreground). В background FCM сам показывает
    // системное уведомление (notification-message), тап по нему ловит handleLaunchIntent.
    override fun onMessageReceived(message: RemoteMessage) {
        super.onMessageReceived(message)
        val title = message.notification?.title ?: message.data["title"] ?: "Tribe VPN"
        val body = message.notification?.body ?: message.data["body"] ?: ""
        val type = message.data["type"] ?: ""
        val days = message.data["days"]?.toIntOrNull() ?: 0
        if (!nativesReady) return // движок ещё не поднялся — лента доедет с сервера (/v1/notifications)
        try {
            nativeOnMessageReceived(title, body, type, days)
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "native message drop: $e")
        }
    }

    companion object {
        private const val TAG = "AvpnFcm"

        // C++ (avpn_fcm_bridge.cpp) взводит флаг из start() ПОСЛЕ registerNativeMethods.
        @Volatile private var nativesReady = false
        @Volatile private var pendingToken: String? = null
        @Volatile private var pendingTapType: String? = null

        private fun deliverToken(token: String) {
            if (token.isEmpty()) return
            if (nativesReady) {
                try {
                    nativeOnNewToken(token)
                    return
                } catch (e: UnsatisfiedLinkError) {
                    Log.w(TAG, "native token drop: $e")
                }
            }
            pendingToken = token
        }

        // Зовёт C++ после регистрации natives: флаш отложенного + запрос текущего токена.
        // Firebase кидает, если google-services.json битый/нет Play Services — глушим (no-op).
        @JvmStatic
        fun start() {
            nativesReady = true
            pendingToken?.let { pendingToken = null; deliverToken(it) }
            pendingTapType?.let {
                pendingTapType = null
                try { nativeOnPushTapped(it) } catch (_: UnsatisfiedLinkError) {}
            }
            try {
                FirebaseMessaging.getInstance().token.addOnSuccessListener { deliverToken(it) }
            } catch (e: Exception) {
                Log.w(TAG, "FCM token fetch unavailable: $e")
            }
        }

        // "granted" | "denied" для AvpnPushBridge.authStatus (до Android 13 разрешение не нужно).
        @JvmStatic
        fun authStatus(ctx: Context): String =
            if (Build.VERSION.SDK_INT < 33 ||
                ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) ==
                PackageManager.PERMISSION_GRANTED
            ) "granted" else "denied"

        // Рантайм-запрос POST_NOTIFICATIONS (зеркало iOS UN authorization): движок зовёт ОДИН
        // раз после первого коннекта (AvpnPushBridge::requestAuthorization → authRequester).
        @JvmStatic
        fun requestPermission(ctx: Context) {
            if (Build.VERSION.SDK_INT < 33) return
            val activity = ctx as? Activity ?: return
            if (authStatus(activity) == "granted") return
            activity.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 7401)
        }

        // Тап по системному уведомлению (background-доставка): FCM кладёт data-ключи в extras
        // интента активити. Зовётся из AmneziaActivity onCreate/onNewIntent (метки // AVPN).
        @JvmStatic
        fun handleLaunchIntent(intent: Intent?) {
            val type = intent?.getStringExtra("type") ?: return
            if (nativesReady) {
                try {
                    nativeOnPushTapped(type)
                    return
                } catch (_: UnsatisfiedLinkError) {}
            }
            pendingTapType = type // cold start: C++ доберёт в start()
        }

        // JNI → C++ (регистрация в avpn_fcm_bridge.cpp).
        @JvmStatic private external fun nativeOnNewToken(token: String)
        @JvmStatic private external fun nativeOnMessageReceived(
            title: String, body: String, type: String, days: Int)
        @JvmStatic private external fun nativeOnPushTapped(type: String)
    }
}
