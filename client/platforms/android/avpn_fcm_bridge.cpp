// AVPN (Task 9, FCM-волна 2026-07-13) — Android-мост пушей: JNI-приём из AvpnFcmService.kt
// → кросс-платформенный avpn::AvpnPushBridge (тот сам маршалит в Qt-поток и шлёт
// deviceTokenReady → движок регистрирует токен на бэке POST /v1/devices/push-token,
// platform="android" → бэк выбирает провайдера fcm). Зеркало iOS AvpnPushController.mm.
#include "avpn_fcm_bridge.h"

#include <QCoreApplication>
#include <QDebug>
#include <QJniEnvironment>
#include <QJniObject>

#include "core/serviceEngine/AvpnPushBridge.h"

namespace
{
    constexpr auto FCM_SERVICE_CLASS = "org/amnezia/vpn/AvpnFcmService";

    // Kotlin: onNewToken/начальный fetch. FCM не делит sandbox/production (в отличие от APNs) —
    // окружение шлём "production" ДО токена (контракт моста: env строго перед setDeviceToken).
    void onNewToken(JNIEnv *env, jclass, jstring jtoken)
    {
        Q_UNUSED(env)
        const QString token = QJniObject(jtoken).toString();
        auto *bridge = avpn::AvpnPushBridge::instance();
        bridge->setPushEnvironment(QStringLiteral("production"));
        bridge->setDeviceToken(token, QStringLiteral("android"));
    }

    // Kotlin: входящий пуш при живом приложении → лента/бейдж (+ typed-сигналы
    // support/payment/announcement внутри applyRemoteNotification, как на iOS).
    void onMessageReceived(JNIEnv *env, jclass, jstring jtitle, jstring jbody, jstring jtype,
                           jint days)
    {
        Q_UNUSED(env)
        avpn::AvpnPushBridge::instance()->onRemoteNotification(
            QJniObject(jtitle).toString(), QJniObject(jbody).toString(),
            QJniObject(jtype).toString(), static_cast<int>(days));
    }

    // Kotlin: тап по системному уведомлению (background-доставка) → диплинк-навигация в QML
    // (pushTapped; cold start добирается через takePendingPushTap в PageStart, как на iOS).
    void onPushTapped(JNIEnv *env, jclass, jstring jtype)
    {
        Q_UNUSED(env)
        avpn::AvpnPushBridge::instance()->onPushTapped(QJniObject(jtype).toString());
    }

    QJniObject androidContext()
    {
        // Qt 6.7+: context() отдаёт QJniObject (Activity, когда она есть; иначе Application).
        return QJniObject(QNativeInterface::QAndroidApplication::context());
    }

    // Рантайм-запрос POST_NOTIFICATIONS (Android 13+): движок зовёт один раз после первого
    // коннекта через AvpnPushBridge::requestAuthorization (тот же UX-момент, что iOS).
    void requestNotificationPermission()
    {
        const QJniObject ctx = androidContext();
        if (!ctx.isValid())
            return;
        QJniObject::callStaticMethod<void>(FCM_SERVICE_CLASS, "requestPermission",
                                           "(Landroid/content/Context;)V", ctx.object());
    }

    void publishAuthStatus()
    {
        const QJniObject ctx = androidContext();
        if (!ctx.isValid())
            return;
        const QJniObject status = QJniObject::callStaticObjectMethod(
            FCM_SERVICE_CLASS, "authStatus", "(Landroid/content/Context;)Ljava/lang/String;",
            ctx.object());
        if (status.isValid())
            avpn::AvpnPushBridge::instance()->setAuthStatus(status.toString());
    }
} // namespace

bool avpn::registerFcmNatives()
{
    const JNINativeMethod methods[] = {
        {"nativeOnNewToken", "(Ljava/lang/String;)V", reinterpret_cast<void *>(onNewToken)},
        {"nativeOnMessageReceived", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V",
         reinterpret_cast<void *>(onMessageReceived)},
        {"nativeOnPushTapped", "(Ljava/lang/String;)V", reinterpret_cast<void *>(onPushTapped)},
    };
    QJniEnvironment env;
    if (!env.registerNativeMethods(FCM_SERVICE_CLASS, methods,
                                   sizeof(methods) / sizeof(JNINativeMethod))) {
        qWarning() << "AvpnFcm: native method registration failed";
        return false;
    }
    // Запросчик разрешения — мост зовёт после первого коннекта (см. AvpnEngineQml).
    avpn::AvpnPushBridge::instance()->setAuthorizationRequester(&requestNotificationPermission);
    publishAuthStatus();
    // Kotlin-половина: флаш отложенного (токен/тап до natives) + запрос текущего токена.
    QJniObject::callStaticMethod<void>(FCM_SERVICE_CLASS, "start", "()V");
    return true;
}
