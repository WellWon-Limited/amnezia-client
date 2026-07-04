#include "AvpnShareBridge.h"

#ifdef Q_OS_IOS
// реализация — client/platforms/ios/AvpnShare.mm (подключается в avpn.cmake под if(IOS))
extern "C" bool AvpnShare_presentText(const char *utf8Text);
#endif

#ifdef Q_OS_ANDROID
    #include <QCoreApplication>
    #include <QJniObject>
#endif

namespace AvpnShare
{

#if defined(Q_OS_IOS)

    bool shareText(const QString &text)
    {
        return AvpnShare_presentText(text.toUtf8().constData());
    }

#elif defined(Q_OS_ANDROID)

    bool shareText(const QString &text)
    {
        QJniObject intent("android/content/Intent");
        if (!intent.isValid())
            return false;

        const QJniObject action = QJniObject::getStaticObjectField("android/content/Intent", "ACTION_SEND", "Ljava/lang/String;");
        intent.callObjectMethod("setAction", "(Ljava/lang/String;)Landroid/content/Intent;", action.object<jstring>());

        const QJniObject extraKey = QJniObject::getStaticObjectField("android/content/Intent", "EXTRA_TEXT", "Ljava/lang/String;");
        intent.callObjectMethod("putExtra", "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;",
                                extraKey.object<jstring>(), QJniObject::fromString(text).object<jstring>());
        intent.callObjectMethod("setType", "(Ljava/lang/String;)Landroid/content/Intent;",
                                QJniObject::fromString(QStringLiteral("text/plain")).object<jstring>());

        const QJniObject chooser = QJniObject::callStaticObjectMethod(
                "android/content/Intent", "createChooser",
                "(Landroid/content/Intent;Ljava/lang/CharSequence;)Landroid/content/Intent;",
                intent.object(), QJniObject::fromString(QString()).object<jstring>());

        QJniObject activity = QNativeInterface::QAndroidApplication::context();
        if (!activity.isValid() || !chooser.isValid())
            return false;

        // startActivity — на Android-main-thread (паттерн android_utils::runOnAndroidThreadAsync)
        QNativeInterface::QAndroidApplication::runOnAndroidMainThread([activity, chooser]() {
            activity.callMethod<void>("startActivity", "(Landroid/content/Intent;)V", chooser.object());
        });
        return true;
    }

#else

    bool shareText(const QString &text)
    {
        Q_UNUSED(text)
        return false; // desktop: нативного share-листа нет — QML делает copy+тост
    }

#endif

} // namespace AvpnShare
