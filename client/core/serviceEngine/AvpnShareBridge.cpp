#include "AvpnShareBridge.h"

#ifdef Q_OS_IOS
// реализация — client/platforms/ios/AvpnShare.mm (подключается в avpn.cmake под if(IOS))
extern "C" bool AvpnShare_presentText(const char *utf8Text);
extern "C" bool AvpnShare_presentTextAndImage(const char *utf8Text, const char *utf8ImagePath);
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

    bool shareTextWithImage(const QString &text, const QString &imagePath)
    {
        return AvpnShare_presentTextAndImage(text.toUtf8().constData(),
                                             imagePath.toUtf8().constData());
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

    bool shareTextWithImage(const QString &text, const QString &imagePath)
    {
        // content:// через штатный FileProvider Qt-манифеста (authorities=${applicationId}.qtprovider,
        // покрывает files-dir). Прямой file:// URI с API 24+ кидает FileUriExposedException.
        QJniObject context = QNativeInterface::QAndroidApplication::context();
        if (!context.isValid())
            return false;

        // authority ДИНАМИЧЕСКИ из packageName: жёсткая строка сломалась при ренейме пакета
        // org.antivpn.client → com.tribevpn.client (28122224) — share тихо деградировал в текст.
        const QJniObject pkg = context.callObjectMethod("getPackageName", "()Ljava/lang/String;");
        if (!pkg.isValid())
            return shareText(text);
        const QString authority = pkg.toString() + QStringLiteral(".qtprovider");

        const QJniObject file = QJniObject("java/io/File", "(Ljava/lang/String;)V",
                                           QJniObject::fromString(imagePath).object<jstring>());
        const QJniObject uri = QJniObject::callStaticObjectMethod(
                "androidx/core/content/FileProvider", "getUriForFile",
                "(Landroid/content/Context;Ljava/lang/String;Ljava/io/File;)Landroid/net/Uri;",
                context.object(), QJniObject::fromString(authority).object<jstring>(),
                file.object());
        if (!uri.isValid())
            return shareText(text); // не вышло с картинкой — хотя бы ссылка

        QJniObject intent("android/content/Intent");
        if (!intent.isValid())
            return false;
        const QJniObject action = QJniObject::getStaticObjectField("android/content/Intent", "ACTION_SEND", "Ljava/lang/String;");
        intent.callObjectMethod("setAction", "(Ljava/lang/String;)Landroid/content/Intent;", action.object<jstring>());
        intent.callObjectMethod("setType", "(Ljava/lang/String;)Landroid/content/Intent;",
                                QJniObject::fromString(QStringLiteral("image/png")).object<jstring>());

        const QJniObject streamKey = QJniObject::getStaticObjectField("android/content/Intent", "EXTRA_STREAM", "Ljava/lang/String;");
        intent.callObjectMethod("putExtra", "(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;",
                                streamKey.object<jstring>(), uri.object());
        const QJniObject textKey = QJniObject::getStaticObjectField("android/content/Intent", "EXTRA_TEXT", "Ljava/lang/String;");
        intent.callObjectMethod("putExtra", "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;",
                                textKey.object<jstring>(), QJniObject::fromString(text).object<jstring>());

        // ClipData + grant-флаг: иначе принимающее приложение не имеет прав читать content:// URI
        const QJniObject clip = QJniObject::callStaticObjectMethod(
                "android/content/ClipData", "newRawUri",
                "(Ljava/lang/CharSequence;Landroid/net/Uri;)Landroid/content/ClipData;",
                QJniObject::fromString(QString()).object<jstring>(), uri.object());
        if (clip.isValid())
            intent.callObjectMethod("setClipData", "(Landroid/content/ClipData;)V", clip.object());
        intent.callObjectMethod("addFlags", "(I)Landroid/content/Intent;", 0x00000001 /*FLAG_GRANT_READ_URI_PERMISSION*/);

        const QJniObject chooser = QJniObject::callStaticObjectMethod(
                "android/content/Intent", "createChooser",
                "(Landroid/content/Intent;Ljava/lang/CharSequence;)Landroid/content/Intent;",
                intent.object(), QJniObject::fromString(QString()).object<jstring>());
        QJniObject activity = QNativeInterface::QAndroidApplication::context();
        if (!activity.isValid() || !chooser.isValid())
            return false;
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

    bool shareTextWithImage(const QString &text, const QString &imagePath)
    {
        Q_UNUSED(text)
        Q_UNUSED(imagePath)
        return false; // desktop: QML-fallback (копирование ссылки + тост)
    }

#endif

} // namespace AvpnShare
