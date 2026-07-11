#include "TribeHaptics.h"

#include "TuningStore.h"

#ifdef Q_OS_IOS
// реализация — client/platforms/ios/TribeHapticsIos.mm (подключается в avpn.cmake под if(IOS))
extern "C" void TribeHaptics_play(int kind);
#endif

#ifdef Q_OS_ANDROID
    #include <QCoreApplication>
    #include <QJniObject>
#endif

namespace avpn {

namespace {

enum HapticKind { kSelection = 0, kLight, kMedium, kSuccess, kWarning, kError, kUnknown };

HapticKind parseKind(const QString &kind)
{
    if (kind == QLatin1String("selection")) return kSelection;
    if (kind == QLatin1String("light"))     return kLight;
    if (kind == QLatin1String("medium"))    return kMedium;
    if (kind == QLatin1String("success"))   return kSuccess;
    if (kind == QLatin1String("warning"))   return kWarning;
    if (kind == QLatin1String("error"))     return kError;
    return kUnknown;
}

#ifdef Q_OS_ANDROID
// View.performHapticFeedback на decorView активити: уважает системную «вибрацию при
// касании», разрешение VIBRATE не требуется. Константы HapticFeedbackConstants —
// сырыми числами (стабильный публичный API, паттерн AvpnShareBridge FLAG_GRANT_*).
void playAndroid(HapticKind kind)
{
    int constant;
    const int sdk = QNativeInterface::QAndroidApplication::sdkVersion();
    switch (kind) {
    case kSelection: constant = 4; break;                    // CLOCK_TICK
    case kLight:     constant = 1; break;                    // VIRTUAL_KEY
    case kMedium:    constant = 6; break;                    // CONTEXT_CLICK (API 23+)
    case kSuccess:   constant = (sdk >= 30) ? 16 : 1; break; // CONFIRM | фолбэк VIRTUAL_KEY
    case kWarning:   constant = 0; break;                    // LONG_PRESS
    case kError:     constant = (sdk >= 30) ? 17 : 0; break; // REJECT | фолбэк LONG_PRESS
    default:         return;
    }

    QJniObject activity = QNativeInterface::QAndroidApplication::context();
    if (!activity.isValid())
        return;
    // View-методы — только на Android-main-thread (паттерн AvpnShareBridge::startActivity)
    QNativeInterface::QAndroidApplication::runOnAndroidMainThread([activity, constant]() {
        const QJniObject window = activity.callObjectMethod("getWindow", "()Landroid/view/Window;");
        if (!window.isValid())
            return;
        const QJniObject decor = window.callObjectMethod("getDecorView", "()Landroid/view/View;");
        if (!decor.isValid())
            return;
        decor.callMethod<jboolean>("performHapticFeedback", "(I)Z", static_cast<jint>(constant));
    });
}
#endif

} // namespace

TribeHaptics::TribeHaptics(QObject *parent) : QObject(parent) { }

void TribeHaptics::play(const QString &kind)
{
    const HapticKind k = parseKind(kind);
    if (k == kUnknown)
        return;
    if (!TuningStore::flag(QStringLiteral("haptics"), true)) // kill-switch с бэка
        return;
    if (m_last.isValid() && m_last.elapsed() < 30) // дребезг двойных тапов
        return;
    m_last.start();

#if defined(Q_OS_IOS)
    TribeHaptics_play(static_cast<int>(k));
#elif defined(Q_OS_ANDROID)
    playAndroid(k);
#else
    // desktop / dev-превью: no-op
#endif
}

} // namespace avpn
