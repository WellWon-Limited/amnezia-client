// AVPN (Доктор D-3): сигналы сети — см. TribeNetInfo.h. Поколение сотовой:
// iOS — мост TribeNetInfoIos.mm; Android — JNI к TelephonyManager (getDataNetworkType:
// на API 33+ хватает normal-разрешения READ_BASIC_PHONE_STATE, ниже может кинуть
// SecurityException — тогда честное ""); десктопы — "".
#include "TribeNetInfo.h"

#include <QNetworkInformation>

#if defined(Q_OS_IOS)
extern "C" const char *TribeNetInfo_cellGen(); // TribeNetInfoIos.mm
#endif

#if defined(Q_OS_ANDROID)
#include <QCoreApplication>
#include <QJniEnvironment>
#include <QJniObject>
#endif

namespace avpn {

#if defined(Q_OS_ANDROID)
// TelephonyManager.getSystemService("phone"); все JNI-исключения гасятся -> дефолт.
static QJniObject telephonyManager()
{
    QJniObject ctx = QNativeInterface::QAndroidApplication::context();
    if (!ctx.isValid())
        return {};
    QJniObject svc = ctx.callObjectMethod(
        "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;",
        QJniObject::fromString(QStringLiteral("phone")).object<jstring>());
    QJniEnvironment env;
    if (env.checkAndClearExceptions())
        return {};
    return svc;
}
#endif

QString cellularGeneration()
{
#if defined(Q_OS_IOS)
    return QString::fromLatin1(TribeNetInfo_cellGen());
#elif defined(Q_OS_ANDROID)
    QJniObject tm = telephonyManager();
    if (!tm.isValid())
        return {};
    const jint t = tm.callMethod<jint>("getDataNetworkType");
    QJniEnvironment env;
    if (env.checkAndClearExceptions())
        return {}; // SecurityException (нет READ_*_PHONE_STATE) — честное «неизвестно»
    switch (t) {
    case 20:                                        return QStringLiteral("5g");  // NR
    case 13: case 19:                               return QStringLiteral("lte"); // LTE/LTE_CA
    case 3: case 8: case 9: case 10: case 15:
    case 17:                                        return QStringLiteral("3g");  // UMTS/HSPA/TD_SCDMA
    case 1: case 2: case 4: case 7: case 11:
    case 16:                                        return QStringLiteral("2g");  // GPRS/EDGE/CDMA/GSM
    default:                                        return {};
    }
#else
    return {};
#endif
}

int meteredState()
{
    if (auto *ni = QNetworkInformation::instance()) {
        if (ni->supportedFeatures().testFlag(QNetworkInformation::Feature::Metered))
            return ni->isMetered() ? 1 : 0;
    }
    return -1;
}

int roamingState()
{
#if defined(Q_OS_ANDROID)
    QJniObject tm = telephonyManager();
    if (!tm.isValid())
        return -1;
    const jboolean r = tm.callMethod<jboolean>("isNetworkRoaming");
    QJniEnvironment env;
    if (env.checkAndClearExceptions())
        return -1;
    return r ? 1 : 0;
#else
    return -1; // iOS: CTCarrier/roaming API мёртв с iOS 16 — не закладываемся (роадмап §C-доп)
#endif
}

} // namespace avpn
