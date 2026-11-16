#pragma once
// AVPN (owner decision 2026-11-16): Android in-app update from our own /dl/ (the site APK, not Play).
// Pure decisions only — URL guard, parsing of the Kotlin inspect line, the install verdict and the
// human texts — so they are testable without a device: tests/build_apk_update_policy.sh.
// The platform glue lives in client/platforms/android/avpn_selfupdate_android.cpp (download, JNI)
// and client/android/src/org/amnezia/vpn/TribeSelfUpdate.kt (PackageManager, PackageInstaller).
//
// Invariants (any violation = do not install, honest error to the person):
//   1. Download only over https from exactly tribevpn.com (no subdomains, no userinfo, no port),
//      an .apk path; the final URL after redirects is checked again.
//   2. Install only our package, signed by the SAME certificate as the running app (Android would
//      refuse otherwise anyway; we refuse before the system dialog), strictly newer versionCode.
//   3. When the server names a version (recommended_version), the APK must be exactly that version.
//   4. Never silently: the system confirmation is Android's own; the app never bypasses it.

#include <QCoreApplication>
#include <QString>
#include <QStringList>
#include <QUrl>

namespace avpn::ApkUpdate {

// PackageInstaller.STATUS_* (android.content.pm.PackageInstaller); PENDING_USER_ACTION = -1.
constexpr int kStatusPendingUserAction = -1;
constexpr int kStatusSuccess = 0;
constexpr int kStatusFailure = 1;
constexpr int kStatusBlocked = 2;
constexpr int kStatusAborted = 3;
constexpr int kStatusInvalid = 4;
constexpr int kStatusConflict = 5;
constexpr int kStatusStorage = 6;
constexpr int kStatusIncompatible = 7;

// The site APK is ~75 MB; anything far above that is not ours.
constexpr qint64 kMaxApkBytes = 300LL * 1024 * 1024;

inline bool urlAllowed(const QUrl &url)
{
    if (!url.isValid() || url.scheme() != QLatin1String("https"))
        return false;
    if (!url.userInfo().isEmpty() || (url.port() != -1 && url.port() != 443))
        return false;
    if (url.host().compare(QLatin1String("tribevpn.com"), Qt::CaseInsensitive) != 0)
        return false;
    return url.path().endsWith(QLatin1String(".apk"), Qt::CaseInsensitive);
}

inline bool sizeAllowed(qint64 bytes)
{
    return bytes <= kMaxApkBytes;
}

struct ApkInfo
{
    bool parsed = false;
    QString packageName;
    qint64 versionCode = -1;
    QString versionName;
    bool signerMatches = false;
};

// Kotlin TribeSelfUpdate.inspect(): "ok|<package>|<versionCode>|<versionName>|<1|0>" or "err|<why>".
inline ApkInfo parseInspect(const QString &line)
{
    ApkInfo info;
    const QStringList p = line.split(QLatin1Char('|'));
    if (p.size() != 5 || p.at(0) != QLatin1String("ok"))
        return info;
    bool ok = false;
    const qint64 code = p.at(2).toLongLong(&ok);
    if (!ok || code <= 0 || p.at(1).isEmpty())
        return info;
    info.parsed = true;
    info.packageName = p.at(1);
    info.versionCode = code;
    info.versionName = p.at(3);
    info.signerMatches = p.at(4) == QLatin1String("1");
    return info;
}

enum class Verdict { Ok, Unreadable, WrongPackage, WrongSigner, NotNewer, WrongVersion };

inline Verdict verdict(const ApkInfo &apk, const QString &ownPackage, qint64 installedCode,
                       const QString &expectedVersion)
{
    if (!apk.parsed)
        return Verdict::Unreadable;
    if (apk.packageName != ownPackage)
        return Verdict::WrongPackage;
    if (!apk.signerMatches)
        return Verdict::WrongSigner;
    if (apk.versionCode <= installedCode)
        return Verdict::NotNewer;
    if (!expectedVersion.isEmpty() && apk.versionName != expectedVersion
        && !apk.versionName.startsWith(expectedVersion + QLatin1Char('.')))
        return Verdict::WrongVersion;
    return Verdict::Ok;
}

inline QString verdictText(Verdict v)
{
    switch (v) {
    case Verdict::Ok:
        return QString();
    case Verdict::Unreadable:
        return QCoreApplication::translate("AvpnApkUpdate", "Скачанный файл повреждён. Попробуйте ещё раз.");
    case Verdict::WrongPackage:
    case Verdict::WrongSigner:
        return QCoreApplication::translate("AvpnApkUpdate", "Скачанный файл не прошёл проверку подписи — установка отменена.");
    case Verdict::NotNewer:
        return QCoreApplication::translate("AvpnApkUpdate", "У вас уже последняя версия.");
    case Verdict::WrongVersion:
        return QCoreApplication::translate("AvpnApkUpdate", "На сайте пока другая версия. Попробуйте обновиться позже.");
    }
    return QCoreApplication::translate("AvpnApkUpdate", "Не удалось обновить. Попробуйте скачать вручную.");
}

inline QString installStatusText(int status)
{
    switch (status) {
    case kStatusAborted:
        return QCoreApplication::translate("AvpnApkUpdate", "Обновление отменено.");
    case kStatusBlocked:
        return QCoreApplication::translate("AvpnApkUpdate", "Android не разрешил установку. Проверьте, что Tribe VPN разрешено устанавливать приложения.");
    case kStatusStorage:
        return QCoreApplication::translate("AvpnApkUpdate", "Не хватает места на телефоне для обновления.");
    case kStatusConflict:
    case kStatusIncompatible:
    case kStatusInvalid:
        return QCoreApplication::translate("AvpnApkUpdate", "Android отклонил обновление. Скачайте приложение с сайта заново.");
    default:
        return QCoreApplication::translate("AvpnApkUpdate", "Не удалось обновить. Попробуйте скачать вручную.");
    }
}

} // namespace avpn::ApkUpdate
