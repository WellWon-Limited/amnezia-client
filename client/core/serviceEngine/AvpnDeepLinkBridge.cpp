// AVPN (Task 13) — реализация моста диплинка ПЕРЕНОСА. См. AvpnDeepLinkBridge.h.
#include "AvpnDeepLinkBridge.h"
#include "Enrollment.h" // AVPN (рефералы): savePendingReferral — pending-код до первого /v1/trial

#include <QMetaObject>
#include <QUrl>
#include <QUrlQuery>

#if !defined(Q_OS_IOS) && !defined(Q_OS_ANDROID)
    #include <QCoreApplication> // desktop: диплинк аргументом командной строки (Windows/Linux URL-протокол)
#endif
#if defined(Q_OS_MACOS)
    #include <QEvent>
    #include <QFileOpenEvent> // macOS: tribe:// приходит Apple Event'ом → QFileOpenEvent на qApp
#endif
#if defined(Q_OS_WIN)
    #include <QDir>
    #include <QSettings> // Windows: самозапись URL-протокола tribe:// в HKCU\Software\Classes
#endif

namespace avpn {

// один вход для всех desktop-источников: подходит ли строка на наш диплинк
static bool looksLikeTribeUrl(const QString &s)
{
    return s.startsWith(QLatin1String("tribe://")) || s.contains(QLatin1String("tribevpn.com/transfer"));
}

#if defined(Q_OS_MACOS)
// macOS: LaunchServices доставляет URL зарегистрированной схемы (CFBundleURLTypes в
// macos/app/Info.plist.in) Apple Event'ом — и при холодном старте, и уже работающему
// приложению. Qt превращает его в QFileOpenEvent, адресованный qApp — ловим фильтром.
namespace {
    class AvpnUrlOpenFilter : public QObject {
    public:
        using QObject::QObject;

    protected:
        bool eventFilter(QObject *watched, QEvent *event) override
        {
            if (event->type() == QEvent::FileOpen) {
                const QString url = static_cast<QFileOpenEvent *>(event)->url().toString();
                if (looksLikeTribeUrl(url)) {
                    AvpnDeepLinkBridge::instance()->handleUrl(url);
                    return true; // наш диплинк — апстрим-импорту не отдаём
                }
            }
            return QObject::eventFilter(watched, event);
        }
    };
} // namespace
#endif

AvpnDeepLinkBridge::AvpnDeepLinkBridge(QObject *parent) : QObject(parent)
{
#if defined(Q_OS_WIN)
    // Windows: самозапись URL-протокола tribe:// в HKCU (без админ-прав; не зависит от типа
    // инсталлятора IFW/MSI; самолечится при смене пути установки). Клик по ссылке запускает
    // второй инстанс с URL в argv: холодный старт ловится сканом ниже, тёплый — форвардом через
    // instance-сокет (main.cpp isAnotherInstanceRunning → startLocalServer).
    if (QCoreApplication::instance()) {
        const QString cmd = QStringLiteral("\"%1\" \"%2\"")
                                    .arg(QDir::toNativeSeparators(QCoreApplication::applicationFilePath()),
                                         QStringLiteral("%1"));
        QSettings cls(QStringLiteral("HKEY_CURRENT_USER\\Software\\Classes\\tribe"), QSettings::NativeFormat);
        cls.setValue(QStringLiteral("Default"), QStringLiteral("URL:Tribe VPN"));
        cls.setValue(QStringLiteral("URL Protocol"), QString());
        cls.setValue(QStringLiteral("shell/open/command/Default"), cmd);
    }
#endif
#if !defined(Q_OS_IOS) && !defined(Q_OS_ANDROID)
    if (QCoreApplication::instance()) {
        // Desktop cold start: Windows/Linux передают URL зарегистрированного протокола аргументом.
        // handleUrl queued → применится ПОСЛЕ того, как coreController свяжет transferRequested
        // с движком (мы создаёмся в том же стеке, до старта event loop).
        const QStringList args = QCoreApplication::arguments();
        for (const QString &a : args) {
            if (looksLikeTribeUrl(a)) {
                handleUrl(a);
                break;
            }
        }
    #if defined(Q_OS_MACOS)
        QCoreApplication::instance()->installEventFilter(new AvpnUrlOpenFilter(this));
    #endif
    }
#endif
}

AvpnDeepLinkBridge *AvpnDeepLinkBridge::instance()
{
    // Лениво создаём один экземпляр. Живёт в Qt-главном потоке (создаётся из coreController).
    static AvpnDeepLinkBridge *s_instance = new AvpnDeepLinkBridge();
    return s_instance;
}

void AvpnDeepLinkBridge::handleUrl(const QString &url)
{
    QMetaObject::invokeMethod(
        this, [this, url]() { applyUrl(url); }, Qt::QueuedConnection);
}

void AvpnDeepLinkBridge::applyUrl(const QString &url)
{
    const QUrl u(url);

    // AVPN (рефералы): tribe://r/<code>|tribe://a/<code> ИЛИ https://*.tribevpn.com/r/<code>|/a/<code>.
    // Извлекаем код приглашения, сохраняем до ПЕРВОГО /v1/trial (first-touch). Бэк сам различит
    // peer(/r/)/affiliate(/a/) по самому коду. Не редимим тут — только запоминаем.
    {
        QString refCode;
        if (u.scheme() == QLatin1String("tribe")
            && (u.host() == QLatin1String("r") || u.host() == QLatin1String("a"))) {
            refCode = u.path();
            if (refCode.startsWith(QLatin1Char('/'))) refCode = refCode.mid(1);
        } else if (u.scheme() == QLatin1String("https")
                   && u.host().endsWith(QLatin1String("tribevpn.com"))) {
            const QString p = u.path();
            if (p.startsWith(QLatin1String("/r/")) || p.startsWith(QLatin1String("/a/")))
                refCode = p.mid(3);
        }
        // только код: отрезаем возможный хвостовой сегмент/слэш
        const int slash = refCode.indexOf(QLatin1Char('/'));
        if (slash >= 0)
            refCode = refCode.left(slash);
        refCode = refCode.trimmed();
        if (!refCode.isEmpty()) {
            Enrollment::savePendingReferral(refCode);
            emit referralCaptured(refCode);
            return; // реферал-ссылка обработана
        }
    }

    // Принимаем: tribe://transfer?t=…  ИЛИ  https://*.tribevpn.com/transfer?t=… (Universal Link).
    const bool isScheme = (u.scheme() == QLatin1String("tribe")
                           && u.host() == QLatin1String("transfer"));
    const bool isUniversal = (u.scheme() == QLatin1String("https")
                              && u.host().endsWith(QLatin1String("tribevpn.com"))
                              && u.path() == QLatin1String("/transfer"));
    if (!isScheme && !isUniversal)
        return;

    const QUrlQuery q(u);
    // Контракт: tribe://transfer?t=<token>. Допускаем псевдоним ?token= на всякий случай.
    QString token = q.queryItemValue(QStringLiteral("t"));
    if (token.isEmpty())
        token = q.queryItemValue(QStringLiteral("token"));
    if (token.isEmpty())
        return;

    // Сам redeem делает движок (у него есть base URL / Identity / NAM): coreController связал
    // transferRequested → AvpnEngineQml::redeemTransfer(token) (POST /v1/transfer/redeem + РОТАЦИЯ).
    m_transferToken = token;
    emit changed();
    emit transferRequested(token);
}

} // namespace avpn

extern "C" void AvpnDeepLink_handleUrl(const char *url)
{
    if (url)
        avpn::AvpnDeepLinkBridge::instance()->handleUrl(QString::fromUtf8(url));
}
