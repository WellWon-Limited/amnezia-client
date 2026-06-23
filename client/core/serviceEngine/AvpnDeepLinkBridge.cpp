// AVPN (Task 13) — реализация моста диплинка ПЕРЕНОСА. См. AvpnDeepLinkBridge.h.
#include "AvpnDeepLinkBridge.h"
#include "Enrollment.h" // AVPN (рефералы): savePendingReferral — pending-код до первого /v1/trial

#include <QMetaObject>
#include <QUrl>
#include <QUrlQuery>

namespace avpn {

AvpnDeepLinkBridge::AvpnDeepLinkBridge(QObject *parent) : QObject(parent) {}

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
