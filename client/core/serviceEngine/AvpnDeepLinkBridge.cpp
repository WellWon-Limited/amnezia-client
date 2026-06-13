// AVPN (Task 13) — реализация моста диплинка ПЕРЕНОСА. См. AvpnDeepLinkBridge.h.
#include "AvpnDeepLinkBridge.h"

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
