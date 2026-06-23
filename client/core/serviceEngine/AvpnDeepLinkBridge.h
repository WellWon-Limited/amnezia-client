// AVPN (Task 13) — мост обратного диплинка ПЕРЕНОСА («как SIM») → QML/движок.
//
// Сценарий «перенести подписку на новое устройство»: исходное устройство выпускает одноразовый
// токен переноса (POST /v1/transfer) и показывает QR/ссылку tribe://transfer?t=<token>. Новое
// устройство открывает эту ссылку — натив-слой (iOS: QtAppDelegate.mm openURL/continueUserActivity;
// Android: intent-filter) зовёт C-функцию AvpnDeepLink_handleUrl() из любого потока. Она маршалится
// в Qt-поток, ИЗВЛЕКАЕТ токен переноса и эмитит transferRequested(token). Дальше — НЕ мост, а движок:
// coreController связывает transferRequested → AvpnEngineQml::redeemTransfer(token), который ходит в
// POST /v1/transfer/redeem, РОТИРУЕТ subscription_token (Enrollment::saveToken) и перечитывает подписку.
//
// Почему redeem делает движок, а не мост: у моста нет base URL / Identity / NAM. Мост — только парсер
// ссылки и потокобезопасный мост из натива в Qt-поток.
//
// Overlay: апстрим не трогаем. На desktop без диплинка — просто пустой мост (no-op).
#pragma once

#include <QObject>
#include <QString>

namespace avpn {

class AvpnDeepLinkBridge : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString pendingTransferToken READ pendingTransferToken NOTIFY changed)

public:
    static AvpnDeepLinkBridge *instance();

    QString pendingTransferToken() const { return m_transferToken; }

    // Натив-слой (iOS/Android), потокобезопасно (маршалит в Qt-поток).
    void handleUrl(const QString &url);

signals:
    void changed();
    // AVPN (Task 13): из ссылки извлечён токен переноса. coreController связывает это с
    // AvpnEngineQml::redeemTransfer(token) (POST /v1/transfer/redeem + РОТАЦИЯ токена).
    void transferRequested(const QString &transferToken);
    // AVPN (рефералы): из /r/<code>|/a/<code> извлечён код приглашения (уже сохранён в pending-стор
    // через Enrollment::savePendingReferral — уйдёт в referral_code первого /v1/trial). Сигнал — для UI.
    void referralCaptured(const QString &code);

private:
    explicit AvpnDeepLinkBridge(QObject *parent = nullptr);
    void applyUrl(const QString &url);

    QString m_transferToken;
};

} // namespace avpn

// C-вход для ObjC++ (QtAppDelegate.mm) / Android JNI — вызывается из любого потока.
extern "C" void AvpnDeepLink_handleUrl(const char *url);
