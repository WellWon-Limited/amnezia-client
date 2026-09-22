#pragma once
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUuid>

namespace avpn {
inline QString reportContentId(const QByteArray &body)
{
    return QString::fromLatin1(QCryptographicHash::hash(body, QCryptographicHash::Sha256).toHex());
}
inline QString reportAcknowledgement(int status, bool transportOk, const QByteArray &body)
{
    if (!transportOk || status < 200 || status >= 300) return {};
    const QString id = QJsonDocument::fromJson(body).object().value(QStringLiteral("id")).toString();
    return QUuid(id).isNull() ? QString() : id;
}
} // namespace avpn
