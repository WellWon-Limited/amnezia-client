#ifndef SERIALIZATION_H
#define SERIALIZATION_H
// Test stand-in for client/core/utils/serialization/serialization.h (xray_protocol_end_check): fixed test credentials.
#include <QJsonObject>
#include <QString>
namespace amnezia::serialization::inbounds {
struct InboundCredentials {
    QString username;
    QString password;
    int port;
};
inline InboundCredentials EnsureInboundAuth(QJsonObject &) { return { QStringLiteral("test"), QStringLiteral("test"), 10808 }; }
}
#endif
