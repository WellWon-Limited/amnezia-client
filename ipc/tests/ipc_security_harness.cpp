#include "ipcsecurity.h"

#include <QCoreApplication>
#include <QJsonObject>

#include <cstdlib>
#include <iostream>

using namespace amnezia::ipcsecurity;

namespace {

void require(bool condition, const char *message)
{
    if (!condition) {
        std::cerr << "IPC security harness failed: " << message << '\n';
        std::exit(1);
    }
}

QJsonObject response(const QByteArray &challenge, const QByteArray &clientNonce,
                     const QByteArray &capability)
{
    QJsonObject result{{QStringLiteral("type"),
                        QStringLiteral("tribe_ipc_response_v1")},
                       {QStringLiteral("schema"), 1},
                       {QStringLiteral("challenge"),
                        QString::fromLatin1(challenge)},
                       {QStringLiteral("client_nonce"),
                        QString::fromLatin1(clientNonce)}};
    if (!capability.isEmpty()) {
        result.insert(QStringLiteral("capability"),
                      QString::fromLatin1(capability));
    }
    return result;
}

} // namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    PeerPolicy policy;
    policy.expected = {501, 20, -1};
    policy.identifier = QStringLiteral("hk.wellwon.vpn");
    policy.teamIdentifier = QStringLiteral("Q7DVH5MCWF");
    PeerIdentity actual{501, 20, 4242};
    SignatureEvidence signature{policy.identifier, policy.teamIdentifier, true};
    require(validatePeerPolicy(actual, signature, policy), "valid peer rejected");

    PeerIdentity wrong = actual;
    wrong.uid = 502;
    require(!validatePeerPolicy(wrong, signature, policy), "wrong uid accepted");
    wrong = actual;
    wrong.gid = 80;
    require(!validatePeerPolicy(wrong, signature, policy), "wrong gid accepted");
    wrong = actual;
    wrong.pid = -1;
    require(!validatePeerPolicy(wrong, signature, policy), "wrong pid accepted");
    SignatureEvidence wrongSignature = signature;
    wrongSignature.identifier = QStringLiteral("org.attacker.app");
    require(!validatePeerPolicy(actual, wrongSignature, policy),
            "wrong identifier accepted");
    wrongSignature = signature;
    wrongSignature.teamIdentifier = QStringLiteral("ATTACKER01");
    require(!validatePeerPolicy(actual, wrongSignature, policy),
            "wrong team accepted");
    wrongSignature = signature;
    wrongSignature.validityChecked = false;
    require(!validatePeerPolicy(actual, wrongSignature, policy),
            "unchecked signature accepted");

    PathMetadata directory{true, true, false, false, 0, 0711};
    require(validateDirectoryMetadata(directory, 0, 0711),
            "secure directory rejected");
    directory.symlink = true;
    require(!validateDirectoryMetadata(directory, 0, 0711),
            "directory symlink accepted");
    directory.symlink = false;
    directory.mode = 0777;
    require(!validateDirectoryMetadata(directory, 0, 0711),
            "world-writable directory accepted");

    PathMetadata socket{true, false, true, false, 501, 0600};
    require(validateSocketMetadata(socket, 501, 0600), "secure socket rejected");
    socket.mode = 0666;
    require(!validateSocketMetadata(socket, 501, 0600),
            "world socket accepted");
    socket.mode = 0600;
    socket.symlink = true;
    require(!validateSocketMetadata(socket, 501, 0600),
            "socket symlink accepted");

    require(!validHandshakeFrameSize(0), "empty frame accepted");
    require(validHandshakeFrameSize(kMaxHandshakeFrameBytes),
            "bounded frame rejected");
    require(!validHandshakeFrameSize(kMaxHandshakeFrameBytes + 1),
            "oversized frame accepted");

    const QByteArray challenge = randomCapability();
    const QByteArray clientNonce = randomCapability();
    const QByteArray capability = randomCapability();
    const QJsonObject validResponse = response(challenge, clientNonce, capability);
    require(validateChallengeResponse(validResponse, challenge, capability),
            "valid challenge rejected");
    require(!validateChallengeResponse(validResponse, challenge, capability),
            "replayed challenge accepted");
    require(!validateChallengeResponse(response(challenge, randomCapability(),
                                                randomCapability()),
                                       challenge, capability),
            "wrong capability accepted");
    require(!validateChallengeResponse(response(randomCapability(),
                                                randomCapability(), capability),
                                       challenge, capability),
            "wrong challenge accepted");
    QJsonObject fractionalSchema = response(challenge, randomCapability(), capability);
    fractionalSchema.insert(QStringLiteral("schema"), 1.5);
    require(!validateChallengeResponse(fractionalSchema, challenge, capability),
            "fractional challenge schema accepted");
    QJsonObject extendedSchema = response(challenge, randomCapability(), capability);
    extendedSchema.insert(QStringLiteral("unsigned_extension"), true);
    require(!validateChallengeResponse(extendedSchema, challenge, capability),
            "unknown challenge field accepted");
    QJsonObject missingCapability = response(challenge, randomCapability(), {});
    require(!validateChallengeResponse(missingCapability, challenge, capability),
            "capability-bound handshake accepted an absent capability field");
    require(!isCanonicalCapability(QByteArray("+invalid")),
            "noncanonical capability accepted");

    std::cout << "IPC security policy harness passed\n";
    return 0;
}
