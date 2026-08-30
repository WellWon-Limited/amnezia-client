/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "daemonlocalserver.h"

#include <QDir>
#include <QFileInfo>
#include <QLocalSocket>

#include "daemonlocalserverconnection.h"
#include "leakdetector.h"
#include "logger.h"
#include "ipc.h"
#include "ipcsecurity.h"

#if defined(MZ_MACOS) || defined(MZ_LINUX)
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <unistd.h>

#endif

namespace {
Logger logger("DaemonLocalServer");
}  // namespace

DaemonLocalServer::DaemonLocalServer(QObject* parent) : QObject(parent) {
  MZ_COUNT_CTOR(DaemonLocalServer);
}

DaemonLocalServer::~DaemonLocalServer() { MZ_COUNT_DTOR(DaemonLocalServer); }

bool DaemonLocalServer::initialize() {
#ifdef Q_OS_MACOS
  QString securityError;
  if (!amnezia::ipcsecurity::consolePeerPolicy(&m_peerPolicy, &securityError)
      || !amnezia::ipcsecurity::prepareRuntimeDirectory(
          m_peerPolicy.expected.uid, m_peerPolicy.expected.gid, &securityError)) {
    logger.error() << "Secure daemon IPC initialization failed:" << securityError;
    return false;
  }
  m_socketPath = amnezia::ipcsecurity::wireguardSocketPath(
      m_peerPolicy.expected.uid);
  if (!amnezia::ipcsecurity::removeVerifiedStaleSocket(
          m_socketPath, m_peerPolicy.expected.uid, &securityError)) {
    logger.error() << "Secure daemon endpoint rejected:" << securityError;
    return false;
  }
  m_server.setSocketOptions(QLocalServer::UserAccessOption);
#else
  m_server.setSocketOptions(QLocalServer::WorldAccessOption);
#endif

  QString path = daemonPath();

  if (!m_server.listen(path)) {
    logger.error() << "Failed to listen the daemon path";
    return false;
  }
#ifdef Q_OS_MACOS
  if (!amnezia::ipcsecurity::secureSocketFile(
          path, m_peerPolicy.expected.uid, m_peerPolicy.expected.gid,
          &securityError)) {
    logger.error() << "Secure daemon socket permissions failed:" << securityError;
    m_server.close();
    QLocalServer::removeServer(path);
    return false;
  }
#endif

  connect(&m_server, &QLocalServer::newConnection, [&] {
    logger.debug() << "New connection received";

    if (!m_server.hasPendingConnections()) {
      return;
    }

    QLocalSocket* socket = m_server.nextPendingConnection();
    Q_ASSERT(socket);

#ifdef Q_OS_MACOS
    QString securityError;
    QByteArray sessionCapability;
    const bool secondClient = m_authenticatedSocket
        && m_authenticatedSocket->state() != QLocalSocket::UnconnectedState;
    if (secondClient
        || !amnezia::ipcsecurity::authorizeSocket(
            socket, m_peerPolicy, nullptr, &securityError)
        || !amnezia::ipcsecurity::performServerHandshake(
            socket, {}, &sessionCapability, &securityError)) {
      logger.warning() << "Rejected daemon IPC peer:"
                       << (secondClient ? QStringLiteral("second_client")
                                        : securityError);
      socket->abort();
      socket->deleteLater();
      return;
    }
    socket->setReadBufferSize(amnezia::ipcsecurity::kMaxDaemonCommandBytes);
    m_authenticatedSocket = socket;
    connect(socket, &QLocalSocket::disconnected, this, [this, socket]() {
      if (m_authenticatedSocket == socket) {
        m_authenticatedSocket.clear();
      }
    });
#endif

    DaemonLocalServerConnection* connection =
        new DaemonLocalServerConnection(&m_server, socket);
    connect(socket, &QLocalSocket::disconnected, connection,
            &DaemonLocalServerConnection::deleteLater);
  });

  return true;
}

QString DaemonLocalServer::daemonPath() const {
#if defined(MZ_WINDOWS)
  return "\\\\.\\pipe\\avpn";  // AVPN: свой pipe (изоляция от Amnezia)
#endif
#if defined(MZ_MACOS)
  return m_socketPath;
#elif defined(MZ_LINUX)
  // AVPN: каталог avpn вместо amneziavpn (изоляция от официальной Amnezia)
  QDir dir("/var/run");
  if (!dir.exists()) {
    return QStringLiteral("/tmp/avpn.socket");
  }

  if (dir.exists("avpn")) {
    logger.debug() << "/var/run/avpn seems to be usable";
    return QStringLiteral("/var/run/avpn/daemon.socket");
  }

  if (!dir.mkdir("avpn")) {
    logger.warning() << "Failed to create /var/run/avpn";
    return QStringLiteral("/tmp/avpn.socket");
  }

  if (chmod("/var/run/avpn", S_IRWXU | S_IRWXG | S_IRWXO) < 0) {
    logger.warning()
        << "Failed to set the right permissions to /var/run/avpn";
    return QStringLiteral("/tmp/avpn.socket");
  }

  return QStringLiteral("/var/run/avpn/daemon.socket");
#endif
}
