/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef DAEMONLOCALSERVER_H
#define DAEMONLOCALSERVER_H

#include <QLocalServer>
#include <QPointer>

#include "ipcsecurity.h"

class QLocalSocket;

class DaemonLocalServer final : public QObject {
  Q_DISABLE_COPY_MOVE(DaemonLocalServer)

 public:
  explicit DaemonLocalServer(QObject* parent);
  ~DaemonLocalServer();

  bool initialize();

 private:
  QString daemonPath() const;

 private:
  QLocalServer m_server;
  QPointer<QLocalSocket> m_authenticatedSocket;
  amnezia::ipcsecurity::PeerPolicy m_peerPolicy;
  QString m_socketPath;
};

#endif  // DAEMONLOCALSERVER_H
