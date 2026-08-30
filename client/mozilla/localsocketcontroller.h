/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef LOCALSOCKETCONTROLLER_H
#define LOCALSOCKETCONTROLLER_H

#include <QHostAddress>
#include <QJsonObject>  // AVPN (IPC-stall fix): очередь отложенного activate
#include <QLocalSocket>
#include <QTimer>
#include <functional>

#include "controllerimpl.h"


class QJsonObject;

class LocalSocketController final : public ControllerImpl {
  Q_OBJECT
  Q_DISABLE_COPY_MOVE(LocalSocketController)

 public:
  LocalSocketController();
  ~LocalSocketController();

  void initialize(const Device* device, const Keys* keys) override;

  void activate(const QJsonObject& rawConfig) override;

  bool activateExactSession(const QJsonObject& rawConfig, const QString& sessionId);
  bool adoptExactSession(const QString& sessionId);
  bool isReady() const { return m_daemonState == eReady; }

  void deactivate() override;
  bool deactivateExactSession(const QString& sessionId);

  void checkStatus() override;

  void getBackendLogs(std::function<void(const QString&)>&& callback) override;

  void cleanupBackendLogs() override;

  bool multihopSupported() override { return true; }

 signals:
  void runtimeStatusChanged(const QJsonObject& status);

 private:
  void initializeInternal();
  void disconnectInternal();

  void daemonConnected();
  void errorOccurred(QLocalSocket::LocalSocketError socketError);
  void readData();
  void parseCommand(const QByteArray& command);
  void activateInternal(const QJsonObject& rawConfig, const QString& exactSessionId);
  void checkExactStatus();

  void write(const QJsonObject& json);

 private:
  enum {
    eUnknown,
    eInitializing,
    eReady,
    eDisconnected,
  } m_daemonState = eUnknown;

  QLocalSocket* m_socket = nullptr;

  // AVPN (IPC-stall fix, 2026-07-10): activate, пришедший в окне подключения к пайпу демона
  // (ретраи initializeInternal — например, сервис как раз перезапускается). Раньше запись уходила
  // в неподключённый сокет и МОЛЧА терялась → вечный «Connecting». Флашится по готовности демона
  // (parseCommand: первый status → eReady), чистится в deactivate()/disconnectInternal().
  QJsonObject m_pendingActivate;

  QByteArray m_buffer;

  QString m_deviceIpv4;
  std::function<void(const QString&)> m_logCallback = nullptr;

  QTimer m_initializingTimer;
  QTimer m_runtimeStatusTimer;
  uint32_t m_initializingRetry = 0;
  QString m_exactSessionId;
};

#endif  // LOCALSOCKETCONTROLLER_H
