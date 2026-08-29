/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "daemonlocalserverconnection.h"

#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QLocalSocket>
#include <QSet>
#include <QStringList>
#include <QUuid>

#include "daemon.h"
#include "leakdetector.h"
#include "logger.h"
#include "version.h" // AVPN: compile-time app/build facts for versioned engine IPC.
#include "ipcsecurity.h"

namespace {
Logger logger("DaemonLocalServerConnection");
}

DaemonLocalServerConnection::DaemonLocalServerConnection(QObject* parent,
                                                         QLocalSocket* socket)
    : QObject(parent) {
  MZ_COUNT_CTOR(DaemonLocalServerConnection);

  logger.debug() << "Connection created";

  Q_ASSERT(socket);
  m_socket = socket;

  connect(m_socket, &QLocalSocket::readyRead, this,
          &DaemonLocalServerConnection::readData);

  Daemon* daemon = Daemon::instance();
  connect(daemon, &Daemon::connected, this,
          &DaemonLocalServerConnection::connected);
  connect(daemon, &Daemon::disconnected, this,
          &DaemonLocalServerConnection::disconnected);
  connect(daemon, &Daemon::backendFailure, this,
          &DaemonLocalServerConnection::backendFailure);
}

DaemonLocalServerConnection::~DaemonLocalServerConnection() {
  MZ_COUNT_DTOR(DaemonLocalServerConnection);

  logger.debug() << "Connection released";
}

void DaemonLocalServerConnection::readData() {
  logger.debug() << "Read Data";

  Q_ASSERT(m_socket);

  while (true) {
    int pos = m_buffer.indexOf("\n");
    if (pos == -1) {
      QByteArray input = m_socket->readAll();
      if (input.isEmpty()) {
        break;
      }
      if (input.size() > amnezia::ipcsecurity::kMaxDaemonCommandBytes
          || m_buffer.size() > amnezia::ipcsecurity::kMaxDaemonCommandBytes
                                 - input.size()) {
        logger.warning() << "Oversized daemon IPC frame rejected";
        m_buffer.clear();
        m_socket->abort();
        return;
      }
      m_buffer.append(input);
      continue;
    }

    if (pos > amnezia::ipcsecurity::kMaxDaemonCommandBytes) {
      logger.warning() << "Oversized daemon IPC command rejected";
      m_buffer.clear();
      m_socket->abort();
      return;
    }

    QByteArray line = m_buffer.left(pos);
    m_buffer.remove(0, pos + 1);

    QByteArray command(line);
    command = command.trimmed();

    if (command.isEmpty()) {
      continue;
    }

    parseCommand(command);
  }
}

void DaemonLocalServerConnection::parseCommand(const QByteArray& data) {
  QJsonDocument json = QJsonDocument::fromJson(data);
  if (!json.isObject()) {
    logger.error() << "Invalid input";
    return;
  }

  QJsonObject obj = json.object();
  QJsonValue typeValue = obj.value("type");
  if (!typeValue.isString()) {
    logger.warning() << "No type command. Ignoring request.";
    return;
  }
  QString type = typeValue.toString();

  logger.debug() << "Command received:" << type;

  // It is expected that sometimes the client will request backend logs
  // before the first authentication. In these cases we just return empty
  // logs.
  if (type == "logs") {
    QJsonObject obj;
    obj.insert("type", "logs");
    obj.insert("logs", "");
    write(obj);
    return;
  }

  if (type == "activate") {
    InterfaceConfig config;
    if (!Daemon::parseConfig(obj, config)) {
      logger.error() << "Invalid configuration";
      emit disconnected();
      return;
    }

    if (!Daemon::instance()->activate(config)) {
      logger.error() << "Failed to activate the interface";
      emit disconnected();
    }
    return;
  }

  if (type == "activate_session_v1") {
    const QString sessionId = obj.value(QStringLiteral("session_id")).toString();
    const QUuid uuid(sessionId);
    if (!obj.value(QStringLiteral("schema")).isDouble()
        || obj.value(QStringLiteral("schema")).toDouble() != 1.0
        || uuid.isNull()
        || uuid.toString(QUuid::WithoutBraces).toLower() != sessionId) {
      logger.error() << "Invalid exact AWG session identity";
      return;
    }
    InterfaceConfig config;
    if (!Daemon::parseConfig(obj, config)
        || !Daemon::instance()->activateExactSession(config, sessionId)) {
      logger.error() << "Failed to activate exact AWG session";
    }
    const QJsonObject status = Daemon::instance()->runtimeStatusV1(sessionId);
    if (!status.isEmpty()) write(status);
    return;
  }

  if (type == "deactivate") {
    Daemon::instance()->deactivate(true);
    return;
  }

  if (type == "deactivate_session_v1") {
    static const QSet<QString> expected{
        QStringLiteral("type"), QStringLiteral("schema"),
        QStringLiteral("session_id")};
    const QStringList keys = obj.keys();
    const QString sessionId = obj.value(QStringLiteral("session_id")).toString();
    const QUuid uuid(sessionId);
    if (QSet<QString>(keys.cbegin(), keys.cend()) != expected
        || !obj.value(QStringLiteral("schema")).isDouble()
        || obj.value(QStringLiteral("schema")).toDouble() != 1.0
        || uuid.isNull()
        || uuid.toString(QUuid::WithoutBraces).toLower() != sessionId
        || !Daemon::instance()->deactivateExactSession(sessionId)) {
      logger.error() << "Exact AWG stop rejected or failed";
    }
    const QJsonObject status = Daemon::instance()->runtimeStatusV1(sessionId);
    if (!status.isEmpty()) write(status);
    return;
  }

  if (type == "runtime_status_v1") {
    static const QSet<QString> expected{
        QStringLiteral("type"), QStringLiteral("schema"),
        QStringLiteral("session_id")};
    const QStringList keys = obj.keys();
    const QString sessionId = obj.value(QStringLiteral("session_id")).toString();
    if (QSet<QString>(keys.cbegin(), keys.cend()) != expected
        || !obj.value(QStringLiteral("schema")).isDouble()
        || obj.value(QStringLiteral("schema")).toDouble() != 1.0) return;
    const QJsonObject status = Daemon::instance()->runtimeStatusV1(sessionId);
    if (!status.isEmpty()) write(status);
    return;
  }

  if (type == "status") {
    QJsonObject obj = Daemon::instance()->getStatus();
    obj.insert("type", "status");
    write(obj);
    return;
  }

#if defined(Q_OS_MAC) && defined(TRIBE_ENGINE_MANIFEST_ENABLED)
  // AVPN: additive, versioned daemon IPC.  These are package-lock facts, not
  // runtime probes: amnezia-xray-bindings v1 has no exported version symbol.
  if (type == "engine_manifest_v1") {
    QJsonObject app;
    app.insert("version", QStringLiteral(APP_VERSION));
    app.insert("build", APP_BUILD);

    QJsonObject awg;
    awg.insert("protocol", "awg");
    awg.insert("adapter", "awg-go");
    awg.insert("adapterVersion", QStringLiteral(TRIBE_AWG_ENGINE_VERSION));
    awg.insert("declaredCoreVersion", QStringLiteral(TRIBE_AWG_CORE_VERSION));
    awg.insert("sourceCommit", QStringLiteral(TRIBE_AWG_ENGINE_COMMIT));
    awg.insert("abi", QStringLiteral(TRIBE_AWG_UAPI_ABI));
    awg.insert("runtimeCoreVersion", QJsonValue::Null);
    awg.insert("versionEvidence", "compile_time_lock_only");
    awg.insert("runtimeVersionProbed", false);
    awg.insert("capabilities", QJsonArray{
        "awg.random_trailers", "awg.disable_cookies", "uapi.readback",
        "tribe.guarded_settings_owner"});

    QJsonObject xray;
    xray.insert("protocol", "xray");
    xray.insert("adapter", "amnezia-xray-bindings");
    xray.insert("adapterVersion", QStringLiteral(TRIBE_XRAY_BINDINGS_VERSION));
    xray.insert("sourceCommit", QStringLiteral(TRIBE_XRAY_BINDINGS_COMMIT));
    xray.insert("declaredCoreVersion", QStringLiteral(TRIBE_XRAY_CORE_VERSION));
    xray.insert("abi", QStringLiteral(TRIBE_XRAY_BINDINGS_ABI));
    xray.insert("runtimeCoreVersion", QJsonValue::Null);
    xray.insert("versionEvidence", "compile_time_lock_only");
    xray.insert("runtimeVersionProbed", false);
    xray.insert("capabilities", QJsonArray{
        "xray.vless.reality.vision.tcp", "xray.embedded", "xray.socket_callback",
        "tribe.guarded_settings_owner"});

    QJsonObject reply;
    reply.insert("type", "engine_manifest_v1");
    reply.insert("schema", 1);
    reply.insert("app", app);
    reply.insert("engines", QJsonArray{awg, xray});
    write(reply);
    return;
  }
#endif

  if (type == "logs") {
    QJsonObject obj;
    obj.insert("type", "logs");
    obj.insert("logs", Daemon::instance()->logs().replace("\n", "|"));
    write(obj);
    return;
  }

  if (type == "cleanlogs") {
    Daemon::instance()->cleanLogs();
    return;
  }

  // AVPN (BUG-4 auto-heal): ребайнд UDP-сокета живого интерфейса (новый локальный порт =
  // новый 5-tuple flow, лечит сессионный блок ТСПУ). Реализация платформенная
  // (WireguardUtils::rebindEndpointSocket, база no-op false). Ответ type=rebound — для лога
  // GUI; старые GUI его молча игнорируют (свой warning на неизвестный тип).
  if (type == "rebind") {
    const bool ok = Daemon::instance() && Daemon::instance()->rebindEndpointSocket();
    QJsonObject obj;
    obj.insert("type", "rebound");
    obj.insert("ok", ok);
    write(obj);
    return;
  }

  logger.warning() << "Invalid command:" << type;
}

void DaemonLocalServerConnection::connected(const QString& pubkey) {
  QJsonObject obj;
  obj.insert("type", "connected");
  obj.insert("pubkey", QJsonValue(pubkey));
  write(obj);
}

void DaemonLocalServerConnection::disconnected() {
  QJsonObject obj;
  obj.insert("type", "disconnected");
  write(obj);
}

void DaemonLocalServerConnection::backendFailure(DaemonError err) {
  QJsonObject obj;
  obj.insert("type", "backendFailure");
  obj.insert("errorCode", static_cast<int>(err));
  write(obj);
}

void DaemonLocalServerConnection::write(const QJsonObject& obj) {
  m_socket->write(QJsonDocument(obj).toJson(QJsonDocument::Compact));
  m_socket->write("\n");
}
