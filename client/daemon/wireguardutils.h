/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef WIREGUARDUTILS_H
#define WIREGUARDUTILS_H

#define _WINSOCKAPI_

#include <QCoreApplication>
#include <QHostAddress>
#include <QObject>
#include <QStringList>

#include "interfaceconfig.h"

constexpr const char* WG_INTERFACE = "tribe0"; // AVPN: офиц. Amnezia держит amn0 — общее имя = конфликт интерфейса/нейм-файла

constexpr uint16_t WG_KEEPALIVE_PERIOD = 60;

class WireguardUtils : public QObject {
  Q_OBJECT

 public:
  class PeerStatus {
   public:
    PeerStatus(const QString& pubkey = QString()) { m_pubkey = pubkey; }
    QString m_pubkey;
    qint64 m_handshake = 0;
    qint64 m_rxBytes = 0;
    qint64 m_txBytes = 0;
  };

  explicit WireguardUtils(QObject* parent) : QObject(parent){};
  virtual ~WireguardUtils() = default;

  virtual bool interfaceExists() = 0;
  virtual QString interfaceName() { return WG_INTERFACE; }
  virtual bool addInterface(const InterfaceConfig& config) = 0;
  virtual bool deleteInterface() = 0;

  virtual bool updatePeer(const InterfaceConfig& config) = 0;
  virtual bool deletePeer(const InterfaceConfig& config) = 0;
  virtual QList<PeerStatus> getPeerStatus() = 0;

  virtual bool updateRoutePrefix(const IPAddress& prefix) = 0;
  virtual bool deleteRoutePrefix(const IPAddress& prefix) = 0;
  
  virtual bool addExclusionRoute(const IPAddress& prefix) = 0;
  virtual bool deleteExclusionRoute(const IPAddress& prefix) = 0;

  // AVPN (BUG-4 auto-heal, 2026-07-22): пересоздать UDP-сокет живого интерфейса с НОВЫМ
  // эфемерным локальным портом (UAPI listen_port=0 → BindUpdate) — новый 5-tuple flow лечит
  // сессионный блок ТСПУ. База — no-op false: платформы без реализации просто не умеют heal
  // (GUI это переживает — HealthLoop уйдёт в failover). Переопределяет WireguardUtilsMacos.
  virtual bool rebindEndpointSocket() { return false; }

  // AVPN win-fix (2026-07-07): пакетное окно вокруг массового добавления exclusion-маршрутов
  // (RU-direct = ~8.6k префиксов). Базовая реализация — no-op: на не-Windows платформах поведение
  // НЕ меняется (маршруты добавляются как раньше). Только WireguardUtilsWindows переопределяет,
  // чтобы схлопнуть O(N²) пересчёт таблицы в один проход. НЕ трогать другие платформы.
  virtual void beginBulkExclusion() {}
  virtual void endBulkExclusion() {}

  // AVPN win-fix (BUG-12, 2026-07-30): порционное разрешение исключений в файрволе.
  // На Windows kill-switch блокирует всё мимо туннеля, поэтому каждому исключению нужен ещё и
  // WFP-фильтр; их создание для RU-direct (~8.6k) занимало ~16с ВНУТРИ activate и держало event
  // loop демона — клиент не дожидался `connected` и слал deactivate (см. CONNECT-INVARIANTS §15).
  // База — no-op true: на прочих платформах путь не меняется.
  virtual bool allowExcludedTrafficChunk(const QStringList& addresses,
                                         const QString& pubkey) {
    Q_UNUSED(addresses);
    Q_UNUSED(pubkey);
    return true;
  }

  virtual bool excludeLocalNetworks(const QList<IPAddress>& addresses) = 0;
};

#endif  // WIREGUARDUTILS_H
