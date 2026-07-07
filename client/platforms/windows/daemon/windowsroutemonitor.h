/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef WINDOWSROUTEMONITOR_H
#define WINDOWSROUTEMONITOR_H

#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>

#include <QHash>
#include <QMap>
#include <QObject>
#include <QTimer> // AVPN win-fix: дебаунс шторма нотификаций

#include "ipaddress.h"

class WindowsRouteMonitor final : public QObject {
  Q_OBJECT

 public:
  WindowsRouteMonitor(quint64 luid, QObject* parent);
  ~WindowsRouteMonitor();

  void setDetaultRouteCapture(bool enable);

  bool addExclusionRoute(const IPAddress& prefix);
  bool deleteExclusionRoute(const IPAddress& prefix);
  void flushExclusionRoutes() { return flushRouteTable(m_exclusionRoutes); };

  // AVPN win-fix (2026-07-07): bulk-окно вокруг массового addExclusionRoute (RU-direct ~8.6k).
  // begin кэширует таблицу маршрутов и метрики ОДИН раз; внутри каждый addExclusionRoute
  // переиспользует кэш и НЕ пересчитывает captured-routes; end делает ОДИН финальный пересчёт.
  // Схлопывает O(N²) (таблица рескан на каждый маршрут) в O(N) → убирает «бесконечный коннект».
  void beginBulkExclusion();
  void endBulkExclusion();

  quint64 getLuid() const { return m_luid; }

 public slots:
  void routeChanged();

 private:
  // AVPN win-fix (2026-07-07): RU-direct-посев (~8.6k CreateIpForwardEntry) порождал шторм
  // NotifyRouteChange2 → 8.6k очередей routeChanged(), каждая с полным GetIpForwardTable2 и
  // пересканом — квадратичная деградация душила сервис. Коалесцируем в один пересчёт за 300мс.
  void routeChangedNow();
  QTimer m_routeChangeDebounce;

  // AVPN win-fix: состояние bulk-окна (см. beginBulkExclusion). m_bulkTable — кэш PMIB_IPFORWARD_TABLE2
  // (void* чтобы не тащить winsock-типы в заголовок сверх нужного), живёт между begin/end.
  bool m_bulkExclusion = false;
  void* m_bulkTable = nullptr;
  // AVPN win-fix: уборка exclusion-маршрутов-сирот от прошлой (крашнутой) сессии по сигнатуре
  // Protocol==NETMGMT && Metric==EXCLUSION_ROUTE_METRIC. Зовётся в конструкторе.
  void purgeOrphanExclusionRoutes();

  bool isRouteExcluded(const IP_ADDRESS_PREFIX* dest) const;
  static bool routeContainsDest(const IP_ADDRESS_PREFIX* route,
                                const IP_ADDRESS_PREFIX* dest);
  static QHostAddress prefixToAddress(const IP_ADDRESS_PREFIX* dest);

  void flushRouteTable(QHash<IPAddress, MIB_IPFORWARD_ROW2*>& table);
  void updateExclusionRoute(MIB_IPFORWARD_ROW2* data, void* table);
  void updateInterfaceMetrics(int family);
  void updateCapturedRoutes(int family);
  void updateCapturedRoutes(int family, void* table);

  QHash<IPAddress, MIB_IPFORWARD_ROW2*> m_exclusionRoutes;
  QMap<quint64, ULONG> m_interfaceMetricsIpv4;
  QMap<quint64, ULONG> m_interfaceMetricsIpv6;

  // Default route cloning
  bool m_defaultRouteCapture = false;
  QHash<IPAddress, MIB_IPFORWARD_ROW2*> m_clonedRoutes;

  const quint64 m_luid = 0;
  HANDLE m_routeHandle = INVALID_HANDLE_VALUE;
};

#endif /* WINDOWSROUTEMONITOR_H */
