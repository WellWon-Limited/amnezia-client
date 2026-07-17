#pragma once

// AVPN: детектор РКН-режима «белых списков» — драйвер проб вокруг чистой логики
// WhitelistVerdict.h. Спека: 2026-07-12-whitelist-mode-detector-design.md §3.
//
// НЕ поллинг: раунд проб запускается ТОЛЬКО по триггерам (серия фейлов control plane,
// снятый watchdog'ом коннект, foreground, вход на сотовую при подозрении), с дебаунсом
// whitelist_round_min_gap_ms. Условия старта: транспорт Cellular + туннель ПОЛНОСТЬЮ
// опущен (tunnelIdle() — иначе пробы уйдут в мёртвый туннель = ложное «всё мертво»).
//
// Проба = HTTPS HEAD (DNS+TCP+TLS с реальным SNI и валидацией цепочки) через общий
// QNetworkAccessManager; ЛЮБОЙ HTTP-ответ (хоть 403) = хост жив, интересен только факт
// завершения handshake. Редиректы не следуем (ManualRedirectPolicy). НЕ ICMP: РКН-фильтр
// работает на L7/SNI. Гигиена: снапшот транспорта на старте раунда, смена
// transport/reachability посреди раунда -> discard целиком (gen-инвалидация, образец
// RttProbeIcmp). Выход из режима: дешёвая exit-проба одного control-хоста (ротация) раз в
// whitelist_exit_probe_ms + мгновенно по noteControlPlaneOk()/уходу с сотовой.
//
// Kill-switch: features.whitelist_detector (default TRUE) читается в рантайме на каждом
// maybeStartRound — бэкенд гасит фичу без релиза. Анти-фриз: только сигналы/таймеры.

#include "WhitelistVerdict.h"

#include <QList>
#include <QObject>
#include <QString>
#include <QTimer>

#include <functional>

class QNetworkAccessManager;

namespace avpn {

class WhitelistDetector : public QObject {
    Q_OBJECT
public:
    explicit WhitelistDetector(QNetworkAccessManager *nam, std::function<bool()> tunnelIdle,
                               QObject *parent = nullptr);

    bool active() const { return m_hyst.active; }

    // D-3 п.17 (Доктор): форс-прогон дифф-проб ВСЕХ 4 наборов прямо сейчас, мимо дебаунса.
    // Диагностический: гистерезис НЕ трогает (одиночный раунд != вход в режим). Предусловия
    // те же, что у обычного раунда (сотовая + опущенный туннель — пробы через туннель врут)
    // и отсутствие уже летящего раунда; не выполнены -> false, колбэк НЕ будет вызван
    // (звонящий обязан иметь свой таймаут). При смене сети посреди раунда колбэк получает
    // Inconclusive.
    bool runRoundNow(std::function<void(WlVerdict verdict, bool marginal)> cb);

    // Триггеры (§3.1 спеки) — дешёвые, дебаунс внутри.
    void noteControlPlaneFailure(); // транспортный фейл bootstrap/ConfigService (не 4xx)
    void noteControlPlaneOk();      // ЛЮБОЙ HTTP-ответ control plane = сеть жива -> сброс/выход
    void noteConnectFailure();      // watchdog снял зависший коннект
    void noteForeground();

signals:
    void activeChanged(bool active);

private:
    void onTransportChanged();
    void maybeStartRound();
    void startRound();
    void abortRound();  // гигиена: смена сети посреди раунда -> discard
    void finishRound();
    void probeHost(const QString &host, bool isControl, bool isAnchor, bool isSocial, int timeoutMs);
    void runExitProbe();
    bool cellularNow() const;
    void setActive(bool on);

    QNetworkAccessManager  *m_nam = nullptr;
    std::function<bool()>   m_tunnelIdle;
    WlHysteresis            m_hyst;

    int             m_gen = 0;               // инвалидация колбэков отброшенного раунда
    bool            m_roundInFlight = false;
    bool            m_roundCellular = false; // снапшот транспорта на старте раунда (гигиена §3.3)
    int             m_pending = 0;
    QList<WlSample> m_samples;
    int             m_failStreak = 0;        // фейлы control plane подряд (триггер с порога 2)
    qint64          m_lastRoundStartMs = 0;
    int             m_exitRotation = 0;      // ротация control-хостов в exit-пробе
    QTimer          m_confirmTimer;          // пауза между confirm-раундами
    QTimer          m_exitTimer;             // exit-пробы в активном режиме
    // Ревью 2026-07-12 (finding 1): noteConnectFailure() приходит из watchdog ДО того, как
    // async-teardown осадит туннель в disconnected → гейт tunnelIdle() режет раунд. Короткий
    // ретрай дотягивает старт до момента, когда туннель реально idle (кап попыток — не поллинг).
    QTimer          m_idleRetryTimer;
    int             m_idleRetryLeft = 0;
    // D-3: форс-раунд Доктора (диагностический, без гистерезиса)
    std::function<void(WlVerdict, bool)> m_forcedCb;
    bool            m_forcedRound = false;
};

} // namespace avpn
