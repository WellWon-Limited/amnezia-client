// client/core/serviceEngine/RestartGuard.h
//
// AVPN (разбор 2026-09-23, журнал iPhone владельца): приложение само ведёт перезапуск туннеля
// (reconcile_restart, свитч движка, сторожа, дедлайны) как «стоп → ждём Disconnected → старт».
// На iOS свёрнутое приложение замораживается через секунды: стоп уходит, а старт — только при
// следующем открытии (10:05:54 → 10:14:54, 13:37:07.9 → 13:49:44 — VPN выключен, звонок в
// WhatsApp не прошёл). У апстрима Amnezia этого класса нет: приложение там туннель само не гасит.
//
// Решение: пока намерение «VPN включён», а туннель не в устоявшемся Connected, фасад держит
// фоновое время iOS (UIApplication background task, ~30 с) — начатый перезапуск доходит до старта,
// дальше NE живёт сам. Здесь только чистые решения (tests/restart_guard_check.cpp); вызов UIKit —
// platforms/ios/AvpnBackgroundGuard.mm.
#pragma once

namespace avpn {

struct RestartGuardInputs {
    bool wantConnected = false;  // намерение пользователя/машины: VPN должен быть поднят
    bool tunnelConnected = false; // последний наблюдённый нативный статус — Connected
    bool opInFlight = false;      // наш стоп/старт ещё не получил терминал
    bool needsRestart = false;    // reconcile запрошен перезапуск (стоп ещё впереди)
};

// Держать фоновое время: намерение ON и состояние не устоялось. Намерение OFF (стоп пользователя)
// продолжения не требует — iOS вправе заморозить приложение сразу.
inline bool restartGuardWanted(const RestartGuardInputs &in)
{
    if (!in.wantConnected)
        return false;
    const bool settled = in.tunnelConnected && !in.opInFlight && !in.needsRestart;
    return !settled;
}

// Защёлка удержания: Begin/End на фронтах, после истечения системного времени — не просить снова
// в том же фоне (цикл begin/expire), пока приложение не выйдет на экран или состояние не устоится.
class RestartGuardLatch {
public:
    enum class Action { None, Begin, End };

    Action sync(bool wanted)
    {
        if (!wanted) {
            m_expired = false; // устоялось — следующий перезапуск снова защищён
            if (m_held) {
                m_held = false;
                return Action::End;
            }
            return Action::None;
        }
        if (m_held || m_expired)
            return Action::None;
        m_held = true;
        return Action::Begin;
    }

    // Система закончила фоновое время (обработчик истечения уже завершил задачу).
    void onExpired()
    {
        m_held = false;
        m_expired = true;
    }

    // Приложение снова на экране: фоновое время не нужно, но защёлку истечения снимаем.
    void onForeground() { m_expired = false; }

    bool held() const { return m_held; }

private:
    bool m_held = false;
    bool m_expired = false;
};

} // namespace avpn
