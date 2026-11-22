#pragma once

// AVPN: блокирующее ожидание QNetworkReply С ЖЁСТКИМ ТАЙМАУТОМ на ВЕСЬ запрос.
// Проблема: у QNetworkReply нет таймаута на общую длительность (есть лишь transferTimeout на
// неактивность сокета, и то не во всех версиях/транспортах). Зависший/медленный control plane
// может держать reply «живым» сколь угодно долго. Наши вызовы синхронные (вложенный QEventLoop
// на потоке движка/GUI), поэтому такой висящий reply = вечный фриз UI.
// Решение: по истечении timeoutMs делаем reply->abort() → finished(OperationCanceledError),
// HTTP-code остаётся 0 → штатная ветка обработчика «network error / пустой результат».
// Использовать ВМЕСТО голого `QEventLoop loop; connect(finished,&loop,quit); loop.exec();`.
//
// Дефолт 15 c: с запасом покрывает enroll/subscription/redeem на медленной мобильной сети,
// но гарантированно разблокирует UI, если бэкенд не ответил.

#include <QElapsedTimer>
#include <QEventLoop>
#include <QList>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QPointer>
#include <QDateTime>
#include <QTimer>

#include <algorithm>
#include <functional>
#include <memory>

namespace avpn {

inline constexpr int kNetTimeoutMs  = 15000; // АСИНХРОННЫЙ путь (armTimeout) — UI не блокируется
// AVPN (краш-фикс iOS): СИНХРОННЫЙ awaitReply крутит вложенный QEventLoop, блокирующий ГЛАВНЫЙ поток.
// 15 c здесь > iOS-watchdog 5 c → при suspend/медленном бэке давало 0x8BADF00D («Hang UIKit-runloop»).
// Держим СТРОГО < 5 c: операция при таймауте уходит в штатную ветку «сеть недоступна» (code 0) + ретрай.
inline constexpr int kSyncTimeoutMs = 4000;

inline void awaitReply(QNetworkReply *reply, int timeoutMs = kSyncTimeoutMs)
{
    if (!reply)
        return;
    if (reply->isFinished())
        return; // ответ/ошибка уже пришли синхронно — входить в цикл не нужно

    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);

    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, [reply, &loop]() {
        if (reply->isRunning())
            reply->abort(); // → finished(OperationCanceledError); обработчик увидит code==0
        loop.quit();
    });

    timer.start(timeoutMs);
    // AVPN (краш-фикс iOS): ExcludeUserInputEvents — пока крутится вложенный цикл, НЕ доставляем
    // UIKit-тачи в QML. Иначе очередной тач хит-тестит всё ещё включённую кнопку → повторный
    // onClicked → второй awaitReply застекает ещё один loop.exec() → re-entrancy → abort().
    // Тачи не теряются: отрабатывают после выхода из цикла. Сетевой/таймаут-выход не затронут.
    loop.exec(QEventLoop::ExcludeUserInputEvents);
}

// AVPN: «жёсткий» таймаут для АСИНХРОННОГО reply (без вложенного QEventLoop — для GUI-потока).
// QTimer припаркован к reply (живёт/умирает вместе с ним); по истечении делает abort()
// → finished(OperationCanceledError), code==0. Использовать там, где nested loop недопустим
// (вызовы прямо из QML на GUI-потоке: re-entrancy при destroy объекта в nested loop = краш).
inline void armTimeout(QNetworkReply *reply, int timeoutMs = kNetTimeoutMs)
{
    if (!reply)
        return;
    // Журнал тестирования: метка старта — длительность запроса в событии http.
    reply->setProperty("avpn_t0", QDateTime::currentMSecsSinceEpoch());
    QTimer *t = new QTimer(reply);
    t->setSingleShot(true);
    QObject::connect(t, &QTimer::timeout, reply, [reply]() {
        if (reply->isRunning()) {
            // Волна-4 (P2-2): таймаут — честный отказ входа; abort без этой метки (смена ноды,
            // стоп туннеля) отказом не считается (classifyApiOutcome).
            reply->setProperty("avpn_timed_out", true);
            reply->abort();
        }
    });
    t->start(timeoutMs);
}

// T1 (device round 6), one rule for every in-tunnel data check (own whoami, the provider probe): no first byte
// shareMs after the request started = starving -> starved(true); the first byte after that = receiving again ->
// starved(false). Nothing is told when the first byte comes inside the share. The timer is parked on the reply
// (it dies with it); a request that ended is never reported. The caller's sink decides what starving means.
inline void watchFirstByte(QNetworkReply *reply, qint64 shareMs, std::function<void(bool)> starved)
{
    if (!reply || !starved)
        return;
    struct State {
        bool gotByte = false;
        bool told = false;
    };
    auto st = std::make_shared<State>();
    QObject::connect(reply, &QNetworkReply::readyRead, reply, [st, starved]() {
        if (st->gotByte)
            return;
        st->gotByte = true;
        if (st->told)
            starved(false);
    });
    QTimer::singleShot(int(std::max<qint64>(0, shareMs)), reply, [reply, st, starved]() {
        if (st->gotByte || !reply->isRunning())
            return;
        st->told = true;
        starved(true);
    });
}

// Tunnel transition on the shared QNAM (DebugSnapshot.h::transitionNetAction). android5 H1/H3 (21.11): the app's main
// thread stood ~5 s right after the native state on a return from the background - with requests in flight,
// clearConnectionCache() runs QNetworkAccessManagerPrivate::destroyThread on the CALLER's thread: the HTTP thread is told
// to quit and waited for (up to 5 s) while it still serves them. Nothing here may wait, and nothing runs inside the
// caller's state handler (the state and the screen come first): on the next event-loop turn the requests running at
// the transition (snapshot) are aborted - their owners re-issue them over the new path - and the cached connections
// (dead keep-alive ones of the old path) are dropped only once no request of this QNAM runs, re-asked whenever one
// ends; a request started after the transition is therefore never stranded. One drop at a time: a transition while
// one waits joins it. abortInFlight without clearCache: someone else asked the drop (upstream on Connected - which
// goes through here too now).
inline constexpr char kCacheClearPending[] = "avpnCacheClearPending";   // a drop waits for an idle QNAM
inline constexpr char kCacheClearLastMs[] = "avpnCacheClearLastMs";     // how long the last drop took (journal)

namespace detail {
inline QList<QPointer<QNetworkReply>> runningReplies(QNetworkAccessManager *nam)
{
    QList<QPointer<QNetworkReply>> running;
    const auto replies = nam->findChildren<QNetworkReply *>(QString(), Qt::FindDirectChildrenOnly);
    for (QNetworkReply *r : replies)
        if (r->isRunning())
            running << r;
    return running;
}

inline void clearCacheWhenIdle(QNetworkAccessManager *nam)
{
    if (!runningReplies(nam).isEmpty()) {
        QObject::connect(
            nam, &QNetworkAccessManager::finished, nam,
            [nam](QNetworkReply *) { QTimer::singleShot(0, nam, [nam]() { clearCacheWhenIdle(nam); }); },
            Qt::SingleShotConnection);
        return;
    }
    QElapsedTimer took;
    took.start();
    nam->clearConnectionCache(); // idle: the HTTP thread serves nothing, its quit is immediate
    nam->setProperty(kCacheClearLastMs, qint64(took.elapsed()));
    nam->setProperty(kCacheClearPending, false);
}
} // namespace detail

inline void resetApiConnections(QNetworkAccessManager *nam, bool clearCache, bool abortInFlight)
{
    if (!nam)
        return;
    const QList<QPointer<QNetworkReply>> running =
        abortInFlight ? detail::runningReplies(nam) : QList<QPointer<QNetworkReply>>();
    const bool startDrop = clearCache && !nam->property(kCacheClearPending).toBool();
    if (startDrop)
        nam->setProperty(kCacheClearPending, true);
    if (running.isEmpty() && !startDrop)
        return;
    QTimer::singleShot(0, nam, [nam, running, startDrop]() {
        for (const QPointer<QNetworkReply> &r : running)
            if (r && r->isRunning())
                r->abort();
        if (startDrop)
            detail::clearCacheWhenIdle(nam);
    });
}
} // namespace avpn
