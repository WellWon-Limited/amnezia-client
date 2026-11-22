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

#include <QEventLoop>
#include <QList>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
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

// Tunnel transitions on the shared QNAM - the GUI thread never waits for Qt's HTTP thread.
//
// android5 H1/H3 (21.11): the GUI thread stood 5 s after a tunnel transition on a return from the background. Qt 6.11.1:
// QNetworkAccessManager::clearConnectionCache() -> QNetworkAccessManagerPrivate::destroyThread() quits the HTTP thread and
// waits for it on the CALLER's thread (qnetworkaccessmanager.cpp:1731-1733, 1752-1757: thread->wait(QDeadlineTimer(5000))),
// and ~QNetworkAccessManagerPrivate does the same (:1736-1739). The HTTP thread in turn reports a finished TLS handshake
// to the GUI with Qt::BlockingQueuedConnection (qnetworkreplyhttpimpl.cpp:996-997, encrypted(); also sslErrors, auth): a
// request mid-handshake at the transition (the resume's journal kick and pollers) makes the two threads wait for each
// other until the 5 s deadline. No deferral fixes that (review of 0e31a2571): neither clearConnectionCache() nor deleting
// a QNAM may happen on the GUI thread.
//
// What clearing was for - no request of a new tunnel generation over a socket of the old path - is kept by the
// connection key instead. Qt reuses a pooled connection by "http-connection:" + scheme://host:port + proxy + ":" +
// peerVerifyName (qhttpthreaddelegate.cpp:94-150, used at :303-311). Every request of the shared QNAM (TribeNetworkAccess
// Manager::createRequest) carries:
//  - the generation's parity as the key's discriminator: peerVerifyName = the URL's own host on odd generations, none on
//    even ones. The name verified and sent as SNI is the same host either way (QSslSocketPrivate::isMatchingHostname
//    lowercases it, qsslsocket.cpp:3012-3041), so nothing else changes - but a request after a transition never joins a
//    connection opened before it (one still in use, with an idle keep-alive channel, would otherwise take it);
//  - ConnectionCacheExpiryTimeoutSecondsAttribute = 0 (qnetworkaccesscache.cpp:217-221; qnetworkreplyhttpimpl.cpp:904-905):
//    a connection is closed as soon as its last request is done, so nothing of a generation is still pooled when the
//    parity comes back two transitions later. The cost: no keep-alive between sequential API calls (one TCP + TLS
//    handshake per isolated call - our API rate is a few calls a minute); concurrent calls still share a connection.
// resetApiConnections, for its two callers (the native-state handler, upstream's Connected): clearCache - the next
// generation begins NOW (synchronously: requests issued later in the same handler already use the new key);
// abortInFlight - the requests running at the transition are aborted on the next event-loop turn (no finished-lambdas
// inside the caller's handler), their owners re-issue them on the new key; an aborted HTTP/1 request closes its socket
// (qhttpnetworkconnection.cpp:975-978) and its connection then closes with its last request. Nothing waits.
inline constexpr char kConnGeneration[] = "avpnConnGeneration"; // the shared QNAM's tunnel generation (parity = key)

// The connection policy of one request on generation `generation` (pure; TribeNetworkAccessManager::createRequest).
// What the caller set itself stays.
inline QNetworkRequest withConnectionPolicy(QNetworkRequest r, quint64 generation)
{
    if (!r.attribute(QNetworkRequest::ConnectionCacheExpiryTimeoutSecondsAttribute).isValid())
        r.setAttribute(QNetworkRequest::ConnectionCacheExpiryTimeoutSecondsAttribute, 0);
    if (r.peerVerifyName().isEmpty() && (generation & 1) && !r.url().host().isEmpty())
        r.setPeerVerifyName(r.url().host());
    return r;
}

// The shared QNAM of the app (amneziaApplication.cpp): every request gets the connection policy above.
class TribeNetworkAccessManager : public QNetworkAccessManager
{
public:
    using QNetworkAccessManager::QNetworkAccessManager;

protected:
    QNetworkReply *createRequest(Operation op, const QNetworkRequest &request, QIODevice *outgoingData = nullptr) override
    {
        return QNetworkAccessManager::createRequest(
            op, withConnectionPolicy(request, property(kConnGeneration).toULongLong()), outgoingData);
    }
};

inline void resetApiConnections(QNetworkAccessManager *nam, bool clearCache, bool abortInFlight)
{
    if (!nam)
        return;
    if (clearCache)
        nam->setProperty(kConnGeneration, nam->property(kConnGeneration).toULongLong() + 1);
    if (!abortInFlight)
        return;
    QList<QPointer<QNetworkReply>> running;
    const auto replies = nam->findChildren<QNetworkReply *>(QString(), Qt::FindDirectChildrenOnly);
    for (QNetworkReply *r : replies)
        if (r->isRunning())
            running << r;
    if (running.isEmpty())
        return;
    QTimer::singleShot(0, nam, [running]() {
        for (const QPointer<QNetworkReply> &r : running)
            if (r && r->isRunning())
                r->abort();
    });
}
} // namespace avpn
