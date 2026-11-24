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

#include <QCoreApplication>
#include <QEventLoop>
#include <QHash>
#include <QList>
#include <QNetworkAccessManager>
#include <QNetworkCookieJar>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPointer>
#include <QDateTime>
#include <QThread>
#include <QTimer>

#include <algorithm>
#include <chrono>
#include <functional>
#include <memory>
#include <utility>

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

// Tunnel transitions on the app's shared API manager - one connection pool per tunnel generation, and the GUI thread
// never waits for Qt's HTTP thread (android5 H1/H3, 21.11; reviews of 0e31a2571 and 5c354b603).
//
// The hazard (Qt 6.11.1). clearConnectionCache() and the destruction of a QNetworkAccessManager call destroyThread(),
// which quits the manager's HTTP thread and waits for it on the CALLER's thread (qnetworkaccessmanager.cpp:1731-1739,
// 1752-1757: thread->wait(QDeadlineTimer(5000))), while that thread reports a TLS handshake, sslErrors and auth to the
// reply's thread with Qt::BlockingQueuedConnection (qnetworkreplyhttpimpl.cpp:986-1003). A transition mid-handshake
// stood 5 s on the GUI thread. A connection-key discriminator is no way out either: the key Qt pools by is only
// scheme://host:port + proxy + peerVerifyName (qhttpthreaddelegate.cpp:94-150, 303-311) - every field of it changes
// routing or TLS identity (review R3: a forced peerVerifyName survives an automatic redirect to another host).
//
// The design. The pool is per HTTP thread (QThreadStorage, qhttpthreaddelegate.cpp:170, 243-246, 311) and the HTTP thread
// is per manager (managerPrivate->createThread(), qnetworkreplyhttpimpl.cpp:713; qnetworkaccessmanager.cpp:1741-1749).
// So a tunnel generation is a plain QNetworkAccessManager of its own, and TribeNetworkAccessManager - the one object every
// holder keeps (amnApp->networkManager()) - routes each request to the current one:
//  - a transition (beginGeneration) makes every later request - new, re-issued after our abort, or redirected (a redirect
//    stays on its reply's own manager: qnetworkreplyhttpimpl.cpp:1393-1402 -> postRequest -> :713) - start on a manager
//    that has no connection at all; generations are never reused, so any number of transitions in a row is the same;
//  - requests and TLS are untouched: no attribute, no peer name, no SNI change; keep-alive within a generation is
//    Qt's own (an idle connection is kept 120 s, qnetworkaccesscache.cpp:13-14);
//  - the requests running at the transition are aborted on the next event-loop turn (the state and the screen first);
//    their owners re-issue them, on the new generation;
//  - an old generation is retired only when the last reply it created is destroyed (its owner's deleteLater): it is
//    moved to one retirement thread and deleted there, so destroyThread() waits there, never on the GUI thread. Its
//    replies stayed on the GUI thread until then, so the HTTP thread's blocking reports were always served.
// The facade itself never creates an HTTP thread (no request runs on it), so destroying it joins nothing. On app exit
// it deletes the replies of every generation first, as ~QNetworkAccessManager does (qnetworkaccessmanager.cpp:452-457:
// their pending blocking calls are dropped with them, qobject.cpp:204-205, 479-485), then retires every generation the
// same way - or, once the application object is gone (the real exit order), leaves them to the process end. Upstream's
// own clear on Connected (connectionUiController.cpp) runs only with AVPN_ENGINE=OFF: with the engine, the native-state
// handler is the one owner of "the path changed" (DebugSnapshot.h newApiGeneration).
// Cost: one HTTP thread and one TCP + TLS handshake per host per generation; sequential calls of a generation reuse
// their connection. A redirect queued by Qt just before our abort may still run on its (old) generation - for a reply
// that is already finished with OperationCanceled, so nobody reads it (qnetworkreplyhttpimpl.cpp:1401-1402).

// The thread retired generations are destroyed on: started once, never joined (the process ends it).
inline QThread *apiRetirementThread()
{
    static QThread *const thread = []() {
        auto *t = new QThread;
        t->setObjectName(QStringLiteral("Tribe API retirement"));
        t->start();
        return t;
    }();
    return thread;
}

// The app's shared API manager (GUI thread, as any QNetworkAccessManager): a facade over one plain manager per tunnel
// generation. Holders keep it as their QNetworkAccessManager *; reply->manager() is this object, reply->parent() the
// generation's manager.
class TribeNetworkAccessManager : public QNetworkAccessManager
{
public:
    explicit TribeNetworkAccessManager(QObject *parent = nullptr) : QNetworkAccessManager(parent) { live() << this; }

    ~TribeNetworkAccessManager() override
    {
        live().removeOne(this);
        // The app's exit: this facade is a child of the application object, destroyed after ~QCoreApplication - no
        // thread runs a posted deletion any more (QEventLoop needs the application), so the generations are then left
        // to the process end, as Qt leaves an HTTP thread that did not stop in time (qnetworkaccessmanager.cpp:1757-1760).
        const bool appAlive = QCoreApplication::instance() != nullptr;
        const auto gens = m_replies.keys();
        for (QNetworkAccessManager *gen : gens) {
            const auto replies = m_replies.take(gen);
            for (const QPointer<QNetworkReply> &r : replies)
                if (r)
                    QObject::disconnect(r, &QObject::destroyed, this, nullptr);
            qDeleteAll(gen->findChildren<QNetworkReply *>()); // as ~QNetworkAccessManager: the replies go first
            if (appAlive && std::none_of(replies.cbegin(), replies.cend(), [](const QPointer<QNetworkReply> &r) { return !r.isNull(); }))
                retire(gen);
            // else: left to the process end, not joined (also when a holder took a reply out of the manager)
        }
    }

    // The facade behind a holder's QNetworkAccessManager *, or nullptr (no RTTI needed).
    static TribeNetworkAccessManager *of(QNetworkAccessManager *nam)
    {
        for (TribeNetworkAccessManager *t : live())
            if (t == nam)
                return t;
        return nullptr;
    }

    quint64 generation() const { return m_generation; }
    // Older generations still waiting for their last reply to be destroyed (journal).
    int retiringGenerations() const { return int(m_replies.size()) - (m_current && m_replies.contains(m_current) ? 1 : 0); }

    // A tunnel transition: every request from now on starts on a new generation; the requests running on older ones
    // are aborted on the next turn (abortInFlight); an older generation retires off this thread once its replies are gone.
    void beginGeneration(bool abortInFlight)
    {
        ++m_generation;
        if (QNetworkAccessManager *old = std::exchange(m_current, nullptr))
            retireWhenIdle(old);
        if (!abortInFlight)
            return;
        QList<QPointer<QNetworkReply>> running;
        for (auto it = m_replies.cbegin(); it != m_replies.cend(); ++it)
            for (const QPointer<QNetworkReply> &r : it.value())
                if (r && r->isRunning())
                    running << r;
        if (running.isEmpty())
            return;
        QTimer::singleShot(0, this, [running]() {
            for (const QPointer<QNetworkReply> &r : running)
                if (r && r->isRunning())
                    r->abort();
        });
    }

protected:
    QNetworkReply *createRequest(Operation op, const QNetworkRequest &request, QIODevice *outgoingData = nullptr) override
    {
        // What QNetworkAccessManager::createRequest takes from the manager itself (qnetworkaccessmanager.cpp:1211-1225),
        // taken from this facade, so a holder's setting applies as before; the rest is the generation's stock path.
        QNetworkRequest req(request);
        if (redirectPolicy() != QNetworkRequest::NoLessSafeRedirectPolicy
            && req.attribute(QNetworkRequest::RedirectPolicyAttribute).isNull())
            req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, redirectPolicy());
        if (req.transferTimeoutAsDuration() == std::chrono::milliseconds::zero())
            req.setTransferTimeout(transferTimeoutAsDuration());
        if (autoDeleteReplies() && req.attribute(QNetworkRequest::AutoDeleteReplyOnFinishAttribute).isNull())
            req.setAttribute(QNetworkRequest::AutoDeleteReplyOnFinishAttribute, true);

        QNetworkAccessManager *gen = current();
        QNetworkReply *reply = nullptr;
        switch (op) {
        case HeadOperation: reply = gen->head(req); break;
        case GetOperation: reply = outgoingData ? gen->get(req, outgoingData) : gen->get(req); break;
        case PutOperation: reply = gen->put(req, outgoingData); break;
        case PostOperation: reply = gen->post(req, outgoingData); break;
        case DeleteOperation: reply = gen->deleteResource(req); break;
        default: // CustomOperation: the verb is in the request (QNetworkAccessManager::sendCustomRequest)
            reply = gen->sendCustomRequest(req, req.attribute(QNetworkRequest::CustomVerbAttribute).toByteArray(), outgoingData);
            break;
        }
        m_replies[gen] << QPointer<QNetworkReply>(reply);
        QObject::connect(reply, &QObject::destroyed, this, [this, gen]() {
            // the QPointer is already null here; the generation is checked once the reply is fully gone
            QMetaObject::invokeMethod(this, [this, gen]() { retireIfIdle(gen); }, Qt::QueuedConnection);
        });
        return reply;
    }

private:
    static QList<TribeNetworkAccessManager *> &live()
    {
        static QList<TribeNetworkAccessManager *> instances;
        return instances;
    }

    QNetworkAccessManager *current()
    {
        if (!m_current) {
            m_current = new QNetworkAccessManager; // no parent: a generation is moved to the retirement thread
            m_current->setCookieJar(cookieJar());   // one cookie jar for every generation, owned by this facade
            cookieJar()->setParent(this);
            m_replies.insert(m_current, {});
        }
        return m_current;
    }

    void retireWhenIdle(QNetworkAccessManager *gen)
    {
        QMetaObject::invokeMethod(this, [this, gen]() { retireIfIdle(gen); }, Qt::QueuedConnection);
    }

    void retireIfIdle(QNetworkAccessManager *gen)
    {
        const auto it = m_replies.find(gen);
        if (it == m_replies.end())
            return;
        it->removeAll(QPointer<QNetworkReply>()); // the destroyed ones (the current generation's list stays short too)
        if (gen == m_current || !it->isEmpty())
            return;
        m_replies.remove(gen);
        retire(gen);
    }

    // No reply of `gen` is left: destroyThread() of its ~QNetworkAccessManager runs on the retirement thread.
    static void retire(QNetworkAccessManager *gen)
    {
        gen->moveToThread(apiRetirementThread());
        gen->deleteLater();
    }

    QNetworkAccessManager *m_current = nullptr;
    QHash<QNetworkAccessManager *, QList<QPointer<QNetworkReply>>> m_replies; // every live generation -> its replies
    quint64 m_generation = 0;
};

// The one owner's step on a tunnel transition (AvpnEngineQml::applyNativeState). A manager that is not the facade
// (none in the app) can only have its running requests aborted.
inline void resetApiConnections(QNetworkAccessManager *nam)
{
    if (TribeNetworkAccessManager *tribe = TribeNetworkAccessManager::of(nam)) {
        tribe->beginGeneration(/*abortInFlight=*/true);
        return;
    }
    if (!nam)
        return;
    QList<QPointer<QNetworkReply>> running;
    for (QNetworkReply *r : nam->findChildren<QNetworkReply *>())
        if (r->isRunning())
            running << r;
    QTimer::singleShot(0, nam, [running]() {
        for (const QPointer<QNetworkReply> &r : running)
            if (r && r->isRunning())
                r->abort();
    });
}
} // namespace avpn
