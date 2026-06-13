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
#include <QNetworkReply>
#include <QTimer>

namespace avpn {

inline constexpr int kNetTimeoutMs = 15000;

inline void awaitReply(QNetworkReply *reply, int timeoutMs = kNetTimeoutMs)
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
    loop.exec();
}

// AVPN: «жёсткий» таймаут для АСИНХРОННОГО reply (без вложенного QEventLoop — для GUI-потока).
// QTimer припаркован к reply (живёт/умирает вместе с ним); по истечении делает abort()
// → finished(OperationCanceledError), code==0. Использовать там, где nested loop недопустим
// (вызовы прямо из QML на GUI-потоке: re-entrancy при destroy объекта в nested loop = краш).
inline void armTimeout(QNetworkReply *reply, int timeoutMs = kNetTimeoutMs)
{
    if (!reply)
        return;
    QTimer *t = new QTimer(reply);
    t->setSingleShot(true);
    QObject::connect(t, &QTimer::timeout, reply, [reply]() {
        if (reply->isRunning())
            reply->abort();
    });
    t->start(timeoutMs);
}

} // namespace avpn
