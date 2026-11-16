// service/server/tests/tribe_scan_fakes.h - AVPN test doubles for the Scanner's service host
// (tribe_scan.cpp links against them instead of the Go archive, NetworkUtilities and pf).
#pragma once

#include <QByteArray>
#include <QList>
#include <QMutex>
#include <QString>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>

#include "amnezia_xray.h"

namespace fake {

struct Call {
    QString what;        // scan_message | stop_all
    QByteArray message;  // scan_message: the request bytes as received
    QByteArray options;  // scan_message: host_options ("" = NULL)
    qint64 waitMs = -1;  // stop_all
    qint64 epoch = -1;   // stop_all: host_epoch
};

struct Engine {
    QMutex mutex;
    QList<Call> calls;
    QList<QString> order; // every bindings call and every test-recorded event, in order ("arm:en7", ...)
    std::function<QByteArray(const QByteArray &message, const QByteArray &options)> reply;
    bool stopAllResult = true;
    QByteArray stopAllReply; // non-empty: the epoch stop answers exactly this

    std::mutex gateMutex;
    std::condition_variable gateCv;
    bool gateOpen = true;

    std::atomic<int> gateWaiters{0}; // calls blocked at the closed gate right now
    std::atomic<int> setSockCallbackCalls{0};
    std::atomic<int> configureCalls{0};
    std::atomic<int> startCalls{0};
    std::atomic<int> stopCalls{0};
    std::atomic<int> logHandlerCalls{0};
    std::atomic<int> tunnelCallbackInvocations{0};
    amnezia_xray_sockcallback tunnelCallback = nullptr;
    void *tunnelContext = nullptr;

    void reset();
    QList<Call> snapshot();
    QList<QString> orderSnapshot();
    void note(const QString &event);
    void closeGate();
    void openGate();
};

Engine &engine();

} // namespace fake
