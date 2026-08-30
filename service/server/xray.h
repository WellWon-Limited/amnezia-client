#ifndef XRAY_H
#define XRAY_H

#include <QJsonObject>
#include <QMutex>
#include <QString>

#include <atomic>
#include <memory>
#include <vector>

class Xray
{
public:
    static Xray& getInstance()
    {
        static Xray instance;
        return instance;
    }

    bool startXray(const QString& cfg);
    bool stopXray();

    // Versioned desktop contract.  A stale client may only stop/query the
    // exact native session it started; it can never affect a replacement.
    bool startXraySession(const QString& sessionId, const QString& cfg);
    bool stopXraySession(const QString& sessionId);
    QJsonObject runtimeStatusV1(const QString& sessionId);

private:
    struct SocketCallbackContext {
        Xray *owner = nullptr;
        quint64 generation = 0;
    };

    static void ctxSockCallback(uintptr_t fd, void* ctx) {
        auto *context = reinterpret_cast<SocketCallbackContext *>(ctx);
        if (context != nullptr && context->owner != nullptr) {
            context->owner->sockCallback(fd, context->generation);
        }
    }
    static void ctxLogHandler(char* str, void* ctx) {
        reinterpret_cast<Xray*>(ctx)->logHandler(str);
    }

    void sockCallback(uintptr_t fd, quint64 generation);
    void logHandler(char* str);
    bool startXrayInternal(const QString& sessionId, const QString& cfg);
    bool stopXrayInternal(const QString& sessionId, bool requireExactSession);
    bool isCanonicalSessionId(const QString& sessionId) const;

#ifdef Q_OS_MAC
    bool preflightSocketProtection(int interfaceIndex);
#endif

#ifdef Q_OS_LINUX
    QByteArray m_defaultIfaceName;
#else
    std::atomic<int> m_defaultIfaceIdx{0};
#endif

    mutable QMutex m_stateMutex;
    QString m_sessionId;
    QString m_runtimeState{QStringLiteral("stopped")};
    QString m_failureReason;
    bool m_coreStarted = false;
    bool m_quarantined = false;
    bool m_haveLastStats = false;
    quint64 m_lastRxBytes = 0;
    quint64 m_lastTxBytes = 0;
    quint64 m_lastRxPackets = 0;
    quint64 m_lastTxPackets = 0;
    quint64 m_counterResetCount = 0;
    std::atomic_bool m_socketProtectionAttempted{false};
    std::atomic_bool m_socketProtectionSucceeded{false};
    std::atomic_bool m_socketProtectionFailed{false};
    quint64 m_generationCounter = 0;
    std::atomic<quint64> m_activeGeneration{0};
    // The bindings callback ABI has no context destructor.  Retaining these
    // tiny tokens for daemon lifetime makes late callbacks memory-safe; the
    // generation check makes them semantically stale.
    std::vector<std::unique_ptr<SocketCallbackContext>> m_callbackContexts;

#ifdef Q_OS_MAC
    QString m_uplinkIfaceName;
    QString m_uplinkGateway;
    bool m_routesInstalled = false;
#endif
};

#endif // XRAY_H
