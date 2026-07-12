// client/core/serviceEngine/BypassListService.h
// AVPN server-driven АнтиВПН (Task 9): оркестратор серверных bypass-списков
// (/v1/bypass-lists — ru_cidrs/bypass_extra/cn_liauto_cidrs/split_dns): подписанный fetch
// (ed25519), ETag/304, LKG-кеш на диске (BypassListLkg.h), анти-downgrade, kill-switch
// через remote-config feature flag. Async (armTimeout) — тот же паттерн, что ConfigService,
// НИКАКИХ nested QEventLoop на GUI-потоке (память tribe-engine-net-async).
#pragma once

#include "BypassListTypes.h"
#include "ConfigTypes.h"

#include <QObject>
#include <QString>

class QNetworkAccessManager;
class QTimer;

namespace avpn {

class BypassListService : public QObject
{
    Q_OBJECT
public:
    BypassListService(QNetworkAccessManager *nam, const QString &baseUrl,
                      const QString &pubKeyHex, QObject *parent = nullptr);

    // loadLkg() (мгновенно, без сети) + первый fetch() + взводит таймер повторного фетча (6ч).
    void start();

    // AVPN (diag-report, Task 4 bff-3): версия последних применённых списков (LKG или свежий
    // fetch); 0 = серверные списки не применялись (работают вкомпиленные фолбэки).
    int lkgVersion() const { return m_lkgVersion; }

public slots:
    // Смена активного edge (Task 10 подключит ConfigService::activeEdgeChanged). Влияет
    // ТОЛЬКО на будущие фетчи — смена базы сама по себе НЕ триггерит немедленный рефетч.
    void setBaseUrl(const QString &b);

    // Kill-switch (Task 10 подключит ConfigService::configApplied). feature-флаг
    // "remote_bypass_lists"==false → пустой invalid снапшот в BypassListStore + фетч на паузу,
    // пока флаг не вернут обратно (тогда — снова loadLkg()+fetch()).
    void onRemoteConfigApplied(const avpn::RemoteConfig &cfg);

signals:
    void listsApplied(const avpn::BypassLists &l);

private:
    void loadLkg();
    void fetch();
    void applyBody(const QByteArray &body, const QByteArray &sigB64, const QByteArray &etag);
    void saveLkg(const QByteArray &body, const QByteArray &sigB64, const QByteArray &etag);

    QNetworkAccessManager *m_nam = nullptr;
    QString m_baseUrl;
    QString m_pubKeyHex;
    QString m_etag;
    int     m_lkgVersion = 0;
    bool    m_disabled = false;
    bool    m_loggedNotFound = false; // 404 — один лог за запуск, не спамить
    // AVPN: дедуп параллельных фетчей (повторный start()/таймер/onRemoteConfigApplied не должны
    // плодить второй in-flight запрос) — снимается в ЛЮБОЙ ветке обработчика finished, включая
    // armTimeout-abort (armTimeout → finished(OperationCanceledError), лямбда всё равно вызовется).
    bool    m_fetching = false;
    QTimer *m_timer = nullptr;
};

// Потокобезопасный снапшот для читателей вне GUI-потока (VpnConnectionTunnelControl).
struct BypassListStore
{
    static void        set(const BypassLists &l); // под QMutex
    static BypassLists get();                      // копия под QMutex
};

} // namespace avpn
