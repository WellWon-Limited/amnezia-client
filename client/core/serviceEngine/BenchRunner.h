// AVPN serviceEngine — in-app бенч соединения (для «Панели администратора» в настройках).
// Меряет ТЕКУЩИЙ сетевой путь устройства (NE-туннель системный ⇒ неважно, чей VPN активен):
// DNS-тайминги + A-записи (гео-CDN), HTTP TTFB/total по корпусу сайтов, ICMP, down/up throughput,
// latency-under-load (аналог RPM networkQuality). Результат — JSON schema:1, совместимый с
// tools/connect-bench (репо tribe-front): сводится общим summarize.sh с замерами с Mac.
// Строго async (сигналы QNAM/QDnsLookup/таймеры), БЕЗ nested QEventLoop (правило NetAwait.h).
// PII нет: публичный IP не сохраняется (из cdn-cgi/trace берём только loc/colo).
#pragma once

#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonObject>
#include <QObject>
#include <QPointer>
#include <QStringList>
#include <QVector>

#include <algorithm>

class QNetworkAccessManager;
class QNetworkReply;
class QDnsLookup;
class QTimer;

namespace avpn {

class IRttProbe;

class BenchRunner : public QObject {
    Q_OBJECT
public:
    // nam — общий QNAM движка (живёт дольше бенча). ICMP-проба своя (не делим с per-node замером).
    explicit BenchRunner(QNetworkAccessManager *nam, QObject *parent = nullptr);
    ~BenchRunner() override;

    bool running() const { return m_running; }

    // extra — вклеивается в результат как extra{} (tunnel_state, node_id, platform, app_ver).
    void start(const QString &label, const QJsonObject &extra);
    void cancel(); // идемпотентно; никаких сигналов после cancel

    // --- чистая математика (inline в хедере: тестируется в tests/parse_check.cpp без moc) ---
    static double median(QVector<double> v)              // пустой → -1 («нет данных»)
    {
        if (v.isEmpty())
            return -1;
        std::sort(v.begin(), v.end());
        const int n = v.size();
        return (n % 2 == 1) ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2.0;
    }
    static double mbit(qint64 bytes, qint64 elapsedMs)   // байты за мс → Mbit/s (0 при elapsed<=0)
    {
        if (elapsedMs <= 0 || bytes <= 0)
            return 0;
        return double(bytes) * 8.0 / (double(elapsedMs) / 1000.0) / 1e6;
    }

signals:
    void stageChanged(const QString &stage); // "dns" | "http" | "ping" | "down" | "up" | "done"
    void finished(const QJsonObject &result);
    void failed(const QString &error);

private:
    // конвейер стадий; каждая по завершении зовёт следующую (всё на главном потоке)
    void stageTrace();
    void stageDns();
    void stageHttp();
    void stagePing();
    void stageIdleRtt();
    void stageDown();
    void stageUp();
    void assemble();

    void dnsNext();
    void httpNext();
    void idleRttNext();
    QNetworkReply *head204(); // HEAD generate_204 (rtt-зонд)
    void abortReply();

    QNetworkAccessManager *m_nam = nullptr;
    IRttProbe *m_icmp = nullptr; // собственная RttProbeIcmp (Win — стаб)

    bool m_running = false;
    int  m_epoch = 0;  // анти-UAF/анти-стейл: колбэки старого запуска игнорируются
    QString m_label;
    QJsonObject m_extra;

    QPointer<QNetworkReply> m_reply;
    QPointer<QNetworkReply> m_loadPending; // rtt-зонд под нагрузкой (не более одного в полёте)
    QDnsLookup *m_dns = nullptr;
    QTimer *m_loadTimer = nullptr;   // rtt-зонды во время down-стадии
    QElapsedTimer m_t;

    // результаты стадий
    QString m_loc, m_colo;
    int m_dnsIdx = 0;
    QJsonArray m_dnsProbes;
    int m_httpIdx = 0; // url*2+run
    QJsonArray m_httpProbes;
    qint64 m_httpTtfbMs = -1;
    qint64 m_httpBytes = 0;
    QJsonArray m_pingProbes;
    int m_idleIdx = 0;
    QVector<double> m_idleRtt;
    QVector<double> m_loadedRtt;
    qint64 m_downBytes = 0, m_downFirstByteMs = -1, m_downEndMs = -1;
    double m_upMbit = 0;
};

} // namespace avpn
