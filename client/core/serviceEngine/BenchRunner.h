// AVPN serviceEngine — in-app бенч соединения (для «Панели администратора» в настройках).
// Меряет ТЕКУЩИЙ сетевой путь устройства (NE-туннель системный ⇒ неважно, чей VPN активен):
// DNS-тайминги + A-записи (гео-CDN), TCP/TLS-фазы, HTTP TTFB/total по корпусу сайтов, серия ICMP
// (loss/jitter), down/up throughput, latency-under-load (аналог RPM networkQuality) + авто-вердикты
// (BenchAnalysis.h). Результат — JSON schema:1, совместимый с tools/connect-bench (репо tribe-front).
// Режимы: полный (~2 мин, ~40 МБ) и lite (~30-40 с, ~8 МБ) — lite использует свип по нодам (BenchSweep).
// Строго async (сигналы QNAM/QDnsLookup/QSslSocket/таймеры), БЕЗ nested QEventLoop (правило NetAwait.h).
// PII нет: публичный IP не сохраняется (из cdn-cgi/trace берём только loc/colo).
#pragma once

#include <QElapsedTimer>
#include <QHash>
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
class QSslSocket;
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

    // extra — вклеивается в результат как extra{} (tunnel_state, node_id, platform, app_ver,
    // connect_ms при свипе). lite — короткий замер для пер-нодного свипа.
    void start(const QString &label, const QJsonObject &extra, bool lite = false);
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
    void stageChanged(const QString &stage); // "dns"|"tls"|"http"|"ping"|"rtt"|"down"|"up"|"done"
    void finished(const QJsonObject &result);
    void failed(const QString &error);

private:
    // конвейер стадий; каждая по завершении зовёт следующую (всё на главном потоке)
    void stageTrace();
    void stageDns();
    void stageTls();
    void stageHttp();
    void stagePing();
    // bench v5: сплит по ФАКТУ (RU-чекер vs egress туннеля, только «совпал/нет» — IP не пишем)
    // + IPv6 (AAAA-резолв и v6-цель). Только full-режим (lite пропускает).
    void stageSplit();
    void splitIpv6Lookup();
    void splitIpv6Http();
    // bench v5: path-MTU (DF-ping нисходящим свипом размеров; probeMtuOne). Только full-режим.
    void stageMtu();
    void mtuNext();
    void stageIdleRtt();
    void stageDown();
    void stageUp();
    void assemble();

    void dnsNext();
    void dnsFallback(const QString &host); // iOS: QDnsLookup не реализован → системный резолвер (QHostInfo)
    void tlsNext();
    void httpNext();
    void pingRound();
    void idleRttNext();
    QNetworkReply *head204(); // HEAD generate_204 (rtt-зонд)
    void abortReply();
    QStringList hosts() const;    // корпус по режиму (lite = 3 хоста: заруб+RU)
    QStringList tlsHosts() const; // подмножество для TCP/TLS-фаз

    QNetworkAccessManager *m_nam = nullptr;
    IRttProbe *m_icmp = nullptr; // собственная RttProbeIcmp (Win — стаб)

    bool m_running = false;
    bool m_lite = false;
    int  m_epoch = 0;  // анти-UAF/анти-стейл: колбэки старого запуска игнорируются
    QString m_label;
    QJsonObject m_extra;

    QPointer<QNetworkReply> m_reply;
    QPointer<QNetworkReply> m_loadPending; // rtt-зонд под нагрузкой (не более одного в полёте)
    int m_hostLookup = -1;                 // id активного QHostInfo::lookupHost (fallback DNS)
    QDnsLookup *m_dns = nullptr;
    QSslSocket *m_ssl = nullptr;
    QTimer *m_loadTimer = nullptr;   // rtt-зонды во время down-стадии
    QElapsedTimer m_t;

    // результаты стадий
    QString m_loc, m_colo;
    QString m_traceIp;        // ip= из cf-trace: ТОЛЬКО в памяти для сравнения в stageSplit; в JSON НЕ пишется
    QJsonObject m_splitCheck; // bench v5: {ru_reachable, ru_equals_tunnel_egress}
    QJsonObject m_ipv6;       // bench v5: {aaaa_ok, https_ok}
    int m_mtuIdx = 0;         // bench v5: индекс текущего размера в свипе MTU
    QJsonObject m_mtu;        // bench v5: {path_mtu | probed:false}
    int m_dnsIdx = 0;
    QJsonArray m_dnsProbes;
    int m_tlsIdx = 0;
    QJsonArray m_tlsProbes;
    qint64 m_tlsTcpMs = -1;
    int m_httpIdx = 0; // url*runs+run
    QJsonArray m_httpProbes;
    qint64 m_httpTtfbMs = -1;
    qint64 m_httpBytes = 0;
    int m_pingRound = 0;                          // серия ICMP: несколько раундов → loss/jitter
    QHash<QString, QVector<double>> m_icmpSamples; // target → удачные RTT по раундам
    QJsonArray m_pingProbes;
    int m_idleIdx = 0;
    QVector<double> m_idleRtt;   // [0] = прогрев (DNS+TCP+TLS) → уходит в conn_setup_ms, НЕ в медиану
    QVector<double> m_loadedRtt;
    qint64 m_downBytes = 0, m_downFirstByteMs = -1, m_downEndMs = -1;
    double m_upMbit = -1;        // -1 = не мерялось (lite/фейл) → в JSON null, НЕ ноль
};

} // namespace avpn
