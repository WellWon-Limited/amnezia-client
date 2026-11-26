// client/core/serviceEngine/ScanPathProberApi.cpp - see ScanPathProberApi.h.
#include "ScanPathProberApi.h"

#include "ApiHostAddress.h" // publicUnicastOnly: review F4

#include <QCoreApplication>
#include <QDateTime>
#include <QHostAddress>
#include <QHostInfo>
#include <QTimer>
#include <QUrl>

#include <memory>

namespace avpn {

namespace {

QStringList ipLiterals(const QStringList &in)
{
    QStringList out;
    for (const QString &ip : in)
        if (scanIsIpLiteral(ip) && !out.contains(ip) && out.size() < kScanProbeBaseIpsMax)
            out << ip;
    return out;
}

} // namespace

void ScanApiRaceApi::session(const QString &networkKey, std::function<void(const RaceScanSession &)> done)
{
    const ScanTunables t;
    const qint64 cost = t.costManifestBytes + t.costApiBytes;
    IScanEngine *engine = m_engine;
    m_api->fetchManifest(networkKey, cost, QDateTime::currentMSecsSinceEpoch(),
                         [networkKey, engine, done](const ScanApiClient::Manifest &r) {
        RaceScanSession s;
        s.networkKey = networkKey;
        s.bytes = r.bytes;
        s.ok = r.ok && !r.scanToken.isEmpty() && !r.tunnelApiBase.isEmpty();
        s.reason = r.ok ? (s.ok ? QString() : QStringLiteral("manifest_incomplete")) : r.reason;
        if (!s.ok) {
            done(s);
            return;
        }
        s.token = r.scanToken;
        s.probeBase = r.tunnelApiBase;
        s.expiresAtMs = r.tokenExpiresAtMs;
        s.numbers = r.view.numbers;
        for (const ScanManifestNode &n : r.view.nodes)
            if (n.awgProbe)
                s.awgNodes.insert(n.nodeId, n.awgEchoTarget.isEmpty() ? r.view.awgEchoTarget : n.awgEchoTarget);
        const QString host = QUrl(s.probeBase).host();
        s.baseIps = scanIsIpLiteral(host) ? QStringList{host} : ipLiterals(engine ? engine->knownHostIps(host) : QStringList());
        if (!s.baseIps.isEmpty() || host.isEmpty()) {
            done(s);
            return;
        }
        // One bounded system lookup (the Scanner's scan_stage1_timeout_ms): the AmneziaWG session dials the API by IP.
        auto answered = std::make_shared<bool>(false);
        QTimer::singleShot(ScanTunables().stage1TimeoutMs, QCoreApplication::instance(), [answered, s, done]() {
            if (!*answered) {
                *answered = true;
                done(s); // no IP: own Xray and providers are still probed, AmneziaWG is not
            }
        });
        QHostInfo::lookupHost(host, QCoreApplication::instance(), [answered, s, done](const QHostInfo &info) mutable {
            if (*answered)
                return;
            *answered = true;
            QStringList ips;
            for (const QHostAddress &a : info.addresses())
                ips << a.toString();
            s.baseIps = ipLiterals(publicUnicastOnly(ips)); // review F4: a FakeDNS answer is no API address
            done(s);
        });
    });
}

namespace {
// The race's seat owner over the Scanner's batch owner (the release lives there).
struct ScanApiRaceSeat final : IRaceSeat {
    std::unique_ptr<ScanSeatBatch> batch;
    void retire(std::function<void()> idle) override
    {
        if (batch)
            batch->retire(std::move(idle));
        else if (idle)
            idle();
    }
};
} // namespace

std::shared_ptr<IRaceSeat> ScanApiRaceApi::probeSeat(const QString &profileId, qint64 costBytes, qint64 releaseAllowance, std::function<void(const Seat &)> done,
                                                     std::function<void(qint64)> releaseBytes)
{
    auto seat = std::make_shared<ScanApiRaceSeat>();
    seat->batch = m_api->probeBatch({profileId}, true, costBytes, releaseAllowance, [done](const ScanApiClient::Batch &b) {
        Seat s;
        s.bytes = b.bytes;
        if (!b.ok || b.items.isEmpty()) {
            s.code = b.failCode.isEmpty() ? QStringLiteral("lease_failed") : b.failCode;
            done(s);
            return;
        }
        const ScanApiClient::BatchItem &i = b.items.first();
        s.ok = i.granted;
        s.leaseId = i.leaseId;
        s.config = i.config;
        s.configSha256 = i.configSha256;
        s.code = i.code;
        done(s);
    }, std::move(releaseBytes));
    return seat;
}

} // namespace avpn
