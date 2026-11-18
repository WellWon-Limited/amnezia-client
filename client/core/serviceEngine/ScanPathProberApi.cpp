// client/core/serviceEngine/ScanPathProberApi.cpp - see ScanPathProberApi.h.
#include "ScanPathProberApi.h"

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
            s.baseIps = ipLiterals(ips);
            done(s);
        });
    });
}

void ScanApiRaceApi::probeSeat(const QString &profileId, std::function<void(const Seat &)> done)
{
    const ScanTunables t;
    m_api->probeBatch({profileId}, true, t.costBatchBytes + t.costConfigBytes, [done](const ScanApiClient::Batch &b) {
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
    });
}

void ScanApiRaceApi::releaseSeats(const QStringList &leaseIds)
{
    if (leaseIds.isEmpty())
        return;
    m_api->releaseLeases(leaseIds, ScanTunables().costApiBytes, [](qint64) {});
}

} // namespace avpn
