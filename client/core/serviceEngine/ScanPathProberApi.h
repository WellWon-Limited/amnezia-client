// client/core/serviceEngine/ScanPathProberApi.h
// AVPN serviceEngine - the production server side of the race's prober (ScanPathProber.h IRaceScanApi) over the
// Scanner's own ScanApiClient: the stored signed manifest of the network revalidated with its ETag (304 + POST
// /v1/scan/token) or fetched, the probe base's IP literals (the engine's known addresses, else one bounded system
// lookup), one probe seat per provider probe through /v1/upstream/lease/probe-batch (include_config) and its release.
// Costs are the Scanner's worst cases (ScanTunables scan_cost_*), so a cut answer never overspends. Secrets (token,
// lease ids, configs) are never logged. [IN-FORK BUILD: QtNetwork]
//
// Upstream Amnezia has no counterpart.
#pragma once

#include "ScanApiClient.h"
#include "ScanPathProber.h"

namespace avpn {

class ScanApiRaceApi final : public IRaceScanApi
{
public:
    ScanApiRaceApi(ScanApiClient *api, IScanEngine *engine) : m_api(api), m_engine(engine) {}
    bool configured() const override { return m_api && m_api->configured(); }
    void session(const QString &networkKey, std::function<void(const RaceScanSession &)> done) override;
    void probeSeat(const QString &profileId, std::function<void(const Seat &)> done) override;
    void releaseSeats(const QStringList &leaseIds) override;

private:
    ScanApiClient *m_api = nullptr;
    IScanEngine *m_engine = nullptr;
};

} // namespace avpn
