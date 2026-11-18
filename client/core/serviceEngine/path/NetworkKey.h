// client/core/serviceEngine/path/NetworkKey.h
// AVPN path engine (design 2026-11-17, §3 "Network") - which network the device is on, in three values:
//  - local key: the key of the device's own memory (PathLedger.h). A fingerprint of the access point known at
//    the moment of the tap without any request: two Wi-Fi points of the same operator are two networks;
//  - coarse key: the key of shared statistics - the operator (autonomous system) and the medium; only this
//    one may ever leave the device;
//  - generation: grows at every change of the local key. Everything started under an older generation is
//    cancelled; its late answers change neither the ledger nor the current attempt (AttemptOwner.h compares
//    generations; the integration layer drops a ledger write whose generation is not the current one).
// [header-only, QtCore; pure]
//
// The platform layer supplies the observation (it is the only part that may ask the OS). The fingerprint of a
// Wi-Fi or wired network is what the platform can read without a permission prompt and without the tunnel:
// the gateway (address or MAC) and the subnet. The raw values never reach the key: it carries a short hash.
//
// Rules:
//  - Wi-Fi / wired: "wifi:<hash>" / "eth:<hash>" of gateway + subnet. No fingerprint at all -> "wifi:-": the
//    evidence then degrades to one slot per medium (today's "wifi" network memory), never to "no memory";
//  - cellular: "cell:<MCC-MNC>:<generation>" (design §3: operator and radio generation), "-" for an unknown part;
//  - offline: empty local key - nothing is read or written, an attempt cannot run;
//  - Unknown medium is NOT a network change: iOS reports it while any VPN is up (the "net" flip of the 17.11
//    journal, SELECTION-MAP §2.4), so it keeps the current key and generation;
//  - coarse key: "<medium>:asn:<N>" when the ASN is known (the Scanner's format), else "cellular:<MCC-MNC>"
//    for cellular, else empty. Learning the ASN later on the same local key is not a network change.
#pragma once

#include <QCryptographicHash>
#include <QString>

namespace avpn::path {

enum class NetMedium { Unknown, Offline, Wifi, Ethernet, Cellular, Other };

struct NetworkObservation {
    NetMedium medium = NetMedium::Unknown;
    QString gateway;  // gateway address or MAC, as the platform reads it
    QString subnet;   // e.g. "192.168.1.0/24"
    QString carrier;  // MCC-MNC
    QString radio;    // "lte", "5g", "3g", ...
    int asn = 0;      // 0 = unknown
};

struct NetworkKey {
    QString local;
    QString coarse;
    quint64 generation = 0;

    bool usable() const { return !local.isEmpty(); }
};

namespace detail {
inline QString shortHash(const QString &s)
{
    return QString::fromLatin1(QCryptographicHash::hash(s.toUtf8(), QCryptographicHash::Sha256).toHex().left(12));
}
inline QString orDash(const QString &s) { return s.trimmed().isEmpty() ? QStringLiteral("-") : s.trimmed(); }
} // namespace detail

inline QString localNetworkKey(const NetworkObservation &o)
{
    switch (o.medium) {
    case NetMedium::Wifi:
    case NetMedium::Ethernet: {
        const QString prefix = o.medium == NetMedium::Wifi ? QStringLiteral("wifi:") : QStringLiteral("eth:");
        const QString fp = o.gateway.trimmed().toLower() + QLatin1Char('|') + o.subnet.trimmed().toLower();
        return prefix + (fp == QLatin1String("|") ? QStringLiteral("-") : detail::shortHash(fp));
    }
    case NetMedium::Cellular:
        return QStringLiteral("cell:") + detail::orDash(o.carrier) + QLatin1Char(':') + detail::orDash(o.radio.toLower());
    case NetMedium::Other:
        return QStringLiteral("other");
    case NetMedium::Unknown:
    case NetMedium::Offline:
        break;
    }
    return {};
}

inline QString coarseNetworkKey(const NetworkObservation &o)
{
    QString medium;
    switch (o.medium) {
    case NetMedium::Wifi:
    case NetMedium::Ethernet: medium = QStringLiteral("wifi"); break;
    case NetMedium::Cellular: medium = QStringLiteral("cellular"); break;
    case NetMedium::Other: medium = QStringLiteral("other"); break;
    case NetMedium::Unknown:
    case NetMedium::Offline: return {};
    }
    if (o.asn > 0)
        return medium + QStringLiteral(":asn:") + QString::number(o.asn);
    if (o.medium == NetMedium::Cellular && !o.carrier.trimmed().isEmpty())
        return medium + QLatin1Char(':') + o.carrier.trimmed();
    return {};
}

// The one owner of the network generation. observe() is fed every observation of the platform; it returns
// true when the network changed (a new generation began).
class NetworkTracker {
public:
    bool observe(const NetworkObservation &o)
    {
        if (o.medium == NetMedium::Unknown)
            return false;
        const QString local = localNetworkKey(o);
        if (m_started && local == m_key.local) {
            const QString coarse = coarseNetworkKey(o);
            if (!coarse.isEmpty())
                m_key.coarse = coarse;
            return false;
        }
        m_started = true;
        m_key.local = local;
        m_key.coarse = coarseNetworkKey(o);
        ++m_key.generation;
        return true;
    }
    const NetworkKey &current() const { return m_key; }
    bool isCurrent(quint64 generation) const { return generation == m_key.generation; }

private:
    NetworkKey m_key;
    bool m_started = false;
};

} // namespace avpn::path
