// client/core/serviceEngine/ApiHostAddress.h
// AVPN serviceEngine - which resolved addresses of OUR API hosts the app may keep and dial. [header-only, QtNetwork; pure]
//
// Device round air-I review F4 (25.11): an address of our API edge is a public unicast address. Every user of the app's
// API address list dials it outside the session's core - the Scanner's direct access check and its AmneziaWG mini
// session (probe.base_ips), the RU-split carve-out, on macOS the kill-switch hold's pass list - so an address that is
// not publicly routable is never useful to any of them, whatever produced it: a provider's FakeDNS pool (Xray's default
// 198.18.0.0/15, our normalizer's 100.88.0.0/16 inside 100.64.0.0/10, Xray's IPv6 pool fc00::/18, a provider's own
// choice in private space), a captive portal, a DNS mask. Before, AvpnEngineQml::resolveApiCarveHosts kept every answer
// for the process lifetime: an app opened inside a provider session recorded the FakeDNS address first, and the Scanner
// dialled it (TribeScanner probeIp = base_ips.first()).
// Only DNS answers are filtered; an IP literal in our own configuration (a dev backend) is kept as configured.
#pragma once

#include <QHash>
#include <QHostAddress>
#include <QList>
#include <QString>
#include <QStringList>
#include <QtGlobal>

namespace avpn {

// IPv4: not 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24, 192.168/16, 198.18/15,
// 198.51.100/24, 203.0.113/24, 224/4, 240/4 (255.255.255.255 included). IPv6: only 2000::/3 without 2001:db8::/32 - so
// ::, ::1, fc00::/7 (Xray's fakedns fc00::/18 too), fe80::/10, ff00::/8 are out; an IPv4-mapped address is judged as
// its IPv4 address.
inline bool isPublicUnicastAddress(const QHostAddress &address)
{
    bool v4 = false;
    const quint32 a = address.toIPv4Address(&v4); // also an IPv4-mapped IPv6 address
    if (v4) {
        struct Net { quint32 base; int bits; };
        static constexpr Net kNotPublic[] = {
            {0x00000000u, 8},  {0x0A000000u, 8},  {0x64400000u, 10}, {0x7F000000u, 8},  {0xA9FE0000u, 16},
            {0xAC100000u, 12}, {0xC0000000u, 24}, {0xC0000200u, 24}, {0xC0A80000u, 16}, {0xC6120000u, 15},
            {0xC6336400u, 24}, {0xCB007100u, 24}, {0xE0000000u, 4},  {0xF0000000u, 4},
        };
        for (const Net &n : kNotPublic)
            if ((a >> (32 - n.bits)) == (n.base >> (32 - n.bits)))
                return false;
        return true;
    }
    if (address.protocol() != QAbstractSocket::IPv6Protocol)
        return false;
    const Q_IPV6ADDR b = address.toIPv6Address();
    if ((b[0] & 0xE0) != 0x20)
        return false; // outside 2000::/3
    return !(b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8); // 2001:db8::/32, documentation
}

// The public unicast IP literals of `in`, in order (anything else - a name, a private or reserved address - dropped).
inline QStringList publicUnicastOnly(const QStringList &in)
{
    QStringList out;
    for (const QString &s : in) {
        const QHostAddress a(s.trimmed());
        if (!a.isNull() && isPublicUnicastAddress(a))
            out << s.trimmed();
    }
    return out;
}

// The one recording rule of the app's API address list (AvpnEngineQml::resolveApiCarveHosts): the public unicast
// answers of one lookup go into the list of every host (`all`) and that host's list (`mine`), in answer order, without
// duplicates; the rest is not recorded. Returns how many answers were left out.
inline int recordApiHostAnswers(QList<QHostAddress> &all, QStringList &mine, const QList<QHostAddress> &answers)
{
    int dropped = 0;
    for (const QHostAddress &ip : answers) {
        if (!isPublicUnicastAddress(ip)) {
            ++dropped;
            continue;
        }
        if (!all.contains(ip))
            all.append(ip);
        if (!mine.contains(ip.toString()))
            mine << ip.toString();
    }
    return dropped;
}

} // namespace avpn
