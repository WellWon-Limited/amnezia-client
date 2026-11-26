// AVPN «Доступ к сайтам РФ» (owner 26.11.2026, AND-67): the RU split list cut to the platform's route budget
// (RouteBudget.h). [header-only, QtCore + QtNetwork QHostAddress; pure]
//
// Rules (the direction is a SUBSET of the input, never more):
//   1. budget unlimited (< 0) or the list already fits -> the input unchanged (identity, not even re-written);
//   2. a lossless merge: duplicates and prefixes inside another one dropped, two sibling halves joined into their parent -
//      exactly the same addresses, nothing added, nothing lost;
//   3. still over the budget -> a cut: the entries overlapping the ordered `priority` prefixes first (in that order; an
//      empty list today - the hook for a server-published priority list), then IPv4 before IPv6, each family largest
//      first (by address count = the shorter prefix), ties: the lower address; the rest is dropped. A prefix is never
//      widened. Why IPv4 first: RU traffic is mostly IPv4, and the RU IPv6 list is ~1,300 /29 allocations that would
//      take the first slots by any cross-family share (a /29 holds 1/1300 of the RU v6 space, more than a v4 /19 holds
//      of the v4 space) - measured on the compiled list: at N=1000 the share rule kept 41.7 % of the RU IPv4 space, IPv4
//      first keeps 72.1 %. A left-out IPv6 RU network goes through the VPN, as with the mode off.
// The result is ordered by family and address (stable for the seed's stamp). An entry that does not parse is kept as
// it is (it cannot be merged or ranked) and counted.
// Tests: tests/route_budget_check.cpp (build_route_budget.sh); the table of RU coverage per budget: its --table mode.
#pragma once

#include <QHostAddress>
#include <QPair>
#include <QString>
#include <QStringList>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <vector>

namespace avpn {

struct RoutePrefix
{
    bool v6 = false;
    quint64 hi = 0; // v4: 0
    quint64 lo = 0; // v4: the address in the low 32 bits
    int len = 0;

    int width() const { return v6 ? 128 : 32; }
};

namespace routes_detail {

// the low `n` bits set (n in 0..128) of a 128-bit value as hi/lo
inline void lowMask(int n, quint64 &hi, quint64 &lo)
{
    if (n <= 0) {
        hi = lo = 0;
    } else if (n < 64) {
        hi = 0;
        lo = (quint64(1) << n) - 1;
    } else if (n == 64) {
        hi = 0;
        lo = ~quint64(0);
    } else if (n < 128) {
        hi = (quint64(1) << (n - 64)) - 1;
        lo = ~quint64(0);
    } else {
        hi = lo = ~quint64(0);
    }
}

inline void normalize(RoutePrefix &p)
{
    quint64 mh, ml;
    lowMask(p.width() - p.len, mh, ml); // host bits
    p.hi &= ~mh;
    p.lo &= ~ml;
}

inline bool lessAddr(const RoutePrefix &a, const RoutePrefix &b)
{
    if (a.v6 != b.v6)
        return !a.v6;
    if (a.hi != b.hi)
        return a.hi < b.hi;
    if (a.lo != b.lo)
        return a.lo < b.lo;
    return a.len < b.len; // the larger prefix first at one address
}

// b inside a (same family)
inline bool contains(const RoutePrefix &a, const RoutePrefix &b)
{
    if (a.v6 != b.v6 || b.len < a.len)
        return false;
    quint64 mh, ml;
    lowMask(a.width() - a.len, mh, ml);
    return (b.hi & ~mh) == a.hi && (b.lo & ~ml) == a.lo;
}

inline bool overlaps(const RoutePrefix &a, const RoutePrefix &b)
{
    return contains(a, b) || contains(b, a);
}

// a and b are the two halves of one parent (a the lower)
inline bool siblings(const RoutePrefix &a, const RoutePrefix &b)
{
    if (a.v6 != b.v6 || a.len != b.len || a.len == 0)
        return false;
    const int bit = a.width() - a.len; // the bit that tells the halves apart
    quint64 bh = 0, bl = 0;
    if (bit < 64)
        bl = quint64(1) << bit;
    else
        bh = quint64(1) << (bit - 64);
    if ((a.hi & bh) || (a.lo & bl))
        return false;
    return b.hi == (a.hi | bh) && b.lo == (a.lo | bl);
}

// rule 3's order: IPv4 first, then the larger prefix, then the lower address
inline bool rankedBefore(const RoutePrefix &a, const RoutePrefix &b)
{
    if (a.v6 != b.v6)
        return !a.v6;
    if (a.len != b.len)
        return a.len < b.len;
    return lessAddr(a, b);
}

} // namespace routes_detail

inline bool parseRoutePrefix(const QString &text, RoutePrefix &out)
{
    const QString t = text.trimmed();
    QHostAddress addr;
    int len = -1;
    if (t.contains(QLatin1Char('/'))) {
        const QPair<QHostAddress, int> s = QHostAddress::parseSubnet(t);
        addr = s.first;
        len = s.second;
    } else if (addr.setAddress(t)) {
        len = addr.protocol() == QAbstractSocket::IPv6Protocol ? 128 : 32;
    }
    if (addr.isNull() || len < 0)
        return false;
    RoutePrefix p;
    if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
        if (len > 32)
            return false;
        p.v6 = false;
        p.lo = addr.toIPv4Address();
    } else if (addr.protocol() == QAbstractSocket::IPv6Protocol) {
        if (len > 128)
            return false;
        const Q_IPV6ADDR a = addr.toIPv6Address();
        p.v6 = true;
        for (int i = 0; i < 8; ++i)
            p.hi = (p.hi << 8) | a[i];
        for (int i = 8; i < 16; ++i)
            p.lo = (p.lo << 8) | a[i];
    } else {
        return false;
    }
    p.len = len;
    routes_detail::normalize(p);
    out = p;
    return true;
}

inline QString formatRoutePrefix(const RoutePrefix &p)
{
    if (!p.v6)
        return QHostAddress(quint32(p.lo)).toString() + QLatin1Char('/') + QString::number(p.len);
    Q_IPV6ADDR a;
    for (int i = 0; i < 8; ++i)
        a[i] = quint8(p.hi >> (8 * (7 - i)));
    for (int i = 0; i < 8; ++i)
        a[8 + i] = quint8(p.lo >> (8 * (7 - i)));
    return QHostAddress(a).toString() + QLatin1Char('/') + QString::number(p.len);
}

// The lossless merge (rule 2). Unparseable entries are returned in `unparsed`.
inline std::vector<RoutePrefix> mergeRoutePrefixes(const QStringList &routes, QStringList *unparsed = nullptr)
{
    using namespace routes_detail;
    std::vector<RoutePrefix> in;
    in.reserve(size_t(routes.size()));
    for (const QString &r : routes) {
        RoutePrefix p;
        if (parseRoutePrefix(r, p))
            in.push_back(p);
        else if (unparsed)
            unparsed->append(r);
    }
    std::sort(in.begin(), in.end(), lessAddr);
    std::vector<RoutePrefix> out;
    out.reserve(in.size());
    for (const RoutePrefix &p : in) {
        if (!out.empty() && contains(out.back(), p))
            continue; // a duplicate or inside the previous one (sorted: nesting or disjoint)
        out.push_back(p);
        while (out.size() >= 2 && siblings(out[out.size() - 2], out.back())) {
            RoutePrefix parent = out[out.size() - 2];
            parent.len -= 1;
            out.pop_back();
            out.back() = parent;
        }
    }
    return out;
}

struct RouteReduction
{
    QStringList routes;  // what the system gets
    int total = 0;       // entries given
    int merged = 0;      // after the lossless merge (= total when the merge was not needed)
    bool changed = false;
};

inline RouteReduction reduceRoutes(const QStringList &routes, int budget, const QStringList &priority = {})
{
    using namespace routes_detail;
    RouteReduction r;
    r.total = int(routes.size());
    if (budget < 0 || r.total <= budget) { // rule 1
        r.routes = routes;
        r.merged = r.total;
        return r;
    }
    QStringList unparsed;
    std::vector<RoutePrefix> merged = mergeRoutePrefixes(routes, &unparsed);
    r.merged = int(merged.size()) + int(unparsed.size());
    r.changed = true;
    std::vector<RoutePrefix> kept;
    if (r.merged <= budget) { // rule 2 was enough
        kept = merged;
    } else { // rule 3
        auto larger = [](const RoutePrefix &a, const RoutePrefix &b) { return rankedBefore(a, b); };
        std::vector<bool> taken(merged.size(), false);
        std::vector<RoutePrefix> order;
        order.reserve(merged.size());
        for (const QString &pr : priority) {
            RoutePrefix want;
            if (!parseRoutePrefix(pr, want))
                continue;
            std::vector<size_t> hit;
            for (size_t i = 0; i < merged.size(); ++i)
                if (!taken[i] && overlaps(merged[i], want))
                    hit.push_back(i);
            std::sort(hit.begin(), hit.end(), [&](size_t a, size_t b) { return larger(merged[a], merged[b]); });
            for (size_t i : hit) {
                taken[i] = true;
                order.push_back(merged[i]);
            }
        }
        std::vector<RoutePrefix> rest;
        for (size_t i = 0; i < merged.size(); ++i)
            if (!taken[i])
                rest.push_back(merged[i]);
        std::sort(rest.begin(), rest.end(), larger);
        order.insert(order.end(), rest.begin(), rest.end());
        const int room = std::max(0, budget - int(unparsed.size()));
        if (int(order.size()) > room)
            order.resize(size_t(room));
        kept = order;
        std::sort(kept.begin(), kept.end(), lessAddr);
    }
    r.routes = unparsed.mid(0, std::max(0, budget));
    for (const RoutePrefix &p : kept)
        r.routes.append(formatRoutePrefix(p));
    return r;
}

// The addresses a list covers, per family (overlaps counted once) - the coverage of a cut.
struct RouteCoverage
{
    double v4 = 0;
    double v6 = 0;
};

inline RouteCoverage routeCoverage(const QStringList &routes)
{
    RouteCoverage c;
    for (const RoutePrefix &p : mergeRoutePrefixes(routes))
        (p.v6 ? c.v6 : c.v4) += std::ldexp(1.0, p.width() - p.len);
    return c;
}

// `cidr` lies inside one of `cover` (the seed's fixed groups: never cut).
inline bool routeInsideAny(const QString &cidr, const QList<RoutePrefix> &cover)
{
    RoutePrefix p;
    if (!parseRoutePrefix(cidr, p))
        return false;
    for (const RoutePrefix &c : cover)
        if (routes_detail::contains(c, p))
            return true;
    return false;
}

} // namespace avpn
