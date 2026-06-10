// AVPN serviceEngine — переключение на нового кандидата через in-place peer swap. [СКАФФОЛД]
// TODO(C-5): при DEAD/деградации → ITunnelControl::applyPeer(новая нода) с её awg-параметрами,
// без пересоздания tun (стабильный /32). UI: «переключаюсь…» (near-seamless, не invisible).
#pragma once

#include "ITunnelControl.h"

namespace avpn {

class Switcher {
public:
    explicit Switcher(ITunnelControl *tunnel) : m_tunnel(tunnel) {}

    TunnelResult switchTo(const Subscription &sub, const SubscriptionNode &node)
    {
        if (!m_tunnel)
            return TunnelResult::fail(QStringLiteral("no tunnel control"));
        return m_tunnel->applyPeer(sub, node); // TODO(C-5): дренаж старого/телеметрия причины
    }

private:
    ITunnelControl *m_tunnel = nullptr;
};

} // namespace avpn
