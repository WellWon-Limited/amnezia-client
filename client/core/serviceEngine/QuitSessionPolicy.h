#pragma once
// AVPN (macOS quit, BUG-6; round mac-B review M2, 25.11.2026): what the app's quit does with the VPN session it controls.
// The daemon keeps an AmneziaWG session after the app is gone and the next launch adopts it (CONNECT-INVARIANTS §19) -
// but only a session that is UP (the handshake done: VpnConnection Connected) may be handed over. An attempt still in
// progress (Connecting: the interface, routes, DNS and the kill switch are set, no handshake yet; Reconnecting) has no
// one to finish it once the app is gone: the daemon only keeps polling for a handshake and the Mac's traffic stays
// routed into a dead tunnel until the next launch. It is ended like a stop (deactivate: routes, DNS, PF restored). A
// session the daemon does not hold by itself (own Xray: tun2socks is this process's child in the service) always ends.
// [header-only, pure]
namespace avpn {

enum class QuitSessionAction {
    Nothing,          // no protocol (nothing started here, or an adopted session: the daemon keeps it as it is)
    ReleaseToDaemon,  // WireguardProtocol::releaseSessionToDaemon - no deactivate
    EndSession        // VpnConnection::disconnectFromVpn - the stop path
};

inline QuitSessionAction quitSessionAction(bool hasProtocol, bool daemonHeldSession, bool sessionUp)
{
    if (!hasProtocol)
        return QuitSessionAction::Nothing;
    if (daemonHeldSession && sessionUp)
        return QuitSessionAction::ReleaseToDaemon;
    return QuitSessionAction::EndSession;
}

} // namespace avpn
