/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// AVPN (awg audit 25.11.2026, round mac-D): what an in-place server switch of the desktop daemon cannot change.
//
// Daemon::switchServer re-sends only the peer (WireguardUtils::updatePeer: public key, PSK, endpoint, allowed IPs,
// keepalive), the peer's routes and the resolvers. Everything else is applied once, when the interface is created:
//   - WireguardUtils::addInterface (macOS, Linux: the UAPI "set" of the interface; Windows: the [Interface] section of
//     toWgConf): the AmneziaWG obfuscation jc/jmin/jmax, s1-s4, h1-h4, the special junk i1-i5 (m_specialJunk), the
//     3.x settings (header protection key, content padding, rekey/reject/keepalive timers, handshake attempts, random
//     trailers, cookies), the DNS servers (Windows);
//   - the kill switch session that addInterface opens (macOS, Linux: blockAll or blockNets by the allowed ranges,
//     allowNets = the excluded addresses - the first one is the server's host - and the DNS servers; Windows: the
//     interface filter);
//   - Daemon::activate's bring-up: the MTU (IPUtils::setMTUAndUp).
// The daemon's own condition (same private key, device addresses and gateways) is always true in Tribe (one device
// key, one /32 per user on every node, one gateway), so a switch to a node with other obfuscation kept the old node's
// settings: "connected" with no handshake. An in-place switch is honest only when all of the above is equal;
// otherwise the daemon takes deactivate + activate.
//
// Shared by every desktop daemon (macOS, Linux, Windows): Qt containers and InterfaceConfig fields only.

#ifndef SERVERSWITCHPOLICY_H
#define SERVERSWITCHPOLICY_H

#include <QString>
#include <QStringList>

#include "interfaceconfig.h"

namespace avpn {

// The names of the interface-level settings in which `next` differs from the live interface's `live` config; empty =
// an in-place switch leaves nothing stale. Names only, never values (keys, headers).
inline QStringList interfaceSettingsThatDiffer(const InterfaceConfig& live, const InterfaceConfig& next) {
  QStringList names;
  const auto note = [&names](bool same, const char* name) {
    if (!same) {
      names << QString::fromLatin1(name);
    }
  };
  note(live.m_junkPacketCount == next.m_junkPacketCount, "jc");
  note(live.m_junkPacketMinSize == next.m_junkPacketMinSize, "jmin");
  note(live.m_junkPacketMaxSize == next.m_junkPacketMaxSize, "jmax");
  note(live.m_initPacketJunkSize == next.m_initPacketJunkSize, "s1");
  note(live.m_responsePacketJunkSize == next.m_responsePacketJunkSize, "s2");
  note(live.m_cookieReplyPacketJunkSize == next.m_cookieReplyPacketJunkSize, "s3");
  note(live.m_transportPacketJunkSize == next.m_transportPacketJunkSize, "s4");
  note(live.m_initPacketMagicHeader == next.m_initPacketMagicHeader, "h1");
  note(live.m_responsePacketMagicHeader == next.m_responsePacketMagicHeader, "h2");
  note(live.m_underloadPacketMagicHeader == next.m_underloadPacketMagicHeader, "h3");
  note(live.m_transportPacketMagicHeader == next.m_transportPacketMagicHeader, "h4");
  note(live.m_specialJunk == next.m_specialJunk, "special_junk");
  note(live.m_headerProtectionKey == next.m_headerProtectionKey, "header_protection_key");
  note(live.m_contentPaddingAddition == next.m_contentPaddingAddition, "content_padding_addition");
  note(live.m_rekeyAfterTime == next.m_rekeyAfterTime, "rekey_after_time");
  note(live.m_rekeyTimeout == next.m_rekeyTimeout, "rekey_timeout");
  note(live.m_rejectAfterTime == next.m_rejectAfterTime, "reject_after_time");
  note(live.m_keepaliveTimeout == next.m_keepaliveTimeout, "keepalive_timeout");
  note(live.m_maxHandshakeAttempts == next.m_maxHandshakeAttempts, "max_handshake_attempts");
  note(live.m_randomTrailers == next.m_randomTrailers, "random_trailers");
  note(live.m_disableCookies == next.m_disableCookies, "disable_cookies");
  note(live.m_deviceMTU == next.m_deviceMTU, "mtu");
  note(live.m_primaryDnsServer == next.m_primaryDnsServer, "primary_dns");
  note(live.m_secondaryDnsServer == next.m_secondaryDnsServer, "secondary_dns");
  note(live.m_killSwitchEnabled == next.m_killSwitchEnabled, "kill_switch");
  // The kill switch session's own inputs, only while it is on (addInterface opens it only then).
  if (live.m_killSwitchEnabled || next.m_killSwitchEnabled) {
    note(live.m_allowedIPAddressRanges == next.m_allowedIPAddressRanges, "kill_switch_allowed_ips");
    note(live.m_excludedAddresses == next.m_excludedAddresses, "kill_switch_excluded_addresses");
  }
  return names;
}

}  // namespace avpn

#endif  // SERVERSWITCHPOLICY_H
