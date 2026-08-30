package org.amnezia.vpn

/**
 * Single Android VPN session owner for both embedded AWG and Xray engines.
 * The outer VpnService/TUN is process-owned; protocol engines receive only a
 * duplicated descriptor and cannot tear down the routing guard.
 */
class TribeVpnService : AmneziaVpnService()
