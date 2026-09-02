// AVPN serviceEngine — построитель конфига Xray (волна awg31-xray-v1, спека 2026-09-01 §2.3):
// наш DTO подписки (SubscriptionNode.xray) → QJsonObject в форме, которую ест апстримный путь
// VpnConnection::connectToVpn → XrayProtocol (десктоп/демон Xray::startXray) / IosController::setupXray
// (NE PacketTunnelProvider+Xray.swift) / Android Xray.kt: корень protocol="xray" + xray_config_data
// {config = СТРОКА JSON xray-core} + hostName/dns1/dns2/splitTunnelType — те же корневые ключи, что у
// AwgConfigBuilder (split-tunnel/dnsFwd-ключи докладывает адаптер VpnConnectionTunnelControl).
// Схема JSON xray-core — зеркало client/core/configurators/xrayConfigurator.cpp
// buildClientProtocolConfig: outbound vless с vnext[]{address, port, users[{id, encryption none,
// flow}]}, streamSettings{network tcp, security reality, realitySettings{publicKey, shortId,
// serverName, fingerprint, spiderX ""}}, inbound socks 127.0.0.1:10808 udp (логин в inbound
// доинжектит EnsureInboundAuth апстрима на каждой платформе — мы его НЕ кладём).
// Overlay-код: НЕ часть апстрима Amnezia. Автономный тест: tests/build_xray_config.sh.
#pragma once

#include "AwgConfigBuilder.h" // ClientKeys, host()/port()
#include "dto/Subscription.h"

#include <QJsonObject>
#include <QString>

namespace avpn {

class XrayConfigBuilder {
public:
    // Полный QJsonObject для connectToVpn (protocol=xray). Нода без node.xray → ПУСТОЙ объект
    // (вызывающий обязан проверить isEmpty(): xray-нода без параметров непригодна для коннекта).
    // keys не используются (VLESS-credential = uuid из подписки), параметр — для симметрии с
    // AwgConfigBuilder::build в диспетчере.
    static QJsonObject build(const Subscription &sub, const SubscriptionNode &node, const ClientKeys &keys);

    // Внутренний xray_config_data: {config: <JSON xray-core строкой>, hostName, port}.
    static QJsonObject buildInner(const Subscription &sub, const SubscriptionNode &node, const ClientKeys &keys);

    // JSON xray-core (объект) / та же строка Compact — то, что уходит в libxray.
    // Бюджеты ядра (server-driven, клампы внутри): рукопожатие и простой соединения.
    static int handshakeSeconds();
    static int connIdleSeconds();

    static QJsonObject coreConfig(const SubscriptionNode &node);
    static QString coreConfigText(const SubscriptionNode &node);

    // AVPN bench: санитизированный дамп для отчёта бенча (tunnel.config) — БЕЗ uuid, publicKey,
    // endpoint-хоста и client_ip (отчёт пересылается наружу). Только факты транспорта:
    // proto/port/dns/network/security/flow/fingerprint/server_name/short_id_len/host_id/transport_rank.
    static QJsonObject reportSummary(const Subscription &sub, const SubscriptionNode &node);
};

} // namespace avpn
