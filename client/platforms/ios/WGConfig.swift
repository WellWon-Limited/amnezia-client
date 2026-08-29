import Foundation

private struct WGConfigValidationError: LocalizedError { // AVPN
  let key: String
  var errorDescription: String? { "Unsupported AWG boolean for \(key)" }
}

struct WGConfig: Decodable {
  let initPacketMagicHeader, responsePacketMagicHeader: String?
  let underloadPacketMagicHeader, transportPacketMagicHeader: String?
  let junkPacketCount, junkPacketMinSize, junkPacketMaxSize: String?
  let initPacketJunkSize, responsePacketJunkSize, cookieReplyPacketJunkSize, transportPacketJunkSize: String?
  let specialJunk1, specialJunk2, specialJunk3, specialJunk4, specialJunk5: String?
  let headerProtectionKey: String?
  let contentPaddingAddition, rekeyAfterTime, rekeyTimeout, rejectAfterTime, keepaliveTimeout, maxHandshakeAttempts: String?
  let randomTrailers, disableCookies: String? // AVPN: AWG 3.1
  let dns1: String
  let dns2: String
  let mtu: String
  let hostName: String
  let port: Int
  let clientIP: String
  let clientPrivateKey: String
  let serverPublicKey: String
  let presharedKey: String?
  var allowedIPs: [String]
  var persistentKeepAlive: String?
  let splitTunnelType: Int
  let splitTunnelSites: [String]
  let protectedTunnelIPs: [String]?
  let guardedCatalogV2: Bool?
  // AVPN split-DNS форвардер (dnsfwd.go): опциональные СТРОКИ (числа ломают JSONDecoder — грабля AWG-полей)
  let dnsFwdOn: String?
  let dnsFwdSuffixes: String?
  let dnsFwdServer: String?
  let dnsFwdWarmup: String?

  enum CodingKeys: String, CodingKey {
    case initPacketMagicHeader = "H1", responsePacketMagicHeader = "H2"
    case underloadPacketMagicHeader = "H3", transportPacketMagicHeader = "H4"
    case junkPacketCount = "Jc", junkPacketMinSize = "Jmin", junkPacketMaxSize = "Jmax"
    case initPacketJunkSize = "S1", responsePacketJunkSize = "S2", cookieReplyPacketJunkSize = "S3", transportPacketJunkSize = "S4"
    case specialJunk1 = "I1", specialJunk2 = "I2", specialJunk3 = "I3", specialJunk4 = "I4", specialJunk5 = "I5"
    case headerProtectionKey = "HeaderProtectionKey"
    case contentPaddingAddition = "ContentPaddingAddition"
    case rekeyAfterTime = "RekeyAfterTime", rekeyTimeout = "RekeyTimeout"
    case rejectAfterTime = "RejectAfterTime", keepaliveTimeout = "KeepaliveTimeout"
    case maxHandshakeAttempts = "MaxHandshakeAttempts"
    case randomTrailers = "RandomTrailers", disableCookies = "DisableCookies"
    case dns1
    case dns2
    case mtu
    case hostName
    case port
    case clientIP = "client_ip"
    case clientPrivateKey = "client_priv_key"
    case serverPublicKey = "server_pub_key"
    case presharedKey = "psk_key"
    case allowedIPs = "allowed_ips"
    case persistentKeepAlive = "persistent_keep_alive"
    case splitTunnelType
    case splitTunnelSites
    case protectedTunnelIPs
    case guardedCatalogV2
    case dnsFwdOn
    case dnsFwdSuffixes
    case dnsFwdServer
    case dnsFwdWarmup
  }

  // AVPN split-DNS: форвардер включён → система получает виртуальный резолвер (100.100.100.53),
  // реальная маршрутизация DNS — в Go-слое (wgSetSplitDns до wgTurnOn).
  var dnsFwdEnabled: Bool { dnsFwdOn == "1" }
  // Прогрев рукопожатия при подъёме туннеля — включён по умолчанию (нет ключа = вкл), бэк может
  // погасить, прислав "0" (kill-switch features.dns_fwd_warmup → cfg["dnsFwdWarmup"] в C++).
  var dnsFwdWarmupEnabled: Bool { dnsFwdWarmup != "0" }
  var effectiveDns: String { dnsFwdEnabled ? "100.100.100.53" : "\(dns1), \(dns2)" }

  // AVPN: the Apple adapter's quick-to-UAPI converter treats an unknown
  // boolean as false.  Validate first so a malformed required wire-format
  // option cannot silently downgrade the tunnel.
  func validateAwg31Booleans() throws {
    if let value = randomTrailers?.trimmingCharacters(in: .whitespacesAndNewlines),
       !value.isEmpty, normalizedAwgBool(value) == nil {
      throw WGConfigValidationError(key: "RandomTrailers")
    }
    if let value = disableCookies?.trimmingCharacters(in: .whitespacesAndNewlines),
       !value.isEmpty, normalizedAwgBool(value) == nil {
      throw WGConfigValidationError(key: "DisableCookies")
    }
  }

  var awg31UapiExpectations: [String: String] { // AVPN
    var result: [String: String] = [:]
    if let value = randomTrailers, let normalized = normalizedAwgBool(value) {
      result["random_trailers"] = normalized
    }
    if let value = disableCookies, let normalized = normalizedAwgBool(value) {
      result["disable_cookies"] = normalized
    }
    return result
  }

  private func normalizedAwgBool(_ value: String) -> String? {
    switch value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
    case "on", "1", "true", "t", "yes": return "1"
    case "off", "0", "false", "f", "no": return "0"
    default: return nil
    }
  }

  var settings: String {
    func trimmed(_ value: String?) -> String? {
      guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines),
            !value.isEmpty else {
        return nil
      }
      return value
    }

    guard
      let junkPacketCount = trimmed(junkPacketCount),
      let junkPacketMinSize = trimmed(junkPacketMinSize),
      let junkPacketMaxSize = trimmed(junkPacketMaxSize),
      let initPacketJunkSize = trimmed(initPacketJunkSize),
      let responsePacketJunkSize = trimmed(responsePacketJunkSize),
      let initPacketMagicHeader = trimmed(initPacketMagicHeader),
      let responsePacketMagicHeader = trimmed(responsePacketMagicHeader),
      let underloadPacketMagicHeader = trimmed(underloadPacketMagicHeader),
      let transportPacketMagicHeader = trimmed(transportPacketMagicHeader)
    else { return "" }

    var settingsLines: [String] = []

    // Required parameters when junkPacketCount is present
    settingsLines.append("Jc = \(junkPacketCount)")
    settingsLines.append("Jmin = \(junkPacketMinSize)")
    settingsLines.append("Jmax = \(junkPacketMaxSize)")
    settingsLines.append("S1 = \(initPacketJunkSize)")
    settingsLines.append("S2 = \(responsePacketJunkSize)")

    settingsLines.append("H1 = \(initPacketMagicHeader)")
    settingsLines.append("H2 = \(responsePacketMagicHeader)")
    settingsLines.append("H3 = \(underloadPacketMagicHeader)")
    settingsLines.append("H4 = \(transportPacketMagicHeader)")

    // Optional parameters - only add if not nil and not empty
    if let s3 = trimmed(cookieReplyPacketJunkSize) {
      settingsLines.append("S3 = \(s3)")
    }
    if let s4 = trimmed(transportPacketJunkSize) {
      settingsLines.append("S4 = \(s4)")
    }

    if let i1 = trimmed(specialJunk1) {
      settingsLines.append("I1 = \(i1)")
    }
    if let i2 = trimmed(specialJunk2) {
      settingsLines.append("I2 = \(i2)")
    }
    if let i3 = trimmed(specialJunk3) {
      settingsLines.append("I3 = \(i3)")
    }
    if let i4 = trimmed(specialJunk4) {
      settingsLines.append("I4 = \(i4)")
    }
    if let i5 = trimmed(specialJunk5) {
      settingsLines.append("I5 = \(i5)")
    }

    if let headerProtectionKey = trimmed(headerProtectionKey) {
      settingsLines.append("HeaderProtectionKey = \(headerProtectionKey)")
    }
    if let contentPaddingAddition = trimmed(contentPaddingAddition) {
      settingsLines.append("ContentPaddingAddition = \(contentPaddingAddition)")
    }
    if let rekeyAfterTime = trimmed(rekeyAfterTime) {
      settingsLines.append("RekeyAfterTime = \(rekeyAfterTime)")
    }
    if let rekeyTimeout = trimmed(rekeyTimeout) {
      settingsLines.append("RekeyTimeout = \(rekeyTimeout)")
    }
    if let rejectAfterTime = trimmed(rejectAfterTime) {
      settingsLines.append("RejectAfterTime = \(rejectAfterTime)")
    }
    if let keepaliveTimeout = trimmed(keepaliveTimeout) {
      settingsLines.append("KeepaliveTimeout = \(keepaliveTimeout)")
    }
    if let maxHandshakeAttempts = trimmed(maxHandshakeAttempts) {
      settingsLines.append("MaxHandshakeAttempts = \(maxHandshakeAttempts)")
    }
    if let randomTrailers = trimmed(randomTrailers),
       let normalized = normalizedAwgBool(randomTrailers) {
      settingsLines.append("RandomTrailers = \(normalized)")
    }
    if let disableCookies = trimmed(disableCookies),
       let normalized = normalizedAwgBool(disableCookies) {
      settingsLines.append("DisableCookies = \(normalized)")
    }

    return settingsLines.joined(separator: "\n")
  }

  var str: String {
    """
    [Interface]
    Address = \(clientIP)
    DNS = \(effectiveDns)
    MTU = \(mtu)
    PrivateKey = \(clientPrivateKey)
    \(settings)
    [Peer]
    PublicKey = \(serverPublicKey)
    \(presharedKey == nil ? "" : "PresharedKey = \(presharedKey!)")
    AllowedIPs = \(allowedIPs.joined(separator: ", "))
    Endpoint = \(hostName):\(port)
    \(persistentKeepAlive == nil ? "" : "PersistentKeepalive = \(persistentKeepAlive!)")
    """
  }
}

extension WGConfig {
  static func decodeNativeEnvelope(_ data: Data) throws -> WGConfig {
    guard data.count <= 2 * 1024 * 1024,
          let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw NSError(domain: "WGConfig", code: 1)
    }
    // Explicit legacy marker is produced by the trusted platform controller; catalog-v2 must
    // retain both its immutable discriminator and authority object in the encrypted handoff.
    let isV2 = try TribeNativeDispatchPolicy.validateEnvelope(root)
    if !isV2, root["client_priv_key"] != nil {
      return try JSONDecoder().decode(WGConfig.self, from: data)
    }

    let protocolName = root["protocol"] as? String ?? ""
    let dataKey = protocolName == "wireguard" ? "wireguard_config_data" : "awg_config_data"
    guard var native = root[dataKey] as? [String: Any] else {
      throw NSError(domain: "WGConfig", code: 5)
    }
    var transformed: [String: Any] = [:]
    transformed["guardedCatalogV2"] = true
    transformed["protectedTunnelIPs"] =
      (root["runtime_authority_v1"] as? [String: Any])?["protected_tunnel_ips"] ?? []
    for key in ["dns1", "dns2", "splitTunnelType", "splitTunnelSites",
                "dnsFwdOn", "dnsFwdSuffixes", "dnsFwdServer", "dnsFwdWarmup"] {
      if let value = root[key], !(value is NSNull) { transformed[key] = value }
    }
    for key in ["hostName", "port", "client_ip", "client_priv_key", "server_pub_key",
                "psk_key", "persistent_keep_alive"] {
      if let value = native[key], !(value is NSNull) { transformed[key] = value }
    }
    let mtuValue = native["mtu"] ?? "1280"
    transformed["mtu"] = mtuValue is String ? mtuValue : String(describing: mtuValue)
    if let allowed = native["allowed_ips"] as? [String] {
      transformed["allowed_ips"] = allowed
    } else if let allowed = native["allowed_ips"] as? String {
      transformed["allowed_ips"] = allowed.split(separator: ",").map {
        $0.trimmingCharacters(in: .whitespacesAndNewlines)
      }
    } else {
      transformed["allowed_ips"] = ["0.0.0.0/0", "::/0"]
    }
    let awgKeys = [
      "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
      "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5",
      "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
      "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts",
      "RandomTrailers", "DisableCookies",
    ]
    for key in awgKeys {
      guard let value = native.removeValue(forKey: key), !(value is NSNull) else { continue }
      transformed[key] = value is String ? value : String(describing: value)
    }
    let transformedData = try JSONSerialization.data(withJSONObject: transformed)
    return try JSONDecoder().decode(WGConfig.self, from: transformedData)
  }
}
