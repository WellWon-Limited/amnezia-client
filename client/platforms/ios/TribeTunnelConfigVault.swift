import CryptoKit
import Darwin
import Foundation
import Security

/// One-shot encrypted handoff shared by the Tribe app and its Network Extension.
/// The persistent NETunnelProviderProtocol stores only an opaque UUID reference.
@objcMembers
public final class TribeTunnelConfigVault: NSObject {
    private static let schema = 1
    private static let maximumConfigBytes = 2 * 1024 * 1024
    private static let maximumRecordBytes = maximumConfigBytes + 32 * 1024
    private static let appGroup = "group.hk.wellwon.tribe"
    private static let keychainAccessGroup = "Q7DVH5MCWF.hk.wellwon.tribe"
    private static let keychainService = "hk.wellwon.tribe.tunnel-config-vault"
    private static let keychainAccount = "aes-gcm-v1"
    private static let magic = Data("TRIBE-TUNNEL-V1".utf8)

    @objc(stageConfig:protocolName:sessionId:)
    public static func stageConfig(_ config: Data, protocolName: String, sessionId: String) -> String? {
        do {
            return try stage(config, protocolName: protocolName, sessionId: sessionId)
        } catch {
            return nil
        }
    }

    @objc(discardReference:)
    public static func discardReference(_ reference: String) {
        discard(reference: reference)
    }

    static func consumeConfig(reference: String, protocolName: String, sessionId: String) throws -> Data {
        let id = try canonicalReference(reference)
        let canonicalSessionId = try canonicalReference(sessionId)
        try validateProtocol(protocolName)
        let source = try recordURL(id: id)
        let claim = try claimURL(id: id)
        guard rename(source.path, claim.path) == 0 else { throw VaultError.invalidRecord }
        defer { try? FileManager.default.removeItem(at: claim) }
        let record = try readOwnedRecord(claim)
        let envelope = try JSONDecoder().decode(Envelope.self, from: record)
        let nowMillis = Int64(Date().timeIntervalSince1970 * 1000)
        guard envelope.schemaVersion == schema,
              envelope.reference == id,
              envelope.protocolName == protocolName,
              envelope.sessionId == canonicalSessionId,
              envelope.createdAtMillis > nowMillis - 10 * 60 * 1000,
              envelope.createdAtMillis <= nowMillis + 5 * 60 * 1000,
              let sealedData = Data(base64Encoded: envelope.sealedCombined),
              sealedData.count <= maximumRecordBytes else {
            throw VaultError.invalidRecord
        }
        let box = try AES.GCM.SealedBox(combined: sealedData)
        let plaintext = try AES.GCM.open(
            box,
            using: try key(),
            authenticating: aad(reference: id, protocolName: protocolName,
                                sessionId: canonicalSessionId)
        )
        guard !plaintext.isEmpty, plaintext.count <= maximumConfigBytes else {
            throw VaultError.invalidRecord
        }
        return plaintext
    }

    static func discard(reference: String) {
        guard let id = try? canonicalReference(reference),
              let url = try? recordURL(id: id) else { return }
        try? FileManager.default.removeItem(at: url)
    }

    private static func stage(_ config: Data, protocolName: String, sessionId: String) throws -> String {
        guard !config.isEmpty, config.count <= maximumConfigBytes else {
            throw VaultError.configSize
        }
        try validateProtocol(protocolName)
        let canonicalSessionId = try canonicalReference(sessionId)
        let id = UUID().uuidString.lowercased()
        let sealed = try AES.GCM.seal(
            config,
            using: try key(),
            authenticating: aad(reference: id, protocolName: protocolName,
                                sessionId: canonicalSessionId)
        )
        guard let combined = sealed.combined else { throw VaultError.encryption }
        let envelope = Envelope(
            schemaVersion: schema,
            reference: id,
            protocolName: protocolName,
            sessionId: canonicalSessionId,
            createdAtMillis: Int64(Date().timeIntervalSince1970 * 1000),
            sealedCombined: combined.base64EncodedString()
        )
        let record = try JSONEncoder().encode(envelope)
        guard record.count <= maximumRecordBytes else { throw VaultError.configSize }
        let directory = try vaultDirectory()
        let destination = try recordURL(id: id)
        let temporary = directory.appendingPathComponent(".\(id).\(UUID().uuidString).tmp")
        do {
            try record.write(to: temporary, options: [.atomic])
            try FileManager.default.setAttributes([
                .posixPermissions: 0o600,
                .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
            ], ofItemAtPath: temporary.path)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            var mutableTemporary = temporary
            try mutableTemporary.setResourceValues(values)
            let fileHandle = try FileHandle(forWritingTo: temporary)
            try fileHandle.synchronize()
            try fileHandle.close()
            if FileManager.default.fileExists(atPath: destination.path) {
                throw VaultError.invalidRecord
            }
            try FileManager.default.moveItem(at: temporary, to: destination)
            try synchronizeDirectory(directory)
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            try? FileManager.default.removeItem(at: destination)
            throw error
        }
        cleanupOrphans(excluding: destination)
        return id
    }

    private static func key() throws -> SymmetricKey {
        let baseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecAttrAccessGroup as String: keychainAccessGroup,
        ]
        var readQuery = baseQuery
        readQuery[kSecReturnData as String] = true
        readQuery[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(readQuery as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data, data.count == 32 {
            return SymmetricKey(data: data)
        }
        guard status == errSecItemNotFound else { throw VaultError.keychain(status) }
        var bytes = Data(count: 32)
        let randomStatus = bytes.withUnsafeMutableBytes { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, buffer.count, base)
        }
        guard randomStatus == errSecSuccess else { throw VaultError.keychain(randomStatus) }
        var addQuery = baseQuery
        addQuery[kSecValueData as String] = bytes
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecDuplicateItem { return try key() }
        guard addStatus == errSecSuccess else { throw VaultError.keychain(addStatus) }
        return SymmetricKey(data: bytes)
    }

    private static func vaultDirectory() throws -> URL {
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroup) else {
            throw VaultError.containerUnavailable
        }
        let directory = container
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("TribeTunnelVault", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [
                .posixPermissions: 0o700,
                .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
            ]
        )
        let canonicalContainer = container.resolvingSymlinksInPath().standardizedFileURL.path
        let canonicalDirectory = directory.resolvingSymlinksInPath().standardizedFileURL.path
        guard canonicalDirectory.hasPrefix(canonicalContainer + "/") else {
            throw VaultError.invalidPath
        }
        var info = stat()
        guard lstat(directory.path, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == geteuid(),
              (info.st_mode & 0o077) == 0 else { throw VaultError.invalidPath }
        return directory
    }

    private static func recordURL(id: String) throws -> URL {
        let directory = try vaultDirectory()
        let url = directory.appendingPathComponent("handoff-\(id).tv1", isDirectory: false)
        guard url.deletingLastPathComponent().standardizedFileURL == directory.standardizedFileURL else {
            throw VaultError.invalidPath
        }
        return url
    }

    private static func claimURL(id: String) throws -> URL {
        let directory = try vaultDirectory()
        let url = directory.appendingPathComponent(
            "claimed-\(id)-\(UUID().uuidString.lowercased()).tv1", isDirectory: false)
        guard url.deletingLastPathComponent().standardizedFileURL == directory.standardizedFileURL else {
            throw VaultError.invalidPath
        }
        return url
    }

    private static func synchronizeDirectory(_ directory: URL) throws {
        let descriptor = open(directory.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw VaultError.invalidPath }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else { throw VaultError.invalidPath }
    }

    private static func canonicalReference(_ value: String) throws -> String {
        guard value == value.lowercased(), let uuid = UUID(uuidString: value),
              uuid.uuidString.lowercased() == value else { throw VaultError.invalidReference }
        return value
    }

    private static func validateProtocol(_ value: String) throws {
        guard value == "awg" || value == "xray" else { throw VaultError.invalidProtocol }
    }

    private static func aad(reference: String, protocolName: String, sessionId: String) -> Data {
        var data = magic
        data.append(0)
        data.append(Data(reference.utf8))
        data.append(0)
        data.append(Data(protocolName.utf8))
        data.append(0)
        data.append(Data(sessionId.utf8))
        return data
    }

    private static func readOwnedRecord(_ url: URL) throws -> Data {
        let descriptor = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw VaultError.invalidRecord }
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == geteuid(),
              (info.st_mode & 0o777) == 0o600,
              info.st_nlink == 1,
              info.st_size > 0,
              info.st_size <= maximumRecordBytes else {
            throw VaultError.invalidRecord
        }
        var result = Data(count: Int(info.st_size))
        var offset = 0
        while offset < result.count {
            // Swift exclusivity forbids reading result.count while Data's storage is borrowed
            // mutably by withUnsafeMutableBytes. Freeze the requested span before the borrow.
            let remaining = result.count - offset
            let count = result.withUnsafeMutableBytes { bytes -> Int in
                guard let base = bytes.baseAddress else { return -1 }
                return read(descriptor, base.advanced(by: offset), remaining)
            }
            guard count > 0 else { throw VaultError.invalidRecord }
            offset += count
        }
        var extra: UInt8 = 0
        guard read(descriptor, &extra, 1) == 0 else { throw VaultError.invalidRecord }
        return result
    }

    private static func cleanupOrphans(excluding: URL) {
        guard let directory = try? vaultDirectory(),
              let files = try? FileManager.default.contentsOfDirectory(
                at: directory,
                includingPropertiesForKeys: [.creationDateKey, .isRegularFileKey],
                options: []) else { return }
        let cutoff = Date().addingTimeInterval(-24 * 60 * 60)
        for file in files where file != excluding {
            guard file.lastPathComponent.hasPrefix("handoff-")
                    || file.lastPathComponent.hasPrefix("claimed-") else { continue }
            let values = try? file.resourceValues(forKeys: [.creationDateKey, .isRegularFileKey])
            if values?.isRegularFile == true, (values?.creationDate ?? .distantPast) < cutoff {
                try? FileManager.default.removeItem(at: file)
            }
        }
    }

    private struct Envelope: Codable {
        let schemaVersion: Int
        let reference: String
        let protocolName: String
        let sessionId: String
        let createdAtMillis: Int64
        let sealedCombined: String
    }

    private enum VaultError: Error {
        case configSize
        case encryption
        case keychain(OSStatus)
        case containerUnavailable
        case invalidPath
        case invalidReference
        case invalidProtocol
        case invalidRecord
    }
}
