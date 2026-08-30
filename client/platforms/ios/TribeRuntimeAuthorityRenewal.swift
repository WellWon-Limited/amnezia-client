import CoreFoundation
import CryptoKit
import Darwin
import Foundation

enum TribeRuntimeAuthorityRenewalError: Error {
    case malformed
    case mismatch
    case persistence
}

struct TribeRuntimeAuthorityRenewalRequest: Equatable {
    static let type = "runtime_authority_renewal_request_v1"
    static let schema = 1
    static let exactKeys: Set<String> = [
        "type", "schema", "operation", "session", "renewal_id", "policy_sha256",
        "outer_session_id", "expected_runtime_session_id", "config_generation",
        "binding_generation", "catalog_revision", "catalog_payload_sha256",
        "authority_commitment_sha256", "hard_deadline",
    ]

    let operation: String
    let session: String
    let renewalId: String
    let policySHA256: String
    let outerSessionId: String
    let expectedRuntimeSessionId: String
    let configGeneration: String
    let bindingGeneration: String
    let catalogRevision: String
    let catalogPayloadSHA256: String
    let authorityCommitmentSHA256: String
    let hardDeadline: String

    init(fields: [String: Any], allowEmptyDeadline: Bool = false) throws {
        guard Set(fields.keys) == Self.exactKeys,
              fields["type"] as? String == Self.type,
              Self.schemaOne(fields["schema"]),
              let operation = fields["operation"] as? String,
              let session = fields["session"] as? String,
              let renewalId = fields["renewal_id"] as? String,
              let policy = fields["policy_sha256"] as? String,
              let outer = fields["outer_session_id"] as? String,
              let expected = fields["expected_runtime_session_id"] as? String,
              let configGeneration = fields["config_generation"] as? String,
              let bindingGeneration = fields["binding_generation"] as? String,
              let revision = fields["catalog_revision"] as? String,
              let payload = fields["catalog_payload_sha256"] as? String,
              let commitment = fields["authority_commitment_sha256"] as? String,
              let deadline = fields["hard_deadline"] as? String,
              Self.canonicalDecimal(operation, allowZero: false),
              Self.canonicalDecimal(session, allowZero: false),
              Self.canonicalUUID(renewalId), Self.sha256(policy), Self.safeOuter(outer),
              Self.canonicalUUID(expected),
              Self.canonicalDecimal(configGeneration, allowZero: true),
              Self.canonicalDecimal(bindingGeneration, allowZero: true),
              Self.canonicalDecimal(revision, allowZero: true),
              Self.sha256(payload), Self.sha256(commitment),
              (Self.canonicalDeadline(deadline) || (allowEmptyDeadline && deadline.isEmpty)) else {
            throw TribeRuntimeAuthorityRenewalError.malformed
        }
        self.operation = operation
        self.session = session
        self.renewalId = renewalId
        self.policySHA256 = policy
        self.outerSessionId = outer
        self.expectedRuntimeSessionId = expected
        self.configGeneration = configGeneration
        self.bindingGeneration = bindingGeneration
        self.catalogRevision = revision
        self.catalogPayloadSHA256 = payload
        self.authorityCommitmentSHA256 = commitment
        self.hardDeadline = deadline
    }

    func fields() -> [String: Any] { [
        "type": Self.type, "schema": Self.schema,
        "operation": operation, "session": session, "renewal_id": renewalId,
        "policy_sha256": policySHA256, "outer_session_id": outerSessionId,
        "expected_runtime_session_id": expectedRuntimeSessionId,
        "config_generation": configGeneration, "binding_generation": bindingGeneration,
        "catalog_revision": catalogRevision,
        "catalog_payload_sha256": catalogPayloadSHA256,
        "authority_commitment_sha256": authorityCommitmentSHA256,
        "hard_deadline": hardDeadline,
    ] }

    func validate(configuration root: [String: Any], serializedConfiguration: Data,
                  snapshot: TribeRuntimeAuthorityLeaseSnapshot) throws {
        guard try TribeNativeDispatchPolicy.validateEnvelope(root),
              let authority = root["runtime_authority_v1"] as? [String: Any],
              authority["policy_sha256"] as? String == policySHA256,
              authority["config_generation"] as? String == configGeneration,
              authority["binding_generation"] as? String == bindingGeneration,
              authority["catalog_revision"] as? String == catalogRevision,
              authority["catalog_payload_sha256"] as? String == catalogPayloadSHA256,
              Self.formatDeadline(snapshot.hardDeadline) == hardDeadline,
              Self.authorityCommitmentSHA256(serializedConfiguration)
                == authorityCommitmentSHA256 else {
            throw TribeRuntimeAuthorityRenewalError.mismatch
        }
    }

    /// Commitment over the exact compact QJsonDocument bytes, before any native JSON reserialization.
    static func authorityCommitmentSHA256(_ serializedConfiguration: Data) -> String {
        SHA256.hash(data: serializedConfiguration)
            .map { String(format: "%02x", $0) }.joined()
    }

    static func formatDeadline(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
        return formatter.string(from: date)
    }

    static func canonicalDecimal(_ value: String, allowZero: Bool) -> Bool {
        !value.isEmpty && value.count <= 20 && (value == "0" || value.first != "0")
            && value.allSatisfy { $0 >= "0" && $0 <= "9" }
            && UInt64(value).map { String($0) == value && (allowZero || $0 > 0) } == true
    }

    static func canonicalUUID(_ value: String) -> Bool {
        value.count == 36 && value == value.lowercased()
            && UUID(uuidString: value)?.uuidString.lowercased() == value
    }

    static func sha256(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy {
            ($0 >= "0" && $0 <= "9") || ($0 >= "a" && $0 <= "f")
        }
    }

    static func safeOuter(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 200 && value.utf8.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5a)
                || ($0 >= 0x61 && $0 <= 0x7a) || [0x2d, 0x5f, 0x3a, 0x2e].contains($0)
        }
    }

    static func safeReason(_ value: String) -> Bool {
        value.utf8.count <= 96 && value.utf8.allSatisfy { $0 >= 0x20 && $0 <= 0x7e }
    }

    static func canonicalDeadline(_ value: String) -> Bool {
        guard value.utf8.count == 24 else { return false }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
        guard let date = formatter.date(from: value) else { return false }
        return formatter.string(from: date) == value
    }

    private static func schemaOne(_ value: Any?) -> Bool {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID() else { return false }
        return number.doubleValue == 1.0 && number.int64Value == 1
    }
}

struct TribeRuntimeAuthorityRenewalReceipt {
    static let type = "runtime_authority_renewal_v1"
    static let exactKeys = TribeRuntimeAuthorityRenewalRequest.exactKeys
        .union(["kind", "reason"])

    let kind: String
    let request: TribeRuntimeAuthorityRenewalRequest
    let hardDeadline: String
    let reason: String

    static func applied(_ request: TribeRuntimeAuthorityRenewalRequest)
        -> TribeRuntimeAuthorityRenewalReceipt {
        TribeRuntimeAuthorityRenewalReceipt(
            kind: "applied", request: request,
            hardDeadline: request.hardDeadline, reason: "")
    }

    static func rejected(_ request: TribeRuntimeAuthorityRenewalRequest, reason: String)
        -> TribeRuntimeAuthorityRenewalReceipt {
        precondition(!reason.isEmpty && TribeRuntimeAuthorityRenewalRequest.safeReason(reason))
        return TribeRuntimeAuthorityRenewalReceipt(
            kind: "rejected", request: request, hardDeadline: "", reason: reason)
    }

    init(fields: [String: Any]) throws {
        guard Set(fields.keys) == Self.exactKeys,
              fields["type"] as? String == Self.type,
              let kind = fields["kind"] as? String,
              let reason = fields["reason"] as? String,
              let hardDeadline = fields["hard_deadline"] as? String else {
            throw TribeRuntimeAuthorityRenewalError.malformed
        }
        var requestFields = fields
        requestFields.removeValue(forKey: "kind")
        requestFields.removeValue(forKey: "reason")
        requestFields["type"] = TribeRuntimeAuthorityRenewalRequest.type
        let request = try TribeRuntimeAuthorityRenewalRequest(
            fields: requestFields, allowEmptyDeadline: kind == "rejected")
        guard (kind == "applied" && reason.isEmpty && hardDeadline == request.hardDeadline)
                || (kind == "rejected" && hardDeadline.isEmpty && !reason.isEmpty
                    && TribeRuntimeAuthorityRenewalRequest.safeReason(reason)) else {
            throw TribeRuntimeAuthorityRenewalError.malformed
        }
        self.kind = kind
        self.request = request
        self.hardDeadline = hardDeadline
        self.reason = reason
    }

    private init(kind: String, request: TribeRuntimeAuthorityRenewalRequest,
                 hardDeadline: String, reason: String) {
        self.kind = kind
        self.request = request
        self.hardDeadline = hardDeadline
        self.reason = reason
    }

    func fields() -> [String: Any] {
        var fields = request.fields()
        fields["type"] = Self.type
        fields["kind"] = kind
        fields["hard_deadline"] = hardDeadline
        fields["reason"] = reason
        return fields
    }

    func matches(_ expected: TribeRuntimeAuthorityRenewalRequest) -> Bool {
        request.operation == expected.operation
            && request.session == expected.session
            && request.renewalId == expected.renewalId
            && request.policySHA256 == expected.policySHA256
            && request.outerSessionId == expected.outerSessionId
            && request.expectedRuntimeSessionId == expected.expectedRuntimeSessionId
            && request.configGeneration == expected.configGeneration
            && request.bindingGeneration == expected.bindingGeneration
            && request.catalogRevision == expected.catalogRevision
            && request.catalogPayloadSHA256 == expected.catalogPayloadSHA256
            && request.authorityCommitmentSHA256 == expected.authorityCommitmentSHA256
            && (kind == "rejected" || hardDeadline == expected.hardDeadline)
    }
}

/// Durable, metadata-only audit record. Bearer material remains exclusively in the one-shot vault.
enum TribeRuntimeAuthorityRenewalStore {
    private static let appGroup = "group.hk.wellwon.tribe"
    private static let fileName = "runtime-authority-renewal-v1.json"

    static func persist(_ receipt: TribeRuntimeAuthorityRenewalReceipt) throws {
        guard receipt.kind == "applied" else {
            throw TribeRuntimeAuthorityRenewalError.persistence
        }
        _ = try TribeRuntimeAuthorityRenewalReceipt(fields: receipt.fields())
        let data = try JSONSerialization.data(
            withJSONObject: receipt.fields(), options: [.sortedKeys])
        guard data.count <= 16 * 1024 else {
            throw TribeRuntimeAuthorityRenewalError.persistence
        }
        let directory = try renewalDirectory()
        let destination = directory.appendingPathComponent(fileName, isDirectory: false)
        let temporary = directory.appendingPathComponent(
            ".renewal-\(UUID().uuidString.lowercased()).tmp", isDirectory: false)
        let descriptor = open(temporary.path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW,
                              mode_t(0o600))
        guard descriptor >= 0 else { throw TribeRuntimeAuthorityRenewalError.persistence }
        var completed = false
        defer {
            close(descriptor)
            if !completed { unlink(temporary.path) }
        }
        var offset = 0
        while offset < data.count {
            let written = data.withUnsafeBytes { bytes -> Int in
                guard let base = bytes.baseAddress else { return -1 }
                return Darwin.write(descriptor, base.advanced(by: offset), data.count - offset)
            }
            guard written > 0 else { throw TribeRuntimeAuthorityRenewalError.persistence }
            offset += written
        }
        guard fsync(descriptor) == 0 else { throw TribeRuntimeAuthorityRenewalError.persistence }
        try FileManager.default.setAttributes([
            .posixPermissions: 0o600,
            .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
        ], ofItemAtPath: temporary.path)
        guard fsync(descriptor) == 0 else { throw TribeRuntimeAuthorityRenewalError.persistence }
        guard rename(temporary.path, destination.path) == 0 else {
            throw TribeRuntimeAuthorityRenewalError.persistence
        }
        completed = true
        let directoryDescriptor = open(directory.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard directoryDescriptor >= 0 else { throw TribeRuntimeAuthorityRenewalError.persistence }
        defer { close(directoryDescriptor) }
        guard fsync(directoryDescriptor) == 0 else {
            throw TribeRuntimeAuthorityRenewalError.persistence
        }
    }

    private static func renewalDirectory() throws -> URL {
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroup) else {
            throw TribeRuntimeAuthorityRenewalError.persistence
        }
        let directory = container
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("TribeRuntimeAuthority", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700,
                         .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
        var info = stat()
        guard lstat(directory.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == geteuid(), (info.st_mode & 0o077) == 0 else {
            throw TribeRuntimeAuthorityRenewalError.persistence
        }
        return directory
    }
}
