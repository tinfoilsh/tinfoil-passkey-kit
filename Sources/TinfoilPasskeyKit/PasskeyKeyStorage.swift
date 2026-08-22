import Foundation
import Security

public struct CachedPRFResult: Codable, Equatable, Sendable {
    public let profile: PasskeyKeyProfile
    public let credentialId: String
    public let prfOutput: Data

    public init(profile: PasskeyKeyProfile, credentialId: String, prfOutput: Data) {
        self.profile = profile
        self.credentialId = credentialId
        self.prfOutput = prfOutput
    }
}

@MainActor
public protocol PasskeyKeyStorage: AnyObject {
    func loadCachedPRFResult() throws -> CachedPRFResult?
    func saveCachedPRFResult(_ result: CachedPRFResult) throws
    func loadLocalCredentialId() throws -> String?
    func saveLocalCredentialId(_ credentialId: String) throws
    func clear() throws
}

@MainActor
public final class MemoryPasskeyKeyStorage: PasskeyKeyStorage {
    private var cachedResult: CachedPRFResult?
    private var localCredentialId: String?

    public init() {}

    public func loadCachedPRFResult() throws -> CachedPRFResult? {
        cachedResult
    }

    public func saveCachedPRFResult(_ result: CachedPRFResult) throws {
        cachedResult = result
    }

    public func loadLocalCredentialId() throws -> String? {
        localCredentialId
    }

    public func saveLocalCredentialId(_ credentialId: String) throws {
        localCredentialId = credentialId
    }

    public func clear() throws {
        cachedResult = nil
        localCredentialId = nil
    }
}

@MainActor
public final class KeychainPasskeyKeyStorage: PasskeyKeyStorage {
    private let service: String
    private let account: String
    private let localCredentialIdKey: String
    private let userDefaults: UserDefaults

    public init(
        service: String,
        account: String,
        localCredentialIdKey: String,
        userDefaults: UserDefaults = .standard
    ) {
        self.service = service
        self.account = account
        self.localCredentialIdKey = localCredentialIdKey
        self.userDefaults = userDefaults
    }

    public func loadCachedPRFResult() throws -> CachedPRFResult? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var value: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = value as? Data else {
            throw storageError(status)
        }
        return try JSONDecoder().decode(CachedPRFResult.self, from: data)
    }

    public func saveCachedPRFResult(_ result: CachedPRFResult) throws {
        let data = try JSONEncoder().encode(result)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            throw storageError(updateStatus)
        }

        var query = baseQuery
        attributes.forEach { query[$0.key] = $0.value }
        let addStatus = SecItemAdd(query as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw storageError(addStatus)
        }
    }

    public func loadLocalCredentialId() throws -> String? {
        userDefaults.string(forKey: localCredentialIdKey)
    }

    public func saveLocalCredentialId(_ credentialId: String) throws {
        userDefaults.set(credentialId, forKey: localCredentialIdKey)
    }

    public func clear() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw storageError(status)
        }
        userDefaults.removeObject(forKey: localCredentialIdKey)
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }

    private func storageError(_ status: OSStatus) -> NSError {
        NSError(
            domain: NSOSStatusErrorDomain,
            code: Int(status),
            userInfo: [NSLocalizedDescriptionKey: SecCopyErrorMessageString(status, nil) ?? "Storage failed" as CFString]
        )
    }
}
