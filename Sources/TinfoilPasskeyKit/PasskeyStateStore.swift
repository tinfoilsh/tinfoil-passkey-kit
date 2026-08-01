import CryptoKit
import Foundation
import Security

@MainActor
public protocol PasskeyStateStore: AnyObject {
    func cachePRFResult(_ result: PRFPasskeyResult)
    func cachedPRFResult() -> PRFPasskeyResult?
    func clearCachedPRFResult()
    func localCredentialId() -> String?
    func setLocalCredentialId(_ credentialId: String)
    func clearLocalCredentialId()
}

@MainActor
public final class KeychainPasskeyStateStore: PasskeyStateStore {
    private struct CacheEntry: Codable {
        let credentialId: String
        let prfOutput: Data
        /// Optional so entries written before this field existed still decode.
        /// A missing value is treated as cross-platform below.
        let isPlatformAuthenticator: Bool?
    }

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

    public func cachePRFResult(_ result: PRFPasskeyResult) {
        let entry = CacheEntry(
            credentialId: result.credentialId,
            prfOutput: result.prfOutput.withUnsafeBytes { Data($0) },
            isPlatformAuthenticator: result.isPlatformAuthenticator
        )
        guard let data = try? JSONEncoder().encode(entry) else { return }

        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let updateStatus = SecItemUpdate(
            baseQuery as CFDictionary,
            attributes as CFDictionary
        )
        guard updateStatus == errSecItemNotFound else { return }

        var addQuery = baseQuery
        attributes.forEach { addQuery[$0.key] = $0.value }
        SecItemAdd(addQuery as CFDictionary, nil)
    }

    public func cachedPRFResult() -> PRFPasskeyResult? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let data = result as? Data,
              let entry = try? JSONDecoder().decode(CacheEntry.self, from: data) else {
            return nil
        }
        return PRFPasskeyResult(
            credentialId: entry.credentialId,
            prfOutput: SymmetricKey(data: entry.prfOutput),
            isPlatformAuthenticator: entry.isPlatformAuthenticator ?? false
        )
    }

    public func clearCachedPRFResult() {
        SecItemDelete(baseQuery as CFDictionary)
    }

    public func localCredentialId() -> String? {
        userDefaults.string(forKey: localCredentialIdKey)
    }

    public func setLocalCredentialId(_ credentialId: String) {
        userDefaults.set(credentialId, forKey: localCredentialIdKey)
    }

    public func clearLocalCredentialId() {
        userDefaults.removeObject(forKey: localCredentialIdKey)
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }
}

@MainActor
public final class InMemoryPasskeyStateStore: PasskeyStateStore {
    private var prfResult: PRFPasskeyResult?
    private var credentialId: String?

    public init() {}

    public func cachePRFResult(_ result: PRFPasskeyResult) {
        prfResult = result
    }

    public func cachedPRFResult() -> PRFPasskeyResult? {
        prfResult
    }

    public func clearCachedPRFResult() {
        prfResult = nil
    }

    public func localCredentialId() -> String? {
        credentialId
    }

    public func setLocalCredentialId(_ credentialId: String) {
        self.credentialId = credentialId
    }

    public func clearLocalCredentialId() {
        credentialId = nil
    }
}
