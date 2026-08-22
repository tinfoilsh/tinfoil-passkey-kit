import Foundation
import Security
import TinfoilPasskeyKit

public protocol WrappedKeyRepository: Sendable {
    func save(_ wrappedKey: WrappedKey) async
    func list() async -> [WrappedKey]
}

public actor InMemoryWrappedKeyRepository: WrappedKeyRepository {
    private var records: [WrappedKey] = []

    public init() {}

    public func save(_ wrappedKey: WrappedKey) {
        records = [wrappedKey]
    }

    public func list() -> [WrappedKey] {
        records
    }
}

@MainActor
public final class PasskeyKeyExample {
    private static let keyByteCount = 32

    private let manager: PasskeyKeyManager
    private let repository: any WrappedKeyRepository

    public init(repository: any WrappedKeyRepository = InMemoryWrappedKeyRepository()) throws {
        let profile = try PasskeyKeyProfile(
            version: 1,
            relyingPartyId: "example.com",
            relyingPartyName: "Passkey Key Example",
            prfSalt: Data("example-key-wrapping".utf8),
            hkdfInfo: Data("example-wrapping-key-v1".utf8)
        )
        self.manager = try PasskeyKeyManager(profile: profile)
        self.repository = repository
    }

    public func enroll() async throws -> Data {
        let key = try Self.generateKey()
        let created = try await manager.createAndWrapKey(
            user: PasskeyUser(
                id: Data(UUID().uuidString.utf8),
                name: "person@example.com",
                displayName: "Example Person"
            ),
            key: key
        )
        await repository.save(created.wrappedKey)
        return key
    }

    public func recover() async throws -> Data {
        let recovered = try await manager.recoverKey(wrappedKeys: await repository.list())
        return recovered.key
    }

    private static func generateKey() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: keyByteCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
        return Data(bytes)
    }
}
