import AuthenticationServices
import Foundation
import Security
import TinfoilPasskeyKit

@MainActor
public final class WindowPresentationAnchorProvider: PasskeyPresentationAnchorProviding {
    private let window: ASPresentationAnchor

    public init(window: ASPresentationAnchor) {
        self.window = window
    }

    public var presentationAnchor: ASPresentationAnchor {
        window
    }
}

public protocol WrappedKeyRepository: Sendable {
    func save(_ record: Data) async throws
    func list() async throws -> [Data]
}

public actor InMemoryWrappedKeyRepository: WrappedKeyRepository {
    private var records: [Data] = []

    public init() {}

    public func save(_ record: Data) throws {
        records.append(record)
    }

    public func list() throws -> [Data] {
        records
    }
}

@MainActor
public final class PasskeyKeyExample {
    private static let keyByteCount = 32

    private let manager: PasskeyKeyManager
    private let repository: any WrappedKeyRepository

    public init(
        presentationAnchorProvider: any PasskeyPresentationAnchorProviding,
        repository: any WrappedKeyRepository = InMemoryWrappedKeyRepository()
    ) throws {
        let profile = try PasskeyKeyProfile(
            version: 1,
            relyingPartyId: "example.com",
            prfSalt: Data("example-key-wrapping".utf8),
            hkdfInfo: Data("example-wrapping-key-v1".utf8)
        )
        self.manager = try PasskeyKeyManager(
            profile: profile,
            relyingPartyName: "Passkey Key Example",
            presentationAnchorProvider: presentationAnchorProvider
        )
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
        try await repository.save(try encodeWrappedKeyRecord(created.wrappedKey))
        return key
    }

    public func recover() async throws -> Data {
        let wrappedKeys = try await loadWrappedKeys()
        let recovered = try await manager.recoverKey(wrappedKeys: wrappedKeys)
        return recovered.key
    }

    public func evaluate() async throws -> EvaluatedCredential {
        let wrappedKeys = try await loadWrappedKeys()
        return try await manager.evaluateCredential(
            credentialIds: wrappedKeys.map(\.credentialId)
        )
    }

    private func loadWrappedKeys() async throws -> [WrappedKey] {
        let records = try await repository.list()
        return try records.map { try decodeWrappedKeyRecord($0) }
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
