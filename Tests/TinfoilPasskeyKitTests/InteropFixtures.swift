import Foundation
@testable import TinfoilPasskeyKit

struct InteropFixtures: Decodable {
    struct Profile: Decodable {
        let version: Int
        let relyingPartyId: String
        let prfSaltHex: String
        let hkdfInfoHex: String

        func value() throws -> PasskeyKeyProfile {
            try PasskeyKeyProfile(
                version: version,
                relyingPartyId: relyingPartyId,
                prfSalt: ByteCodec.hexDecode(prfSaltHex),
                hkdfInfo: ByteCodec.hexDecode(hkdfInfoHex)
            )
        }
    }

    struct WrappedKeyValue: Decodable {
        let profile: Profile
        let credentialId: String
        let kekIvHex: String
        let wrappedKeyHex: String

        func value() throws -> WrappedKey {
            WrappedKey(
                profile: try profile.value(),
                credentialId: credentialId,
                kekIvHex: kekIvHex,
                wrappedKeyHex: wrappedKeyHex
            )
        }
    }

    struct Vector: Decodable {
        let wrappedKey: WrappedKeyValue
        let prfOutputHex: String
        let keyHex: String
        let canonicalRecord: String
    }

    struct MalformedField: Decodable {
        let field: String
        let value: String
    }

    struct Negative: Decodable {
        let profileMismatch: Profile
        let tamperedWrappedKeyHex: String
        let malformedFields: [MalformedField]
    }

    let vectors: [String: Vector]
    let negative: Negative

    static func load() throws -> InteropFixtures {
        let testFile = URL(fileURLWithPath: #filePath)
        let repositoryRoot = testFile
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let data = try Data(contentsOf: repositoryRoot.appendingPathComponent("Fixtures/interop.json"))
        return try JSONDecoder().decode(InteropFixtures.self, from: data)
    }
}
