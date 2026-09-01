import Foundation
import XCTest
@testable import TinfoilPasskeyKit

@MainActor
final class KeychainPasskeyKeyStorageTests: XCTestCase {
    private struct LegacyEntry: Codable {
        let credentialId: String
        let prfOutput: Data
    }

    private func makeProfile() throws -> PasskeyKeyProfile {
        try PasskeyKeyProfile(
            version: 1,
            relyingPartyId: "example.com",
            prfSalt: Data("example-key-wrapping".utf8),
            hkdfInfo: Data("example-wrapping-key-v1".utf8)
        )
    }

    private func makeStorage(
        decodeCachedRecord: ((Data) throws -> CachedPRFResult)? = nil
    ) -> KeychainPasskeyKeyStorage {
        KeychainPasskeyKeyStorage(
            service: "example.com",
            account: "test-prf-cache",
            localCredentialIdKey: "test-local-credential",
            decodeCachedRecord: decodeCachedRecord
        )
    }

    func testDecodesCanonicalRecordWithoutInvokingFallback() throws {
        let expected = CachedPRFResult(
            profile: try makeProfile(),
            credentialId: "AQ",
            prfOutput: Data(count: 32)
        )
        let data = try JSONEncoder().encode(expected)
        var fallbackInvoked = false
        let storage = makeStorage { _ in
            fallbackInvoked = true
            throw PasskeyKeyError.invalidInput(diagnostic: "unexpected fallback")
        }

        XCTAssertEqual(try storage.decodeStoredRecord(data), expected)
        XCTAssertFalse(fallbackInvoked)
    }

    func testFallbackDecodesLegacyRecord() throws {
        let profile = try makeProfile()
        let legacy = LegacyEntry(credentialId: "AQ", prfOutput: Data(count: 32))
        let data = try JSONEncoder().encode(legacy)
        let storage = makeStorage { payload in
            let entry = try JSONDecoder().decode(LegacyEntry.self, from: payload)
            return CachedPRFResult(
                profile: profile,
                credentialId: entry.credentialId,
                prfOutput: entry.prfOutput
            )
        }

        let decoded = try storage.decodeStoredRecord(data)
        XCTAssertEqual(decoded.profile, profile)
        XCTAssertEqual(decoded.credentialId, "AQ")
        XCTAssertEqual(decoded.prfOutput, Data(count: 32))
    }

    func testFallbackErrorsPropagate() throws {
        let storage = makeStorage { _ in
            throw PasskeyKeyError.invalidInput(diagnostic: "unrecognized cache format")
        }

        XCTAssertThrowsError(
            try storage.decodeStoredRecord(Data("not json".utf8))
        ) { error in
            guard case PasskeyKeyError.invalidInput = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    func testWithoutFallbackCanonicalDecodeErrorPropagates() {
        let storage = makeStorage()
        XCTAssertThrowsError(try storage.decodeStoredRecord(Data("not json".utf8)))
    }
}
