import Foundation
import XCTest
import TinfoilPasskeyKit

/// Uses a plain (non-testable) import so these tests fail to compile if
/// the crypto-only entry points stop being public.
final class PublicKeyWrappingTests: XCTestCase {
    private let prfOutput = Data((0..<32).map { UInt8($0) })
    private let key = Data((100..<132).map { UInt8($0) })
    private let credentialId = "AQ"

    private func makeProfile() throws -> PasskeyKeyProfile {
        try PasskeyKeyProfile(
            version: 1,
            relyingPartyId: "example.com",
            prfSalt: Data("example-key-wrapping".utf8),
            hkdfInfo: Data("example-wrapping-key-v1".utf8)
        )
    }

    func testWrapAndUnwrapRoundTripWithoutManager() throws {
        let profile = try makeProfile()
        let wrapped = try wrapKey(
            profile: profile,
            credentialId: credentialId,
            prfOutput: prfOutput,
            key: key
        )
        XCTAssertEqual(wrapped.profile, profile)
        XCTAssertEqual(wrapped.credentialId, credentialId)
        XCTAssertEqual(
            try unwrapKey(profile: profile, prfOutput: prfOutput, wrapped: wrapped),
            key
        )
    }

    func testUnwrapRejectsWrongPRFOutput() throws {
        let profile = try makeProfile()
        let wrapped = try wrapKey(
            profile: profile,
            credentialId: credentialId,
            prfOutput: prfOutput,
            key: key
        )
        var wrongOutput = prfOutput
        wrongOutput[0] ^= 0xff
        XCTAssertThrowsError(
            try unwrapKey(profile: profile, prfOutput: wrongOutput, wrapped: wrapped)
        ) { error in
            guard case PasskeyKeyError.operationFailed = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    func testWrapValidatesInputs() throws {
        let profile = try makeProfile()
        XCTAssertThrowsError(try wrapKey(
            profile: profile,
            credentialId: credentialId,
            prfOutput: Data(count: 31),
            key: key
        )) { error in
            guard case PasskeyKeyError.invalidInput = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
        XCTAssertThrowsError(try wrapKey(
            profile: profile,
            credentialId: credentialId,
            prfOutput: prfOutput,
            key: Data(count: 31)
        )) { error in
            guard case PasskeyKeyError.invalidInput = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }
}
