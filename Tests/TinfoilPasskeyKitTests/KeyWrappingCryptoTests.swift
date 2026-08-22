import Foundation
import XCTest
@testable import TinfoilPasskeyKit

final class KeyWrappingCryptoTests: XCTestCase {
    func testProducesExactSwiftWireVectorAndCanonicalRecord() throws {
        let vector = try fixtureVector(named: "swiftWrapped")
        let wrapped = try KeyWrappingCrypto.wrapForTesting(
            profile: vector.wrappedKey.profile.value(),
            credentialId: vector.wrappedKey.credentialId,
            prfOutput: ByteCodec.hexDecode(vector.prfOutputHex),
            key: ByteCodec.hexDecode(vector.keyHex),
            iv: ByteCodec.hexDecode(vector.wrappedKey.kekIvHex)
        )

        XCTAssertEqual(wrapped, try vector.wrappedKey.value())
        XCTAssertEqual(try encodeWrappedKeyRecord(wrapped), Data(vector.canonicalRecord.utf8))
    }

    func testOpensExactJavaScriptWireVectorAndCanonicalRecord() throws {
        let vector = try fixtureVector(named: "javascriptWrapped")
        let wrapped = try decodeWrappedKeyRecord(Data(vector.canonicalRecord.utf8))

        XCTAssertEqual(wrapped, try vector.wrappedKey.value())
        XCTAssertEqual(
            try KeyWrappingCrypto.unwrap(
                profile: vector.wrappedKey.profile.value(),
                prfOutput: ByteCodec.hexDecode(vector.prfOutputHex),
                wrapped: wrapped
            ),
            try ByteCodec.hexDecode(vector.keyHex)
        )
    }

    func testRejectsFixtureProfileMismatchMalformedFieldsAndTampering() throws {
        let fixtures = try InteropFixtures.load()
        let vector = try fixtureVector(named: "javascriptWrapped")
        let configuredProfile = try vector.wrappedKey.profile.value()
        let wrapped = try vector.wrappedKey.value()
        let prfOutput = try ByteCodec.hexDecode(vector.prfOutputHex)

        XCTAssertThrowsError(try KeyWrappingCrypto.unwrap(
            profile: fixtures.negative.profileMismatch.value(),
            prfOutput: prfOutput,
            wrapped: wrapped
        ))

        for malformed in fixtures.negative.malformedFields {
            let value = WrappedKey(
                profile: wrapped.profile,
                credentialId: malformed.field == "credentialId" ? malformed.value : wrapped.credentialId,
                kekIvHex: malformed.field == "kekIvHex" ? malformed.value : wrapped.kekIvHex,
                wrappedKeyHex: malformed.field == "wrappedKeyHex" ? malformed.value : wrapped.wrappedKeyHex
            )
            XCTAssertThrowsError(try KeyWrappingCrypto.validateWrappedKey(value, profile: configuredProfile))
        }

        let tampered = WrappedKey(
            profile: wrapped.profile,
            credentialId: wrapped.credentialId,
            kekIvHex: wrapped.kekIvHex,
            wrappedKeyHex: fixtures.negative.tamperedWrappedKeyHex
        )
        XCTAssertThrowsError(
            try KeyWrappingCrypto.unwrap(
                profile: configuredProfile,
                prfOutput: prfOutput,
                wrapped: tampered
            )
        ) { error in
            guard case PasskeyKeyError.operationFailed = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    func testRejectsWrongKeyPRFAndProfileVersions() throws {
        XCTAssertThrowsError(try KeyWrappingCrypto.validateKey(Data(count: 31)))
        XCTAssertThrowsError(try KeyWrappingCrypto.validatePRFOutput(Data(count: 31)))
        let profile = try fixtureVector(named: "swiftWrapped").wrappedKey.profile
        XCTAssertThrowsError(try PasskeyKeyProfile(
            version: 2,
            relyingPartyId: profile.relyingPartyId,
            prfSalt: ByteCodec.hexDecode(profile.prfSaltHex),
            hkdfInfo: ByteCodec.hexDecode(profile.hkdfInfoHex)
        ))
    }

    func testUsesFreshIVs() throws {
        let vector = try fixtureVector(named: "swiftWrapped")
        let profile = try vector.wrappedKey.profile.value()
        let prfOutput = try ByteCodec.hexDecode(vector.prfOutputHex)
        let key = try ByteCodec.hexDecode(vector.keyHex)
        let first = try KeyWrappingCrypto.wrap(
            profile: profile,
            credentialId: vector.wrappedKey.credentialId,
            prfOutput: prfOutput,
            key: key
        )
        let second = try KeyWrappingCrypto.wrap(
            profile: profile,
            credentialId: vector.wrappedKey.credentialId,
            prfOutput: prfOutput,
            key: key
        )
        XCTAssertNotEqual(first.kekIvHex, second.kekIvHex)
    }

    private func fixtureVector(named name: String) throws -> InteropFixtures.Vector {
        let fixtures = try InteropFixtures.load()
        return try XCTUnwrap(fixtures.vectors[name])
    }
}
