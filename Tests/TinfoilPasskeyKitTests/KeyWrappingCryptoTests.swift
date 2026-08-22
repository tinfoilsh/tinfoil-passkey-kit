import Foundation
import XCTest
@testable import TinfoilPasskeyKit

final class KeyWrappingCryptoTests: XCTestCase {
    private let profile = try! PasskeyKeyProfile(
        version: 1,
        relyingPartyId: "example.com",
        prfSalt: Data("tinfoil-chat-key-encryption".utf8),
        hkdfInfo: Data("tinfoil-chat-kek-v1".utf8)
    )

    func testUnwrapsExactJavaScriptFixture() throws {
        let wrapped = WrappedKey(
            profile: profile,
            credentialId: "AQID",
            kekIvHex: "0102030405060708090a0b0c",
            wrappedKeyHex: "53c8f700925c9f94a7cf679d8a892c82f7c443769103a322e477a38d9118f0a014a659136ee1b9f6ed4921877f17aca7"
        )
        let prfOutput = Data((0..<32).map(UInt8.init))
        let expected = Data((0..<32).map { UInt8(255 - $0) })

        XCTAssertEqual(
            try KeyWrappingCrypto.unwrap(
                profile: profile,
                prfOutput: prfOutput,
                wrapped: wrapped
            ),
            expected
        )
    }

    func testProducesSharedSwiftFixture() throws {
        let fixtureProfile = try PasskeyKeyProfile(
            version: 1,
            relyingPartyId: "example.com",
            prfSalt: Data("test-prf".utf8),
            hkdfInfo: Data("test-kek".utf8)
        )
        let wrapped = try KeyWrappingCrypto.wrapForTesting(
            profile: fixtureProfile,
            credentialId: "AQID",
            prfOutput: Data(repeating: 3, count: 32),
            key: Data((0..<32).map(UInt8.init)),
            iv: Data((0..<12).map(UInt8.init))
        )

        XCTAssertEqual(wrapped.kekIvHex, "000102030405060708090a0b")
        XCTAssertEqual(
            wrapped.wrappedKeyHex,
            "a5dd0ee7cbbc212ee1b0ed30d56b7448509eb265f2fb0f92f720b330d7da970291b62781a5fdaeb7fc1a23a3d12a3ceb"
        )
    }

    func testRejectsWrongLengthsMalformedFieldsAndTampering() throws {
        XCTAssertThrowsError(try KeyWrappingCrypto.validateKey(Data(count: 31)))
        XCTAssertThrowsError(try KeyWrappingCrypto.validatePRFOutput(Data(count: 31)))

        let wrapped = try KeyWrappingCrypto.wrapForTesting(
            profile: profile,
            credentialId: "AQ",
            prfOutput: Data(count: 32),
            key: Data(count: 32),
            iv: Data(count: 12)
        )
        let malformed = WrappedKey(
            profile: profile,
            credentialId: wrapped.credentialId,
            kekIvHex: "bad",
            wrappedKeyHex: wrapped.wrappedKeyHex
        )
        XCTAssertThrowsError(try KeyWrappingCrypto.validateWrappedKey(malformed, profile: profile))

        var bytes = try ByteCodec.hexDecode(wrapped.wrappedKeyHex)
        bytes[0] ^= .max
        let tampered = WrappedKey(
            profile: profile,
            credentialId: wrapped.credentialId,
            kekIvHex: wrapped.kekIvHex,
            wrappedKeyHex: ByteCodec.hexEncode(bytes)
        )
        XCTAssertThrowsError(
            try KeyWrappingCrypto.unwrap(
                profile: profile,
                prfOutput: Data(count: 32),
                wrapped: tampered
            )
        ) { error in
            guard case PasskeyKeyError.operationFailed = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    func testUsesFreshIVs() throws {
        let first = try KeyWrappingCrypto.wrap(
            profile: profile,
            credentialId: "AQ",
            prfOutput: Data(count: 32),
            key: Data(count: 32)
        )
        let second = try KeyWrappingCrypto.wrap(
            profile: profile,
            credentialId: "AQ",
            prfOutput: Data(count: 32),
            key: Data(count: 32)
        )
        XCTAssertNotEqual(first.kekIvHex, second.kekIvHex)
    }
}
