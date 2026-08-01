import Foundation
import XCTest
@testable import TinfoilPasskeyKit

final class PasskeyCodecTests: XCTestCase {
    private let hexFixtureByteCount = 64

    func testHexRoundTrip() throws {
        let bytes = Data((0..<hexFixtureByteCount).map { UInt8($0) })
        XCTAssertEqual(try PasskeyCodec.hexDecode(PasskeyCodec.hexEncode(bytes)), bytes)
    }

    func testHexRejectsMalformedInput() {
        XCTAssertThrowsError(try PasskeyCodec.hexDecode("abc"))
        XCTAssertThrowsError(try PasskeyCodec.hexDecode("0g"))
    }

    func testBase64URLRoundTripHasNoPaddingOrUnsafeCharacters() throws {
        let bytes = Data((0..<33).map { UInt8($0) })
        let encoded = PasskeyCodec.base64URLEncode(bytes)

        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertFalse(encoded.contains("="))
        XCTAssertEqual(try PasskeyCodec.base64URLDecode(encoded), bytes)
    }
}
