import Foundation
import XCTest
@testable import TinfoilPasskeyKit

final class ByteCodecTests: XCTestCase {
    func testHexAndBase64URLRoundTrips() throws {
        let bytes = Data((0..<64).map(UInt8.init))
        XCTAssertEqual(try ByteCodec.hexDecode(ByteCodec.hexEncode(bytes)), bytes)

        let encoded = ByteCodec.base64URLEncode(bytes)
        XCTAssertFalse(encoded.contains("="))
        XCTAssertEqual(try ByteCodec.base64URLDecode(encoded), bytes)
    }

    func testMalformedEncodingsAreInvalidInput() {
        for value in ["abc", "0G", "0g"] {
            XCTAssertThrowsError(try ByteCodec.hexDecode(value)) { error in
                guard case PasskeyKeyError.invalidInput = error else {
                    return XCTFail("Unexpected error: \(error)")
                }
            }
        }
        for value in ["", "a", "AB", "AQ==", "!"] {
            XCTAssertThrowsError(
                try ByteCodec.base64URLDecode(value, field: "profile.prfSalt")
            ) { error in
                XCTAssertTrue(error.localizedDescription.contains("profile.prfSalt"))
            }
        }
    }
}
