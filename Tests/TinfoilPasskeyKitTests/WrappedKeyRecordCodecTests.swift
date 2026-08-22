import Foundation
import XCTest
@testable import TinfoilPasskeyKit

final class WrappedKeyRecordCodecTests: XCTestCase {
    private let canonical = """
    {"version":1,"profile":{"version":1,"relyingPartyId":"example.com","prfSalt":"AP8","hkdfInfo":"AQID"},"credentialId":"AQID","kekIvHex":"000000000000000000000000","wrappedKeyHex":"111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"}
    """

    func testDecodesExactJavaScriptRecordAndEmitsExactUTF8Bytes() throws {
        let wrappedKey = try decodeWrappedKeyRecord(Data(canonical.utf8))

        XCTAssertEqual(wrappedKey.profile.version, 1)
        XCTAssertEqual(wrappedKey.profile.relyingPartyId, "example.com")
        XCTAssertEqual(wrappedKey.profile.prfSalt, Data([0, 255]))
        XCTAssertEqual(wrappedKey.profile.hkdfInfo, Data([1, 2, 3]))
        XCTAssertEqual(try encodeWrappedKeyRecord(wrappedKey), Data(canonical.utf8))
    }

    func testSharedSwiftRecordByteFixture() throws {
        let repository = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let data = try Data(
            contentsOf: repository.appendingPathComponent("fixtures/swift-wrapped-key.json")
        )
        let fixture = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        let profileRecord = try XCTUnwrap(fixture["profile"] as? [String: Any])
        let profile = try PasskeyKeyProfile(
            version: try XCTUnwrap(profileRecord["version"] as? Int),
            relyingPartyId: try XCTUnwrap(profileRecord["relyingPartyId"] as? String),
            prfSalt: try ByteCodec.hexDecode(
                try XCTUnwrap(profileRecord["prfSaltHex"] as? String)
            ),
            hkdfInfo: try ByteCodec.hexDecode(
                try XCTUnwrap(profileRecord["hkdfInfoHex"] as? String)
            )
        )
        let wrappedKey = WrappedKey(
            profile: profile,
            credentialId: try XCTUnwrap(fixture["credentialId"] as? String),
            kekIvHex: try XCTUnwrap(fixture["kekIvHex"] as? String),
            wrappedKeyHex: try XCTUnwrap(fixture["wrappedKeyHex"] as? String)
        )
        let expectedBytes = try ByteCodec.hexDecode(
            try XCTUnwrap(fixture["canonicalRecordUtf8Hex"] as? String)
        )

        XCTAssertEqual(try encodeWrappedKeyRecord(wrappedKey), expectedBytes)
        XCTAssertEqual(try decodeWrappedKeyRecord(expectedBytes), wrappedKey)
    }

    func testDecoderAcceptsWhitespaceAndAnyFieldOrder() throws {
        let reordered = """
        {
          "wrappedKeyHex": "\(String(repeating: "11", count: 48))",
          "credentialId": "AQID",
          "profile": {
            "hkdfInfo": "AQID",
            "relyingPartyId": "example.com",
            "version": 1,
            "prfSalt": "AP8"
          },
          "version": 1,
          "kekIvHex": "\(String(repeating: "00", count: 12))"
        }
        """

        XCTAssertEqual(
            try decodeWrappedKeyRecord(Data(reordered.utf8)),
            try decodeWrappedKeyRecord(Data(canonical.utf8))
        )
    }

    func testDecoderRejectsMalformedAndNoncanonicalRecords() {
        let malformed = [
            "not json",
            "{}",
            canonical.replacingOccurrences(of: "\"version\":1", with: "\"version\":2"),
            canonical.replacingOccurrences(
                of: "\"profile\":{\"version\":1",
                with: "\"profile\":{\"version\":2"
            ),
            canonical.replacingOccurrences(of: "\"profile\":{", with: "\"extra\":true,\"profile\":{"),
            canonical.replacingOccurrences(
                of: "\"profile\":{\"version\":1,",
                with: "\"profile\":{\"version\":1,\"extra\":true,"
            ),
            canonical.replacingOccurrences(of: "\"prfSalt\":\"AP8\"", with: "\"prfSalt\":\"AP8=\""),
            canonical.replacingOccurrences(of: "\"hkdfInfo\":\"AQID\"", with: "\"hkdfInfo\":\"***\""),
            canonical.replacingOccurrences(of: "\"credentialId\":\"AQID\"", with: "\"credentialId\":\"AQID=\""),
            canonical.replacingOccurrences(of: "\"credentialId\":\"AQID\"", with: "\"credentialId\":\"AB\""),
            canonical.replacingOccurrences(of: "\"kekIvHex\":\"00", with: "\"kekIvHex\":\"AA")
        ]

        for value in malformed {
            XCTAssertThrowsError(try decodeWrappedKeyRecord(Data(value.utf8))) { error in
                guard case PasskeyKeyError.invalidInput = error else {
                    return XCTFail("Unexpected error: \(error)")
                }
            }
        }
    }
}
