import Foundation
import XCTest
@testable import TinfoilPasskeyKit

final class WrappedKeyRecordCodecTests: XCTestCase {
    func testEmitsAndDecodesExactCrossLanguageRecords() throws {
        let fixtures = try InteropFixtures.load()
        for vector in fixtures.vectors.values {
            let expected = Data(vector.canonicalRecord.utf8)
            let wrappedKey = try vector.wrappedKey.value()
            XCTAssertEqual(try encodeWrappedKeyRecord(wrappedKey), expected)
            XCTAssertEqual(try decodeWrappedKeyRecord(expected), wrappedKey)
        }
    }

    func testDecoderAcceptsWhitespaceAndAnyFieldOrder() throws {
        let vector = try fixtureVector(named: "javascriptWrapped")
        let canonical = Data(vector.canonicalRecord.utf8)
        let value = try JSONSerialization.jsonObject(with: canonical)
        let reordered = try JSONSerialization.data(
            withJSONObject: value,
            options: [.prettyPrinted, .sortedKeys]
        )

        XCTAssertEqual(
            try decodeWrappedKeyRecord(reordered),
            try decodeWrappedKeyRecord(canonical)
        )
    }

    func testDecoderRejectsMalformedAndNoncanonicalRecords() throws {
        let canonical = try fixtureVector(named: "javascriptWrapped").canonicalRecord
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
            canonical.replacingOccurrences(of: "\"prfSalt\":\"", with: "\"prfSalt\":\"="),
            canonical.replacingOccurrences(of: "\"hkdfInfo\":\"", with: "\"hkdfInfo\":\"***"),
            canonical.replacingOccurrences(of: "\"credentialId\":\"AQID\"", with: "\"credentialId\":\"AQID=\""),
            canonical.replacingOccurrences(of: "\"credentialId\":\"AQID\"", with: "\"credentialId\":\"AB\""),
            canonical.replacingOccurrences(of: "\"kekIvHex\":\"01", with: "\"kekIvHex\":\"AA")
        ]

        for value in malformed {
            XCTAssertThrowsError(try decodeWrappedKeyRecord(Data(value.utf8))) { error in
                guard case PasskeyKeyError.invalidInput = error else {
                    return XCTFail("Unexpected error: \(error)")
                }
            }
        }
    }

    func testDecoderRejectsBOMAlternativeEncodingsAndInvalidUTF8() throws {
        let canonical = try fixtureVector(named: "javascriptWrapped").canonicalRecord
        let utf8 = Data(canonical.utf8)
        var withBOM = Data([0xEF, 0xBB, 0xBF])
        withBOM.append(utf8)
        let utf16 = try XCTUnwrap(canonical.data(using: .utf16LittleEndian))
        let utf32 = try XCTUnwrap(canonical.data(using: .utf32BigEndian))
        let invalidUTF8 = Data([0x7B, 0xFF, 0x7D])

        for value in [withBOM, utf16, utf32, invalidUTF8] {
            XCTAssertThrowsError(try decodeWrappedKeyRecord(value)) { error in
                guard case PasskeyKeyError.invalidInput = error else {
                    return XCTFail("Unexpected error: \(error)")
                }
            }
        }
    }

    private func fixtureVector(named name: String) throws -> InteropFixtures.Vector {
        let fixtures = try InteropFixtures.load()
        return try XCTUnwrap(fixtures.vectors[name])
    }
}
