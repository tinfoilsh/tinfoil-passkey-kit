import Foundation
import XCTest
@testable import TinfoilPasskeyKit

@MainActor
final class PasskeyModelsTests: XCTestCase {
    func testProfileValidatesEveryField() {
        XCTAssertThrowsError(try profile(version: 0))
        XCTAssertThrowsError(try profile(version: 9_007_199_254_740_992))
        XCTAssertNoThrow(try profile(version: 9_007_199_254_740_991))
        XCTAssertThrowsError(try profile(relyingPartyId: ""))
        XCTAssertThrowsError(try profile(relyingPartyName: ""))
        XCTAssertThrowsError(try profile(prfSalt: Data()))
        XCTAssertThrowsError(try profile(hkdfInfo: Data()))
    }

    func testProfileCodableRoundTripRejectsUnexpectedFields() throws {
        let value = try profile()
        XCTAssertEqual(try JSONDecoder().decode(
            PasskeyKeyProfile.self,
            from: JSONEncoder().encode(value)
        ), value)

        let json = """
        {
          "version": 1,
          "relyingPartyId": "example.com",
          "relyingPartyName": "Example",
          "prfSalt": "AQ==",
          "hkdfInfo": "Ag==",
          "extra": true
        }
        """
        XCTAssertThrowsError(
            try JSONDecoder().decode(PasskeyKeyProfile.self, from: Data(json.utf8))
        )
    }

    func testConfigurationRequiresPositiveFiniteTimeout() throws {
        let value = try profile()
        for timeout in [0, -1, .infinity, .nan] {
            XCTAssertThrowsError(
                try PasskeyKeyManager(profile: value, timeout: timeout)
            )
        }
    }

    private func profile(
        version: Int = 1,
        relyingPartyId: String = "example.com",
        relyingPartyName: String = "Example",
        prfSalt: Data = Data([1]),
        hkdfInfo: Data = Data([2])
    ) throws -> PasskeyKeyProfile {
        try PasskeyKeyProfile(
            version: version,
            relyingPartyId: relyingPartyId,
            relyingPartyName: relyingPartyName,
            prfSalt: prfSalt,
            hkdfInfo: hkdfInfo
        )
    }
}
