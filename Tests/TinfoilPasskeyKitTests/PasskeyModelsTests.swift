import AuthenticationServices
import Foundation
import XCTest
@testable import TinfoilPasskeyKit

@MainActor
final class PasskeyModelsTests: XCTestCase {
    func testProfileValidatesEveryField() {
        XCTAssertThrowsError(try profile(version: 0))
        XCTAssertThrowsError(try profile(version: 2))
        XCTAssertNoThrow(try profile(version: 1))
        XCTAssertThrowsError(try profile(relyingPartyId: ""))
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
                try PasskeyKeyManager(
                    profile: value,
                    relyingPartyName: "Example",
                    presentationAnchorProvider: TestPresentationAnchorProvider(),
                    timeout: timeout
                )
            )
        }
        XCTAssertThrowsError(
            try PasskeyKeyManager(
                profile: value,
                relyingPartyName: "",
                presentationAnchorProvider: TestPresentationAnchorProvider()
            )
        )
    }

    private func profile(
        version: Int = 1,
        relyingPartyId: String = "example.com",
        prfSalt: Data = Data([1]),
        hkdfInfo: Data = Data([2])
    ) throws -> PasskeyKeyProfile {
        try PasskeyKeyProfile(
            version: version,
            relyingPartyId: relyingPartyId,
            prfSalt: prfSalt,
            hkdfInfo: hkdfInfo
        )
    }
}

@MainActor
private final class TestPresentationAnchorProvider: PasskeyPresentationAnchorProviding {
    var presentationAnchor: ASPresentationAnchor {
        fatalError("Presentation is not exercised by model tests")
    }
}
