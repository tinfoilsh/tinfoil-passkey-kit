import CryptoKit
import Foundation
import XCTest
@testable import TinfoilPasskeyKit

@MainActor
final class PasskeyKitTests: XCTestCase {
    private let cachedPRFByte: UInt8 = 4
    private let testCEKByte: UInt8 = 8

    func testRejectsUserHandlesLongerThanWebAuthnLimit() async {
        let kit = PasskeyKit(
            configuration: PasskeyKitConfiguration(
                rpId: "example.com",
                rpName: "Example"
            )
        )
        let user = PasskeyUser(
            id: String(
                repeating: "u",
                count: PasskeyProtocol.maximumUserHandleByteCount + 1
            ),
            name: "u@example.com"
        )

        do {
            _ = try await kit.createPasskey(for: user)
            XCTFail("Expected an oversized user handle to be rejected")
        } catch PasskeyKitError.userHandleTooLong(let count) {
            XCTAssertEqual(count, PasskeyProtocol.maximumUserHandleByteCount + 1)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testCachedPRFCanRewrapAndUnlockWithoutCeremony() throws {
        let store = InMemoryPasskeyStateStore()
        let result = PRFPasskeyResult(
            credentialId: "credential",
            prfOutput: SymmetricKey(
                data: Data(
                    repeating: cachedPRFByte,
                    count: PasskeyProtocol.prfOutputByteCount
                )
            ),
            isPlatformAuthenticator: true
        )
        store.cachePRFResult(result)
        let kit = PasskeyKit(
            configuration: PasskeyKitConfiguration(
                rpId: "example.com",
                rpName: "Example",
                stateStore: store
            )
        )
        let cek = Data(repeating: testCEKByte, count: PasskeyProtocol.cekByteCount)

        let wrapped = try XCTUnwrap(try kit.rewrapWithCachedPRF(cek))
        let unlocked = try XCTUnwrap(kit.unlockWithCachedPRF([wrapped]))

        XCTAssertEqual(unlocked.credentialId, result.credentialId)
        XCTAssertEqual(unlocked.cek, cek)
    }

    func testCachedUnlockReturnsNilWithoutMatchingBundle() throws {
        let store = InMemoryPasskeyStateStore()
        store.cachePRFResult(
            PRFPasskeyResult(
                credentialId: "cached",
                prfOutput: SymmetricKey(size: .bits256),
                isPlatformAuthenticator: false
            )
        )
        let kit = PasskeyKit(
            configuration: PasskeyKitConfiguration(
                rpId: "example.com",
                rpName: "Example",
                stateStore: store
            )
        )
        let other = WrappedCEK(
            credentialId: "other",
            kekIvHex: "00",
            wrappedKeyHex: "00"
        )

        XCTAssertNil(kit.unlockWithCachedPRF([other]))
    }

    func testClearLocalStateRemovesBothValues() {
        let store = InMemoryPasskeyStateStore()
        store.cachePRFResult(
            PRFPasskeyResult(
                credentialId: "credential",
                prfOutput: SymmetricKey(size: .bits256),
                isPlatformAuthenticator: true
            )
        )
        store.setLocalCredentialId("credential")
        let kit = PasskeyKit(
            configuration: PasskeyKitConfiguration(
                rpId: "example.com",
                rpName: "Example",
                stateStore: store
            )
        )

        kit.clearLocalState()

        XCTAssertNil(store.cachedPRFResult())
        XCTAssertNil(store.localCredentialId())
    }
}
