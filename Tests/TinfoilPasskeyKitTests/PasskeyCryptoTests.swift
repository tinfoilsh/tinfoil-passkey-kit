import CryptoKit
import Foundation
import XCTest
@testable import TinfoilPasskeyKit

final class PasskeyCryptoTests: XCTestCase {
    private let testHKDFInfo = Data("test-kek-v1".utf8)
    private let firstTestCEKByte: UInt8 = 7
    private let secondTestCEKByte: UInt8 = 9

    func testGeneratedCEKIsValidAndDistinct() throws {
        let first = try PasskeyCrypto.generateCEK()
        let second = try PasskeyCrypto.generateCEK()

        XCTAssertTrue(PasskeyCrypto.isValidCEK(first))
        XCTAssertTrue(PasskeyCrypto.isValidCEK(second))
        XCTAssertNotEqual(first, second)
    }

    func testWrapAndUnwrapRoundTrip() throws {
        let prfOutput = referencePRFOutput()
        let kek = PasskeyCrypto.deriveKeyEncryptionKey(
            from: prfOutput,
            info: testHKDFInfo
        )
        let cek = Data(
            (0..<PasskeyProtocol.cekByteCount).map { UInt8($0 + 1) }
        )

        let wrapped = try PasskeyCrypto.wrapCEK(
            credentialId: "credential",
            kek: kek,
            cek: cek
        )

        XCTAssertEqual(wrapped.credentialId, "credential")
        XCTAssertEqual(
            try PasskeyCodec.hexDecode(wrapped.kekIvHex).count,
            PasskeyProtocol.aesGCMIVByteCount
        )
        XCTAssertEqual(try PasskeyCrypto.unwrapCEK(wrapped, using: kek), cek)
    }

    func testWrapUsesFreshIV() throws {
        let kek = PasskeyCrypto.deriveKeyEncryptionKey(
            from: SymmetricKey(size: .bits256),
            info: testHKDFInfo
        )
        let cek = Data(repeating: firstTestCEKByte, count: PasskeyProtocol.cekByteCount)

        let first = try PasskeyCrypto.wrapCEK(credentialId: "credential", kek: kek, cek: cek)
        let second = try PasskeyCrypto.wrapCEK(credentialId: "credential", kek: kek, cek: cek)

        XCTAssertNotEqual(first.kekIvHex, second.kekIvHex)
        XCTAssertNotEqual(first.wrappedKeyHex, second.wrappedKeyHex)
    }

    func testKEKMatchesNodeAndJavaScriptReferenceVector() {
        let prfOutput = referencePRFOutput()
        let kek = PasskeyCrypto.deriveKeyEncryptionKey(from: prfOutput)
        let bytes = kek.withUnsafeBytes { Data($0) }

        XCTAssertEqual(
            PasskeyCodec.hexEncode(bytes),
            "dced3c8920b83221ac53e4b0a9a2e075c52826ce67e4a5a536808ca9526a4b35"
        )
    }

    func testDecryptsNodeAndJavaScriptReferenceVector() throws {
        let prfOutput = referencePRFOutput()
        let kek = PasskeyCrypto.deriveKeyEncryptionKey(from: prfOutput)
        let wrapped = WrappedCEK(
            credentialId: "credential",
            kekIvHex: "000102030405060708090a0b",
            wrappedKeyHex: "6bc530571e357f5f140a29a228e90781fba755503b2dcdcf4231757ef56baa93ed95472cac92af58564a39dc771b3f3a"
        )
        let expectedCEK = Data(
            (0..<PasskeyProtocol.cekByteCount).map {
                UInt8($0 + PasskeyProtocol.cekByteCount)
            }
        )

        XCTAssertEqual(try PasskeyCrypto.unwrapCEK(wrapped, using: kek), expectedCEK)
    }

    func testTamperedCiphertextIsRejected() throws {
        let kek = PasskeyCrypto.deriveKeyEncryptionKey(
            from: SymmetricKey(size: .bits256),
            info: testHKDFInfo
        )
        let cek = Data(repeating: secondTestCEKByte, count: PasskeyProtocol.cekByteCount)
        let wrapped = try PasskeyCrypto.wrapCEK(credentialId: "credential", kek: kek, cek: cek)
        var ciphertext = try PasskeyCodec.hexDecode(wrapped.wrappedKeyHex)
        ciphertext[0] ^= UInt8.max
        let tampered = WrappedCEK(
            credentialId: wrapped.credentialId,
            kekIvHex: wrapped.kekIvHex,
            wrappedKeyHex: PasskeyCodec.hexEncode(ciphertext)
        )

        XCTAssertThrowsError(try PasskeyCrypto.unwrapCEK(tampered, using: kek))
    }

    func testKeyIDMatchesEnclaveAndJavaScriptReferenceVector() throws {
        let cek = Data((0..<PasskeyProtocol.cekByteCount).map { UInt8($0) })
        let keyID = try PasskeyCrypto.deriveKeyID(from: cek)

        XCTAssertEqual(
            PasskeyCodec.hexEncode(keyID),
            "960e28ca37b723e7abc19995dbef143f"
        )
    }

    func testWrongCEKLengthIsRejected() {
        let cek = Data(repeating: 0, count: PasskeyProtocol.cekByteCount - 1)

        XCTAssertThrowsError(try PasskeyCrypto.deriveKeyID(from: cek)) { error in
            guard case PasskeyCryptoError.wrongCEKLength(let count) = error else {
                return XCTFail("Unexpected error: \(error)")
            }
            XCTAssertEqual(count, cek.count)
        }
    }

    private func referencePRFOutput() -> SymmetricKey {
        SymmetricKey(
            data: Data(
                (0..<PasskeyProtocol.prfOutputByteCount).map { UInt8($0) }
            )
        )
    }
}
