import CryptoKit
import Foundation
import Security

public enum PasskeyCrypto {
    public static func generateCEK() throws -> Data {
        try randomData(count: PasskeyProtocol.cekByteCount)
    }

    public static func isValidCEK(_ cek: Data) -> Bool {
        cek.count == PasskeyProtocol.cekByteCount
    }

    public static func deriveKeyEncryptionKey(
        from prfOutput: SymmetricKey,
        info: Data = PasskeyProtocol.tinfoilHKDFInfoV1
    ) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: prfOutput,
            salt: Data(),
            info: info,
            outputByteCount: PasskeyProtocol.kekByteCount
        )
    }

    public static func deriveKeyID(
        from cek: Data,
        info: Data = PasskeyProtocol.tinfoilKeyIDInfoV1,
        outputByteCount: Int = PasskeyProtocol.keyIDByteCount
    ) throws -> Data {
        guard isValidCEK(cek) else {
            throw PasskeyCryptoError.wrongCEKLength(cek.count)
        }
        guard outputByteCount > 0 else {
            throw PasskeyCryptoError.invalidOutputLength(outputByteCount)
        }
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: cek),
            salt: Data(),
            info: info,
            outputByteCount: outputByteCount
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    public static func wrapCEK(
        credentialId: String,
        kek: SymmetricKey,
        cek: Data
    ) throws -> WrappedCEK {
        guard isValidCEK(cek) else {
            throw PasskeyCryptoError.wrongCEKLength(cek.count)
        }
        let iv = try randomData(count: PasskeyProtocol.aesGCMIVByteCount)
        let nonce = try AES.GCM.Nonce(data: iv)
        let sealed = try AES.GCM.seal(cek, using: kek, nonce: nonce)
        // The enclave persists kek_iv (12 B) + ciphertext + tag (16 B)
        // as separate hex strings. SealedBox.ciphertext does not include
        // the tag - we append it explicitly to match the on-wire layout.
        var ciphertextAndTag = Data(sealed.ciphertext)
        ciphertextAndTag.append(sealed.tag)
        return WrappedCEK(
            credentialId: credentialId,
            kekIvHex: PasskeyCodec.hexEncode(iv),
            wrappedKeyHex: PasskeyCodec.hexEncode(ciphertextAndTag)
        )
    }

    public static func unwrapCEK(
        _ wrapped: WrappedCEK,
        using kek: SymmetricKey
    ) throws -> Data {
        let plaintext = try decryptWrappedPayload(wrapped, using: kek)
        guard isValidCEK(plaintext) else {
            throw PasskeyCryptoError.unwrappedCEKWrongLength(plaintext.count)
        }
        return plaintext
    }

    public static func decryptWrappedPayload(
        _ wrapped: WrappedCEK,
        using kek: SymmetricKey
    ) throws -> Data {
        guard !wrapped.kekIvHex.isEmpty, !wrapped.wrappedKeyHex.isEmpty else {
            throw PasskeyCryptoError.missingWrappedKey
        }
        let iv = try PasskeyCodec.hexDecode(wrapped.kekIvHex)
        guard iv.count == PasskeyProtocol.aesGCMIVByteCount else {
            throw PasskeyCryptoError.wrongIVLength(iv.count)
        }
        let combinedCiphertext = try PasskeyCodec.hexDecode(wrapped.wrappedKeyHex)
        // AES-GCM tag is 128 bits / 16 bytes.
        guard combinedCiphertext.count > PasskeyProtocol.aesGCMTagByteCount else {
            throw PasskeyCryptoError.wrappedKeyTooShort(combinedCiphertext.count)
        }
        let ciphertext = combinedCiphertext.dropLast(PasskeyProtocol.aesGCMTagByteCount)
        let tag = combinedCiphertext.suffix(PasskeyProtocol.aesGCMTagByteCount)
        let nonce = try AES.GCM.Nonce(data: iv)
        let sealed = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag
        )
        return try AES.GCM.open(sealed, using: kek)
    }

    private static func randomData(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw PasskeyCryptoError.randomGenerationFailed(status)
        }
        return Data(bytes)
    }
}
