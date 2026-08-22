import CryptoKit
import Foundation
import Security

enum KeyWrappingCrypto {
    static let keyByteCount = 32
    static let prfOutputByteCount = 32
    static let ivByteCount = 12
    static let tagByteCount = 16

    static func validateKey(_ key: Data) throws {
        guard key.count == keyByteCount else {
            throw PasskeyKeyError.invalidInput(diagnostic: "key must be exactly 32 bytes")
        }
    }

    static func validatePRFOutput(_ output: Data) throws {
        guard output.count == prfOutputByteCount else {
            throw PasskeyKeyError.invalidInput(diagnostic: "PRF output must be exactly 32 bytes")
        }
    }

    static func validateWrappedKey(_ wrapped: WrappedKey, profile: PasskeyKeyProfile) throws {
        guard wrapped.profile == profile else {
            throw PasskeyKeyError.invalidInput(diagnostic: "wrapped key profile mismatch")
        }
        _ = try ByteCodec.base64URLDecode(wrapped.credentialId)
        guard wrapped.kekIvHex.count == ivByteCount * 2,
              wrapped.wrappedKeyHex.count == (keyByteCount + tagByteCount) * 2 else {
            throw PasskeyKeyError.invalidInput(diagnostic: "wrapped key has an invalid length")
        }
        _ = try ByteCodec.hexDecode(wrapped.kekIvHex)
        _ = try ByteCodec.hexDecode(wrapped.wrappedKeyHex)
    }

    static func wrap(
        profile: PasskeyKeyProfile,
        credentialId: String,
        prfOutput: Data,
        key: Data
    ) throws -> WrappedKey {
        try wrapForTesting(
            profile: profile,
            credentialId: credentialId,
            prfOutput: prfOutput,
            key: key,
            iv: randomData(count: ivByteCount)
        )
    }

    static func wrapForTesting(
        profile: PasskeyKeyProfile,
        credentialId: String,
        prfOutput: Data,
        key: Data,
        iv: Data
    ) throws -> WrappedKey {
        try validateKey(key)
        try validatePRFOutput(prfOutput)
        _ = try ByteCodec.base64URLDecode(credentialId)
        do {
            guard iv.count == ivByteCount else {
                throw PasskeyKeyError.invalidInput(diagnostic: "AES-GCM IV must be exactly 12 bytes")
            }
            let sealed = try AES.GCM.seal(
                key,
                using: deriveWrappingKey(prfOutput: prfOutput, profile: profile),
                nonce: AES.GCM.Nonce(data: iv)
            )
            var ciphertextAndTag = Data(sealed.ciphertext)
            ciphertextAndTag.append(sealed.tag)
            return WrappedKey(
                profile: profile,
                credentialId: credentialId,
                kekIvHex: ByteCodec.hexEncode(iv),
                wrappedKeyHex: ByteCodec.hexEncode(ciphertextAndTag)
            )
        } catch let error as PasskeyKeyError {
            throw error
        } catch {
            throw PasskeyKeyError.operationFailed(
                diagnostic: "failed to wrap key",
                underlying: error
            )
        }
    }

    static func unwrap(
        profile: PasskeyKeyProfile,
        prfOutput: Data,
        wrapped: WrappedKey
    ) throws -> Data {
        try validatePRFOutput(prfOutput)
        try validateWrappedKey(wrapped, profile: profile)
        do {
            let iv = try ByteCodec.hexDecode(wrapped.kekIvHex)
            let combined = try ByteCodec.hexDecode(wrapped.wrappedKeyHex)
            let sealed = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: iv),
                ciphertext: combined.dropLast(tagByteCount),
                tag: combined.suffix(tagByteCount)
            )
            let key = try AES.GCM.open(
                sealed,
                using: deriveWrappingKey(prfOutput: prfOutput, profile: profile)
            )
            try validateKey(key)
            return key
        } catch let error as PasskeyKeyError {
            throw error
        } catch {
            throw PasskeyKeyError.operationFailed(
                diagnostic: "failed to recover key",
                underlying: error
            )
        }
    }

    private static func deriveWrappingKey(
        prfOutput: Data,
        profile: PasskeyKeyProfile
    ) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: prfOutput),
            salt: Data(),
            info: profile.hkdfInfo,
            outputByteCount: keyByteCount
        )
    }

    private static func randomData(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else {
            let error = NSError(domain: NSOSStatusErrorDomain, code: Int(status))
            throw PasskeyKeyError.operationFailed(
                diagnostic: "secure random generation failed",
                underlying: error
            )
        }
        return Data(bytes)
    }
}
