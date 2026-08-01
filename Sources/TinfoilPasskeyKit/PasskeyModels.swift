import CryptoKit
import Foundation
import Security

/// Identity attached to a newly created passkey.
public struct PasskeyUser: Sendable {
    /// Stable opaque user ID used as the WebAuthn user handle.
    public let id: String
    /// Account identifier shown in passkey pickers, usually an email address.
    public let name: String
    /// Metadata retained for API parity; Apple currently displays `name`.
    public let displayName: String

    public init(id: String, name: String, displayName: String? = nil) {
        self.id = id
        self.name = name
        self.displayName = displayName ?? name
    }
}

/// Result of a successful PRF-capable passkey ceremony.
public struct PRFPasskeyResult {
    /// Unpadded base64url-encoded credential ID.
    public let credentialId: String
    /// Raw PRF output. Treat this as secret key material.
    public let prfOutput: SymmetricKey
    /// Whether the ceremony used an authenticator attached to this device.
    public let isPlatformAuthenticator: Bool

    public init(
        credentialId: String,
        prfOutput: SymmetricKey,
        isPlatformAuthenticator: Bool
    ) {
        self.credentialId = credentialId
        self.prfOutput = prfOutput
        self.isPlatformAuthenticator = isPlatformAuthenticator
    }
}

/// A CEK wrapped under a passkey-derived KEK with AES-256-GCM.
public struct WrappedCEK: Codable, Equatable, Sendable {
    public let credentialId: String
    public let kekIvHex: String
    public let wrappedKeyHex: String

    public init(credentialId: String, kekIvHex: String, wrappedKeyHex: String) {
        self.credentialId = credentialId
        self.kekIvHex = kekIvHex
        self.wrappedKeyHex = wrappedKeyHex
    }
}

public struct EnrollmentResult {
    public let credentialId: String
    public let wrappedCEK: WrappedCEK
    public let prfResult: PRFPasskeyResult

    public init(
        credentialId: String,
        wrappedCEK: WrappedCEK,
        prfResult: PRFPasskeyResult
    ) {
        self.credentialId = credentialId
        self.wrappedCEK = wrappedCEK
        self.prfResult = prfResult
    }
}

public struct UnlockResult: Equatable, Sendable {
    public let credentialId: String
    public let cek: Data

    public init(credentialId: String, cek: Data) {
        self.credentialId = credentialId
        self.cek = cek
    }
}

public enum PasskeyAuthenticationMode: Sendable {
    case interactive
    case immediatelyAvailable
}

public enum PasskeyKitError: LocalizedError {
    case prfNotSupported
    case prfOutputMissing
    case userCancelled
    case authorizationFailed(Error)
    case randomGenerationFailed(OSStatus)
    case invalidBase64URL
    case operationInProgress
    case noCredentialIDs
    case noMatchingBundle
    case invalidChallengeLength(Int)
    case userHandleTooLong(Int)

    public var errorDescription: String? {
        switch self {
        case .prfNotSupported:
            return "Authenticator does not support PRF"
        case .prfOutputMissing:
            return "PRF output missing from assertion"
        case .userCancelled:
            return "User cancelled passkey operation"
        case .authorizationFailed(let error):
            return "Passkey authorization failed: \(error.localizedDescription)"
        case .randomGenerationFailed(let status):
            return "Secure random generation failed (status \(status))"
        case .invalidBase64URL:
            return "Invalid base64url-encoded credential ID"
        case .operationInProgress:
            return "Another passkey operation is already in progress"
        case .noCredentialIDs:
            return "At least one passkey credential ID is required"
        case .noMatchingBundle:
            return "The authenticated passkey has no matching wrapped CEK"
        case .invalidChallengeLength(let count):
            return "Passkey challenge length must be positive (got \(count))"
        case .userHandleTooLong(let count):
            return "Passkey user ID must be at most \(PasskeyProtocol.maximumUserHandleByteCount) UTF-8 bytes (got \(count))"
        }
    }
}

public enum PasskeyCryptoError: LocalizedError {
    case wrongCEKLength(Int)
    case wrongIVLength(Int)
    case malformedHex
    case missingWrappedKey
    case wrappedKeyTooShort(Int)
    case invalidOutputLength(Int)
    case randomGenerationFailed(OSStatus)
    case unwrappedCEKWrongLength(Int)

    public var errorDescription: String? {
        switch self {
        case .wrongCEKLength(let count):
            return "CEK must be \(PasskeyProtocol.cekByteCount) bytes (got \(count))"
        case .wrongIVLength(let count):
            return "AES-GCM IV must be \(PasskeyProtocol.aesGCMIVByteCount) bytes (got \(count))"
        case .malformedHex:
            return "Value is not valid even-length hexadecimal data"
        case .missingWrappedKey:
            return "Wrapped CEK is missing its IV or ciphertext"
        case .wrappedKeyTooShort(let count):
            return "Wrapped CEK is too short to contain an authentication tag (got \(count) bytes)"
        case .invalidOutputLength(let count):
            return "Derived key output length must be positive (got \(count))"
        case .randomGenerationFailed(let status):
            return "Secure random generation failed (status \(status))"
        case .unwrappedCEKWrongLength(let count):
            return "Unwrapped CEK must be \(PasskeyProtocol.cekByteCount) bytes (got \(count))"
        }
    }
}

public struct PasskeyKitConfiguration {
    /// WebAuthn relying-party identifier, such as `example.com`.
    public let rpId: String
    /// Metadata retained for cross-platform API parity; Apple uses the RP ID.
    public let rpName: String
    /// Input to the PRF extension. This must remain stable across clients.
    public let prfSalt: Data
    /// HKDF domain separator used to derive the KEK from PRF output.
    public let hkdfInfo: Data
    public let challengeByteCount: Int
    public let stateStore: (any PasskeyStateStore)?

    public init(
        rpId: String,
        rpName: String,
        prfSalt: Data = PasskeyProtocol.tinfoilPRFSaltV1,
        hkdfInfo: Data = PasskeyProtocol.tinfoilHKDFInfoV1,
        challengeByteCount: Int = PasskeyProtocol.challengeByteCount,
        stateStore: (any PasskeyStateStore)? = nil
    ) {
        self.rpId = rpId
        self.rpName = rpName
        self.prfSalt = prfSalt
        self.hkdfInfo = hkdfInfo
        self.challengeByteCount = challengeByteCount
        self.stateStore = stateStore
    }
}
