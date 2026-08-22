import Foundation

public struct PasskeyKeyProfile: Codable, Equatable, Sendable {
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case relyingPartyId
        case prfSalt
        case hkdfInfo
    }

    public let version: Int
    public let relyingPartyId: String
    public let prfSalt: Data
    public let hkdfInfo: Data

    public init(
        version: Int,
        relyingPartyId: String,
        prfSalt: Data,
        hkdfInfo: Data
    ) throws {
        guard version == 1 else {
            throw PasskeyKeyError.invalidInput(diagnostic: "profile version must be 1")
        }
        guard !relyingPartyId.isEmpty else {
            throw PasskeyKeyError.invalidInput(diagnostic: "relying-party ID must not be empty")
        }
        guard !prfSalt.isEmpty else {
            throw PasskeyKeyError.invalidInput(diagnostic: "PRF salt must not be empty")
        }
        guard !hkdfInfo.isEmpty else {
            throw PasskeyKeyError.invalidInput(diagnostic: "HKDF info must not be empty")
        }
        self.version = version
        self.relyingPartyId = relyingPartyId
        self.prfSalt = prfSalt
        self.hkdfInfo = hkdfInfo
    }

    public init(from decoder: Decoder) throws {
        let rawValues = try decoder.container(keyedBy: ProfileCodingKey.self)
        let expectedKeys = Set(CodingKeys.allCases.map(\.rawValue))
        guard Set(rawValues.allKeys.map(\.stringValue)) == expectedKeys else {
            throw PasskeyKeyError.invalidInput(
                diagnostic: "profile must contain exactly the documented fields"
            )
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            version: values.decode(Int.self, forKey: .version),
            relyingPartyId: values.decode(String.self, forKey: .relyingPartyId),
            prfSalt: values.decode(Data.self, forKey: .prfSalt),
            hkdfInfo: values.decode(Data.self, forKey: .hkdfInfo)
        )
    }
}

private struct ProfileCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }

    init?(intValue: Int) {
        self.stringValue = String(intValue)
        self.intValue = intValue
    }
}

public struct WrappedKey: Codable, Equatable, Sendable {
    public let profile: PasskeyKeyProfile
    public let credentialId: String
    public let kekIvHex: String
    public let wrappedKeyHex: String

    public init(
        profile: PasskeyKeyProfile,
        credentialId: String,
        kekIvHex: String,
        wrappedKeyHex: String
    ) {
        self.profile = profile
        self.credentialId = credentialId
        self.kekIvHex = kekIvHex
        self.wrappedKeyHex = wrappedKeyHex
    }
}

public struct PasskeyUser: Codable, Equatable, Sendable {
    public let id: Data
    public let name: String
    public let displayName: String?

    public init(id: Data, name: String, displayName: String? = nil) {
        self.id = id
        self.name = name
        self.displayName = displayName
    }
}

public struct CreatedWrappedKey: Equatable, Sendable {
    public let credentialId: String
    public let wrappedKey: WrappedKey

    public init(credentialId: String, wrappedKey: WrappedKey) {
        self.credentialId = credentialId
        self.wrappedKey = wrappedKey
    }
}

public struct RecoveredKey: Equatable, Sendable {
    public let credentialId: String
    public let key: Data

    public init(credentialId: String, key: Data) {
        self.credentialId = credentialId
        self.key = key
    }
}

public enum PasskeyInteraction: Equatable, Sendable {
    case interactive
    case immediatelyAvailable
}

public struct PRFResult: Equatable, Sendable {
    public let output: Data

    public init(output: Data) {
        self.output = output
    }
}

public struct EvaluatedCredential: Equatable, Sendable {
    public let credentialId: String
    public let prfResult: PRFResult

    public init(credentialId: String, prfResult: PRFResult) {
        self.credentialId = credentialId
        self.prfResult = prfResult
    }
}

public enum PasskeyOperation: Sendable {
    case enroll
    case recover
}

public enum PasskeyCapability: Sendable {
    case supported
    case unsupported
    case unknown
}

public enum PasskeyKeyError: Error, @unchecked Sendable {
    case unsupported(diagnostic: String? = nil, underlying: Error? = nil)
    case cancelled(diagnostic: String? = nil, underlying: Error? = nil)
    case timeout(diagnostic: String? = nil, underlying: Error? = nil)
    case operationInProgress
    case invalidInput(diagnostic: String? = nil, underlying: Error? = nil)
    case operationFailed(diagnostic: String? = nil, underlying: Error? = nil)

    public var underlyingError: Error? {
        switch self {
        case .unsupported(_, let underlying),
             .cancelled(_, let underlying),
             .timeout(_, let underlying),
             .invalidInput(_, let underlying),
             .operationFailed(_, let underlying):
            return underlying
        case .operationInProgress:
            return nil
        }
    }
}

extension PasskeyKeyError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unsupported(let diagnostic, _):
            return diagnostic ?? "The requested passkey operation is unsupported"
        case .cancelled(let diagnostic, _):
            return diagnostic ?? "The passkey operation was cancelled"
        case .timeout(let diagnostic, _):
            return diagnostic ?? "The passkey operation timed out"
        case .operationInProgress:
            return "Another passkey operation is in progress"
        case .invalidInput(let diagnostic, _):
            return diagnostic ?? "The passkey operation received invalid input"
        case .operationFailed(let diagnostic, _):
            return diagnostic ?? "The passkey operation failed"
        }
    }
}
