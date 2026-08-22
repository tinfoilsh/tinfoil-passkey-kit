import Foundation

public struct PasskeyKeyProfile: Codable, Equatable, Sendable {
    private static let maximumInteroperableVersion = 9_007_199_254_740_991

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case version
        case relyingPartyId
        case relyingPartyName
        case prfSalt
        case hkdfInfo
    }

    public let version: Int
    public let relyingPartyId: String
    public let relyingPartyName: String
    public let prfSalt: Data
    public let hkdfInfo: Data

    public init(
        version: Int,
        relyingPartyId: String,
        relyingPartyName: String,
        prfSalt: Data,
        hkdfInfo: Data
    ) throws {
        guard version > 0, version <= Self.maximumInteroperableVersion else {
            throw PasskeyKeyError.invalidInput(
                diagnostic: "profile version must be a positive JavaScript safe integer"
            )
        }
        guard !relyingPartyId.isEmpty else {
            throw PasskeyKeyError.invalidInput(diagnostic: "relying-party ID must not be empty")
        }
        guard !relyingPartyName.isEmpty else {
            throw PasskeyKeyError.invalidInput(diagnostic: "relying-party name must not be empty")
        }
        guard !prfSalt.isEmpty else {
            throw PasskeyKeyError.invalidInput(diagnostic: "PRF salt must not be empty")
        }
        guard !hkdfInfo.isEmpty else {
            throw PasskeyKeyError.invalidInput(diagnostic: "HKDF info must not be empty")
        }
        self.version = version
        self.relyingPartyId = relyingPartyId
        self.relyingPartyName = relyingPartyName
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
            relyingPartyName: values.decode(String.self, forKey: .relyingPartyName),
            prfSalt: values.decode(Data.self, forKey: .prfSalt),
            hkdfInfo: values.decode(Data.self, forKey: .hkdfInfo)
        )
    }
}

public typealias PasskeyKeyLogger = @MainActor (_ error: Error) -> Void

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
