import CoreFoundation
import Foundation

private let wrappedKeyRecordFields: Set<String> = [
    "version",
    "profile",
    "credentialId",
    "kekIvHex",
    "wrappedKeyHex"
]

private let wrappedKeyProfileRecordFields: Set<String> = [
    "version",
    "relyingPartyId",
    "prfSalt",
    "hkdfInfo"
]

public func encodeWrappedKeyRecord(_ wrappedKey: WrappedKey) throws -> Data {
    try KeyWrappingCrypto.validateWrappedKey(wrappedKey, profile: wrappedKey.profile)
    let profile = wrappedKey.profile
    let json = "{" +
        "\"version\":1," +
        "\"profile\":{" +
        "\"version\":1," +
        "\"relyingPartyId\":\(jsonString(profile.relyingPartyId))," +
        "\"prfSalt\":\(jsonString(ByteCodec.base64URLEncode(profile.prfSalt)))," +
        "\"hkdfInfo\":\(jsonString(ByteCodec.base64URLEncode(profile.hkdfInfo)))" +
        "}," +
        "\"credentialId\":\(jsonString(wrappedKey.credentialId))," +
        "\"kekIvHex\":\(jsonString(wrappedKey.kekIvHex))," +
        "\"wrappedKeyHex\":\(jsonString(wrappedKey.wrappedKeyHex))" +
        "}"
    return Data(json.utf8)
}

public func decodeWrappedKeyRecord(_ json: Data) throws -> WrappedKey {
    let value: Any
    do {
        value = try JSONSerialization.jsonObject(with: json)
    } catch {
        throw PasskeyKeyError.invalidInput(
            diagnostic: "wrapped key JSON is malformed",
            underlying: error
        )
    }
    guard let record = value as? [String: Any],
          Set(record.keys) == wrappedKeyRecordFields else {
        throw PasskeyKeyError.invalidInput(
            diagnostic: "wrapped key record has unexpected fields"
        )
    }
    try requireVersionOne(record["version"], field: "wrapped key record")
    guard let profileRecord = record["profile"] as? [String: Any],
          Set(profileRecord.keys) == wrappedKeyProfileRecordFields else {
        throw PasskeyKeyError.invalidInput(
            diagnostic: "wrapped key profile record has unexpected fields"
        )
    }
    try requireVersionOne(profileRecord["version"], field: "wrapped key profile")
    guard let relyingPartyId = profileRecord["relyingPartyId"] as? String,
          let prfSalt = profileRecord["prfSalt"] as? String,
          let hkdfInfo = profileRecord["hkdfInfo"] as? String,
          let credentialId = record["credentialId"] as? String,
          let kekIvHex = record["kekIvHex"] as? String,
          let wrappedKeyHex = record["wrappedKeyHex"] as? String else {
        throw PasskeyKeyError.invalidInput(
            diagnostic: "wrapped key record fields have invalid types"
        )
    }
    let profile = try PasskeyKeyProfile(
        version: 1,
        relyingPartyId: relyingPartyId,
        prfSalt: ByteCodec.base64URLDecode(prfSalt),
        hkdfInfo: ByteCodec.base64URLDecode(hkdfInfo)
    )
    let wrappedKey = WrappedKey(
        profile: profile,
        credentialId: credentialId,
        kekIvHex: kekIvHex,
        wrappedKeyHex: wrappedKeyHex
    )
    try KeyWrappingCrypto.validateWrappedKey(wrappedKey, profile: profile)
    return wrappedKey
}

private func requireVersionOne(_ value: Any?, field: String) throws {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID(),
          number == 1 else {
        throw PasskeyKeyError.invalidInput(diagnostic: "\(field) version must be 1")
    }
}

private func jsonString(_ value: String) -> String {
    var result = "\""
    for scalar in value.unicodeScalars {
        switch scalar.value {
        case 0x08: result += "\\b"
        case 0x09: result += "\\t"
        case 0x0A: result += "\\n"
        case 0x0C: result += "\\f"
        case 0x0D: result += "\\r"
        case 0x22: result += "\\\""
        case 0x5C: result += "\\\\"
        case 0x00...0x1F:
            result += String(format: "\\u%04x", scalar.value)
        default:
            result.unicodeScalars.append(scalar)
        }
    }
    result += "\""
    return result
}
