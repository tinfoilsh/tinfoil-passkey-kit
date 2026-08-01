import Foundation

public enum PasskeyCodec {
    private static let base64QuantumCharacterCount = 4
    private static let hexCharacterCountPerByte = 2
    private static let hexRadix = 16

    public static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func base64URLDecode(_ string: String) throws -> Data {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % base64QuantumCharacterCount
        if remainder > 0 {
            base64 += String(
                repeating: "=",
                count: base64QuantumCharacterCount - remainder
            )
        }
        guard let data = Data(base64Encoded: base64) else {
            throw PasskeyKitError.invalidBase64URL
        }
        return data
    }

    public static func hexEncode(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    public static func hexDecode(_ string: String) throws -> Data {
        guard string.count.isMultiple(of: hexCharacterCountPerByte) else {
            throw PasskeyCryptoError.malformedHex
        }

        var data = Data()
        data.reserveCapacity(string.count / hexCharacterCountPerByte)
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: hexCharacterCountPerByte)
            guard let byte = UInt8(string[index..<next], radix: hexRadix) else {
                throw PasskeyCryptoError.malformedHex
            }
            data.append(byte)
            index = next
        }
        return data
    }
}
