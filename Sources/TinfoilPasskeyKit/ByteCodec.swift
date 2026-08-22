import Foundation

enum ByteCodec {
    private static let base64QuantumCharacterCount = 4
    private static let hexCharacterCountPerByte = 2
    private static let hexRadix = 16

    static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func base64URLDecode(
        _ string: String,
        field: String = "credential ID"
    ) throws -> Data {
        guard !string.isEmpty,
              string.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil,
              string.count % base64QuantumCharacterCount != 1 else {
            throw PasskeyKeyError.invalidInput(diagnostic: "\(field) must be unpadded base64url")
        }
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % base64QuantumCharacterCount
        if remainder > 0 {
            base64 += String(repeating: "=", count: base64QuantumCharacterCount - remainder)
        }
        guard let data = Data(base64Encoded: base64),
              !data.isEmpty,
              base64URLEncode(data) == string else {
            throw PasskeyKeyError.invalidInput(diagnostic: "\(field) must be unpadded base64url")
        }
        return data
    }

    static func hexEncode(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func hexDecode(_ string: String) throws -> Data {
        guard string.count.isMultiple(of: hexCharacterCountPerByte) else {
            throw PasskeyKeyError.invalidInput(diagnostic: "value must be even-length lowercase hexadecimal")
        }
        var data = Data()
        data.reserveCapacity(string.count / hexCharacterCountPerByte)
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: hexCharacterCountPerByte)
            let pair = string[index..<next]
            guard pair == pair.lowercased(), let byte = UInt8(pair, radix: hexRadix) else {
                throw PasskeyKeyError.invalidInput(diagnostic: "value must be lowercase hexadecimal")
            }
            data.append(byte)
            index = next
        }
        return data
    }
}
