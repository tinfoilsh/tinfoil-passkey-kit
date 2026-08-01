import Foundation

public enum PasskeyProtocol {
    public static let tinfoilPRFSaltV1 = Data("tinfoil-chat-key-encryption".utf8)
    public static let tinfoilHKDFInfoV1 = Data("tinfoil-chat-kek-v1".utf8)
    public static let tinfoilKeyIDInfoV1 = Data("tinfoil-key-id-v1".utf8)

    public static let challengeByteCount = 32
    public static let prfOutputByteCount = 32
    public static let cekByteCount = 32
    public static let kekByteCount = 32
    public static let keyIDByteCount = 16
    public static let aesGCMIVByteCount = 12
    public static let aesGCMTagByteCount = 16
    public static let maximumUserHandleByteCount = 64
}
