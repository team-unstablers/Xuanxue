import Foundation

/// SSH key related errors
public enum SSHError: Error, LocalizedError, Sendable {
    case invalidFormat(String)
    case unsupportedAlgorithm(String)
    case invalidKeyData(String)
    case invalidSignature
    case decryptionFailed(String)
    case unsupportedKDF(String)
    case unsupportedCipher(String)
    case incorrectPassphrase
    case keyMismatch

    public var errorDescription: String? {
        switch self {
        case .invalidFormat(let message):
            return "Invalid format: \(message)"
        case .unsupportedAlgorithm(let algorithm):
            return "Unsupported algorithm: \(algorithm)"
        case .invalidKeyData(let message):
            return "Invalid key data: \(message)"
        case .invalidSignature:
            return "Invalid signature"
        case .decryptionFailed(let message):
            return "Decryption failed: \(message)"
        case .unsupportedKDF(let kdf):
            return "Unsupported KDF: \(kdf)"
        case .unsupportedCipher(let cipher):
            return "Unsupported cipher: \(cipher)"
        case .incorrectPassphrase:
            return "Incorrect passphrase"
        case .keyMismatch:
            return "Key data mismatch"
        }
    }
}
