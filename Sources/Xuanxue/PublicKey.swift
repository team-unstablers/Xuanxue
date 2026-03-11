import Foundation
import SwiftASN1

#if canImport(Security)
@preconcurrency import Security
#endif

#if canImport(CryptoKit)
import CryptoKit
#endif

/// SSH Public Key
public struct PublicKey: Sendable, Hashable {
    /// The key algorithm
    public let algorithm: SSHKeyAlgorithm

    /// The key size in bits
    public let keySize: Int

    /// Optional comment
    public let comment: String?

    /// Internal key representation
    internal let keyData: PublicKeyData

    /// Parse a public key from OpenSSH format string
    /// Example: "ssh-rsa AAAAB3NzaC1yc2E... user@host"
    public init(sshString: String) throws {
        let components = sshString.trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: " ", maxSplits: 2)

        guard components.count >= 2 else {
            throw SSHError.invalidFormat("Expected format: algorithm base64-data [comment]")
        }

        let algorithmString = String(components[0])
        let base64Data = String(components[1])
        let comment = components.count >= 3 ? String(components[2]) : nil

        guard let algorithm = SSHKeyAlgorithm(rawValue: algorithmString) else {
            throw SSHError.unsupportedAlgorithm(algorithmString)
        }

        guard let keyData = Data(base64Encoded: base64Data) else {
            throw SSHError.invalidKeyData("Invalid base64 encoding")
        }

        try self.init(algorithm: algorithm, keyData: keyData, comment: comment)
    }

    /// Parse a public key from raw key data
    public init(algorithm: SSHKeyAlgorithm, keyData: Data, comment: String? = nil) throws {
        self.algorithm = algorithm
        self.comment = comment

        var buffer = SSHBuffer(keyData)

        // Verify algorithm string in key data
        let keyAlgorithm = try buffer.readString()
        guard keyAlgorithm == algorithm.rawValue else {
            throw SSHError.invalidKeyData("Algorithm mismatch: expected \(algorithm.rawValue), got \(keyAlgorithm)")
        }

        switch algorithm.family {
        case .rsa:
            let (key, size) = try Self.parseRSAPublicKey(buffer: &buffer)
            self.keyData = .rsa(key)
            self.keySize = size

        case .ecdsa:
            let (key, size) = try Self.parseECDSAPublicKey(buffer: &buffer, algorithm: algorithm)
            self.keyData = .ecdsa(key)
            self.keySize = size

        case .ed25519:
            let (key, size) = try Self.parseEd25519PublicKey(buffer: &buffer)
            self.keyData = .ed25519(key)
            self.keySize = size
        }
    }

    /// Verify a signature
    public func verify(_ signature: Data, for data: Data) -> Bool {
        switch keyData {
        case .rsa(let secKey):
            return verifyRSASignature(signature, for: data, key: secKey)
        case .ecdsa(let key):
            return verifyECDSASignature(signature, for: data, key: key)
        case .ed25519(let key):
            return verifyEd25519Signature(signature, for: data, key: key)
        }
    }

    public static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return lhs.algorithm == rhs.algorithm && lhs.keyData == rhs.keyData
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(algorithm)
        hasher.combine(keyData)
    }
}

// MARK: - Internal Key Data
internal enum PublicKeyData: Sendable, Hashable {
    #if canImport(Security)
    case rsa(SecKey)
    #endif

    #if canImport(CryptoKit)
    case ecdsa(ECDSAPublicKeyWrapper)
    case ed25519(Curve25519.Signing.PublicKey)
    #endif

    static func == (lhs: PublicKeyData, rhs: PublicKeyData) -> Bool {
        switch (lhs, rhs) {
        case (.rsa(let l), .rsa(let r)):
            // Compare by exported key data
            guard let lData = SecKeyCopyExternalRepresentation(l, nil) as Data?,
                  let rData = SecKeyCopyExternalRepresentation(r, nil) as Data? else {
                return false
            }
            return lData == rData
        case (.ecdsa(let l), .ecdsa(let r)):
            return l == r
        case (.ed25519(let l), .ed25519(let r)):
            return l.rawRepresentation == r.rawRepresentation
        default:
            return false
        }
    }

    func hash(into hasher: inout Hasher) {
        switch self {
        case .rsa(let key):
            if let data = SecKeyCopyExternalRepresentation(key, nil) as Data? {
                hasher.combine(data)
            }
        case .ecdsa(let key):
            hasher.combine(key)
        case .ed25519(let key):
            hasher.combine(key.rawRepresentation)
        }
    }
}

// MARK: - ECDSA Key Wrapper
#if canImport(CryptoKit)
internal enum ECDSAPublicKeyWrapper: Sendable, Hashable {
    case p256(P256.Signing.PublicKey)
    case p384(P384.Signing.PublicKey)
    case p521(P521.Signing.PublicKey)

    var rawRepresentation: Data {
        switch self {
        case .p256(let key): return key.rawRepresentation
        case .p384(let key): return key.rawRepresentation
        case .p521(let key): return key.rawRepresentation
        }
    }

    static func == (lhs: ECDSAPublicKeyWrapper, rhs: ECDSAPublicKeyWrapper) -> Bool {
        return lhs.rawRepresentation == rhs.rawRepresentation
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(rawRepresentation)
    }
}
#endif

// MARK: - RSA Parsing
extension PublicKey {
    #if canImport(Security)
    private static func parseRSAPublicKey(buffer: inout SSHBuffer) throws -> (SecKey, Int) {
        // RSA public key format: e (exponent), n (modulus)
        let exponent = try buffer.readBytes()
        let modulus = try buffer.readBytes()

        // Calculate key size, removing leading zero bytes (used for sign extension)
        let effectiveModulusBytes = modulus.drop(while: { $0 == 0 })
        let keySize = effectiveModulusBytes.count * 8

        // Create DER-encoded RSA public key for Security framework
        let derData = try encodeRSAPublicKeyDER(modulus: modulus, exponent: exponent)

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: keySize
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(derData as CFData, attributes as CFDictionary, &error) else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw SSHError.invalidKeyData("Failed to create RSA key: \(errorMessage)")
        }

        return (secKey, keySize)
    }

    private static func encodeRSAPublicKeyDER(modulus: Data, exponent: Data) throws -> Data {
        var serializer = DER.Serializer()
        try serializer.appendConstructedNode(identifier: .sequence) { serializer in
            // Modulus as INTEGER
            try serializer.serialize(ArraySlice(modulus))
            // Exponent as INTEGER
            try serializer.serialize(ArraySlice(exponent))
        }
        return Data(serializer.serializedBytes)
    }
    #endif
}

// MARK: - ECDSA Parsing
#if canImport(CryptoKit)
extension PublicKey {
    private static func parseECDSAPublicKey(buffer: inout SSHBuffer, algorithm: SSHKeyAlgorithm) throws -> (ECDSAPublicKeyWrapper, Int) {
        // ECDSA public key format: curve name, Q (public point)
        let curveName = try buffer.readString()
        let publicPoint = try buffer.readBytes()

        guard curveName == algorithm.ecdsaCurveName else {
            throw SSHError.invalidKeyData("Curve mismatch: expected \(algorithm.ecdsaCurveName ?? "unknown"), got \(curveName)")
        }

        // The public point starts with 0x04 (uncompressed point format)
        guard publicPoint.first == 0x04 else {
            throw SSHError.invalidKeyData("Expected uncompressed point format (0x04)")
        }

        switch curveName {
        case "nistp256":
            let key = try P256.Signing.PublicKey(x963Representation: publicPoint)
            return (.p256(key), 256)
        case "nistp384":
            let key = try P384.Signing.PublicKey(x963Representation: publicPoint)
            return (.p384(key), 384)
        case "nistp521":
            let key = try P521.Signing.PublicKey(x963Representation: publicPoint)
            return (.p521(key), 521)
        default:
            throw SSHError.unsupportedAlgorithm("Unsupported ECDSA curve: \(curveName)")
        }
    }
}
#endif

// MARK: - Ed25519 Parsing
#if canImport(CryptoKit)
extension PublicKey {
    private static func parseEd25519PublicKey(buffer: inout SSHBuffer) throws -> (Curve25519.Signing.PublicKey, Int) {
        let publicKeyData = try buffer.readBytes()

        guard publicKeyData.count == 32 else {
            throw SSHError.invalidKeyData("Ed25519 public key must be 32 bytes, got \(publicKeyData.count)")
        }

        let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
        return (key, 256)
    }
}
#endif

// MARK: - Signature Verification
extension PublicKey {
    #if canImport(Security)
    private func verifyRSASignature(_ signature: Data, for data: Data, key: SecKey) -> Bool {
        // Determine signature algorithm based on key algorithm
        let secAlgorithm: SecKeyAlgorithm
        switch algorithm {
        case .rsa:
            secAlgorithm = .rsaSignatureMessagePKCS1v15SHA1
        case .rsaSha256:
            secAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
        case .rsaSha512:
            secAlgorithm = .rsaSignatureMessagePKCS1v15SHA512
        default:
            return false
        }

        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(key, secAlgorithm, data as CFData, signature as CFData, &error)
        return result
    }
    #endif

    #if canImport(CryptoKit)
    private func verifyECDSASignature(_ signature: Data, for data: Data, key: ECDSAPublicKeyWrapper) -> Bool {
        // SSH ECDSA signature format: r || s (each as mpint)
        do {
            var buffer = SSHBuffer(signature)
            let r = try buffer.readBytes()
            let s = try buffer.readBytes()

            // Convert to DER format for CryptoKit
            let derSignature = try encodeECDSASignatureDER(r: r, s: s)

            switch key {
            case .p256(let pubKey):
                let sig = try P256.Signing.ECDSASignature(derRepresentation: derSignature)
                return pubKey.isValidSignature(sig, for: SHA256.hash(data: data))
            case .p384(let pubKey):
                let sig = try P384.Signing.ECDSASignature(derRepresentation: derSignature)
                return pubKey.isValidSignature(sig, for: SHA384.hash(data: data))
            case .p521(let pubKey):
                let sig = try P521.Signing.ECDSASignature(derRepresentation: derSignature)
                return pubKey.isValidSignature(sig, for: SHA512.hash(data: data))
            }
        } catch {
            return false
        }
    }

    private func encodeECDSASignatureDER(r: Data, s: Data) throws -> Data {
        var serializer = DER.Serializer()
        try serializer.appendConstructedNode(identifier: .sequence) { serializer in
            try serializer.serialize(ArraySlice(r))
            try serializer.serialize(ArraySlice(s))
        }
        return Data(serializer.serializedBytes)
    }

    private func verifyEd25519Signature(_ signature: Data, for data: Data, key: Curve25519.Signing.PublicKey) -> Bool {
        return key.isValidSignature(signature, for: data)
    }
    #endif
}
