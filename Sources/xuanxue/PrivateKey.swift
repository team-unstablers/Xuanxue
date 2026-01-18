import Foundation
import SwiftASN1
import libbcrypt

#if canImport(Security)
@preconcurrency import Security
#endif

#if canImport(CryptoKit)
import CryptoKit
#endif

#if canImport(CommonCrypto)
import CommonCrypto
#endif

/// SSH Private Key
public struct PrivateKey: @unchecked Sendable {
    /// The key algorithm
    public let algorithm: SSHKeyAlgorithm

    /// The key size in bits
    public let keySize: Int

    /// Optional comment
    public let comment: String?

    /// The corresponding public key
    public let publicKey: PublicKey

    /// Internal key representation
    internal let keyData: PrivateKeyData

    /// OpenSSH private key magic
    private static let opensshMagic = "openssh-key-v1\0"

    /// Parse a private key from OpenSSH format string
    /// - Parameter passphrase: Optional UTF-8 passphrase data for encrypted keys.
    public init(sshString: String, passphrase: Data? = nil) throws {
        let trimmed = sshString.trimmingCharacters(in: .whitespacesAndNewlines)

        if trimmed.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----") {
            try self.init(opensshPEM: trimmed, passphrase: passphrase)
        } else if trimmed.hasPrefix("-----BEGIN RSA PRIVATE KEY-----") ||
                  trimmed.hasPrefix("-----BEGIN EC PRIVATE KEY-----") ||
                  trimmed.hasPrefix("-----BEGIN PRIVATE KEY-----") {
            try self.init(traditionalPEM: trimmed, passphrase: passphrase)
        } else {
            throw SSHError.invalidFormat("Unknown private key format")
        }
    }

    /// Parse an OpenSSH format private key
    private init(opensshPEM: String, passphrase: Data?) throws {
        let lines = opensshPEM.components(separatedBy: .newlines)
            .filter { !$0.hasPrefix("-----") && !$0.isEmpty }
        let base64Content = lines.joined()

        guard let keyData = Data(base64Encoded: base64Content) else {
            throw SSHError.invalidKeyData("Invalid base64 encoding")
        }

        try self.init(opensshData: keyData, passphrase: passphrase)
    }

    /// Parse OpenSSH binary data
    private init(opensshData data: Data, passphrase: Data?) throws {
        var buffer = SSHBuffer(data)

        // Check magic
        let magic = try buffer.readExactBytes(Self.opensshMagic.count)
        guard String(decoding: magic, as: UTF8.self) == Self.opensshMagic else {
            throw SSHError.invalidFormat("Invalid OpenSSH magic")
        }

        // Read header fields
        let cipherName = try buffer.readString()
        let kdfName = try buffer.readString()
        let _ = try buffer.readBytes() // kdfOptions
        let numKeys = try buffer.readUInt32()

        guard numKeys == 1 else {
            throw SSHError.invalidFormat("Multiple keys not supported")
        }

        // Read public key
        let publicKeyData = try buffer.readBytes()
        var encryptedData = try buffer.readBytes()
        defer { Self.zeroize(&encryptedData) }

        // Read KDF options before decryption
        var kdfBuffer = SSHBuffer(Data())

        // Re-read the key to get KDF options properly
        var headerBuffer = SSHBuffer(data)
        _ = try headerBuffer.readExactBytes(Self.opensshMagic.count)
        _ = try headerBuffer.readString() // cipherName
        _ = try headerBuffer.readString() // kdfName
        let kdfOptions = try headerBuffer.readBytes()
        kdfBuffer = SSHBuffer(kdfOptions)

        // Decrypt if needed
        var decryptedData = Data()
        defer { Self.zeroize(&decryptedData) }
        if cipherName == "none" {
            guard kdfName == "none" else {
                throw SSHError.invalidFormat("KDF should be 'none' when cipher is 'none'")
            }
            decryptedData = encryptedData
        } else {
            // Encrypted key requires passphrase
            guard var passphrase = passphrase, !passphrase.isEmpty else {
                throw SSHError.decryptionFailed("Passphrase required for encrypted key")
            }
            defer { Self.zeroize(&passphrase) }

            // Parse KDF options
            guard kdfName == "bcrypt" else {
                throw SSHError.unsupportedCipher("Unsupported KDF: \(kdfName)")
            }

            let salt = try kdfBuffer.readBytes()
            let rounds = try kdfBuffer.readUInt32()

            // Determine cipher parameters
            let (keyLen, ivLen, blockSize) = try Self.cipherParams(cipherName)

            // Derive key using bcrypt_pbkdf
            var derivedKey = [UInt8](repeating: 0, count: keyLen + ivLen)
            defer { Self.zeroize(&derivedKey) }
            let result: Int32 = passphrase.withUnsafeBytes { passPtr in
                guard let passBase = passPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return -1
                }
                return salt.withUnsafeBytes { saltPtr in
                    guard let saltBase = saltPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                        return -1
                    }
                    return bcrypt_pbkdf(
                        passBase,
                        passphrase.count,
                        saltBase,
                        salt.count,
                        &derivedKey,
                        keyLen + ivLen,
                        rounds
                    )
                }
            }

            guard result == 0 else {
                throw SSHError.decryptionFailed("bcrypt_pbkdf failed")
            }

            var key = Data(derivedKey[0..<keyLen])
            var iv = Data(derivedKey[keyLen..<(keyLen + ivLen)])
            defer {
                Self.zeroize(&key)
                Self.zeroize(&iv)
            }

            // Decrypt using AES
            decryptedData = try Self.decryptAES(encryptedData, key: key, iv: iv, cipher: cipherName, blockSize: blockSize)
        }

        // Parse decrypted private key
        try self.init(decryptedData: decryptedData, publicKeyData: publicKeyData)
    }

    /// Parse decrypted private key data
    private init(decryptedData: Data, publicKeyData: Data) throws {
        var buffer = SSHBuffer(decryptedData)

        // Check random values (verify decryption)
        let checkInt1 = try buffer.readUInt32()
        let checkInt2 = try buffer.readUInt32()

        guard checkInt1 == checkInt2 else {
            throw SSHError.incorrectPassphrase
        }

        // Read key type
        let keyType = try buffer.readString()
        guard let algorithm = SSHKeyAlgorithm(rawValue: keyType) else {
            throw SSHError.unsupportedAlgorithm(keyType)
        }

        self.algorithm = algorithm

        // Parse key based on algorithm
        switch algorithm.family {
        case .rsa:
            let (privateKey, publicKey, size) = try Self.parseRSAPrivateKey(buffer: &buffer)
            self.keyData = .rsa(privateKey)
            self.publicKey = publicKey
            self.keySize = size

        case .ecdsa:
            let (privateKey, publicKey, size) = try Self.parseECDSAPrivateKey(buffer: &buffer, algorithm: algorithm)
            self.keyData = .ecdsa(privateKey)
            self.publicKey = publicKey
            self.keySize = size

        case .ed25519:
            let (privateKey, publicKey, size) = try Self.parseEd25519PrivateKey(buffer: &buffer)
            self.keyData = .ed25519(privateKey)
            self.publicKey = publicKey
            self.keySize = size
        }

        // Read comment
        self.comment = try? buffer.readString()
    }

    /// Parse a traditional PEM private key
    private init(traditionalPEM: String, passphrase: Data?) throws {
        let document = try PEMDocument(pemString: traditionalPEM)

        switch document.discriminator {
        case "RSA PRIVATE KEY":
            try self.init(pkcs1RSAData: Data(document.derBytes), passphrase: passphrase)
        case "EC PRIVATE KEY":
            try self.init(sec1ECData: Data(document.derBytes), passphrase: passphrase)
        case "PRIVATE KEY":
            try self.init(pkcs8Data: Data(document.derBytes), passphrase: passphrase)
        default:
            throw SSHError.invalidFormat("Unknown PEM type: \(document.discriminator)")
        }
    }

    /// Sign data
    public func sign(_ data: Data) -> Data {
        switch keyData {
        case .rsa(let key):
            return signRSA(data, key: key)
        case .ecdsa(let key):
            return signECDSA(data, key: key)
        case .ed25519(let key):
            return signEd25519(data, key: key)
        }
    }
}

// MARK: - Internal Key Data
internal enum PrivateKeyData: @unchecked Sendable {
    #if canImport(Security)
    case rsa(SecKey)
    #endif

    #if canImport(CryptoKit)
    case ecdsa(ECDSAPrivateKeyWrapper)
    case ed25519(Curve25519.Signing.PrivateKey)
    #endif
}

// MARK: - ECDSA Private Key Wrapper
#if canImport(CryptoKit)
internal enum ECDSAPrivateKeyWrapper: Sendable {
    case p256(P256.Signing.PrivateKey)
    case p384(P384.Signing.PrivateKey)
    case p521(P521.Signing.PrivateKey)
}
#endif

// MARK: - RSA Key Parsing
extension PrivateKey {
    #if canImport(Security)
    private static func parseRSAPrivateKey(buffer: inout SSHBuffer) throws -> (SecKey, PublicKey, Int) {
        // OpenSSH RSA private key format:
        // n (modulus), e (exponent), d (private exponent),
        // iqmp (coefficient), p (prime1), q (prime2)
        let n = try buffer.readBytes()
        let e = try buffer.readBytes()
        var d = try buffer.readBytes()
        var iqmp = try buffer.readBytes()
        var p = try buffer.readBytes()
        var q = try buffer.readBytes()
        defer {
            Self.zeroize(&d)
            Self.zeroize(&iqmp)
            Self.zeroize(&p)
            Self.zeroize(&q)
        }

        // Calculate key size, removing leading zero bytes (used for sign extension)
        let effectiveModulusBytes = n.drop(while: { $0 == 0 })
        let keySize = effectiveModulusBytes.count * 8

        // Create PKCS#1 DER for private key
        var derData = try encodeRSAPrivateKeyDER(n: n, e: e, d: d, p: p, q: q, iqmp: iqmp)
        defer { Self.zeroize(&derData) }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: keySize
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(derData as CFData, attributes as CFDictionary, &error) else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw SSHError.invalidKeyData("Failed to create RSA private key: \(errorMessage)")
        }

        // Create public key
        let publicKeyData = createSSHPublicKeyData(algorithm: .rsa, n: n, e: e)
        let publicKey = try PublicKey(algorithm: .rsa, keyData: publicKeyData)

        return (secKey, publicKey, keySize)
    }

    private static func encodeRSAPrivateKeyDER(n: Data, e: Data, d: Data, p: Data, q: Data, iqmp: Data) throws -> Data {
        // Calculate dp = d mod (p-1), dq = d mod (q-1)
        var pMinus1 = BigIntOps.subtractOne(p)
        var qMinus1 = BigIntOps.subtractOne(q)
        var dp = BigIntOps.modulo(d, pMinus1)
        var dq = BigIntOps.modulo(d, qMinus1)
        defer {
            Self.zeroize(&pMinus1)
            Self.zeroize(&qMinus1)
            Self.zeroize(&dp)
            Self.zeroize(&dq)
        }

        // For Security framework, we need PKCS#1 RSAPrivateKey format
        var serializer = DER.Serializer()
        try serializer.appendConstructedNode(identifier: .sequence) { serializer in
            // Version (0 for two-prime RSA)
            try serializer.serialize(ArraySlice<UInt8>([0]))
            // n (modulus)
            try serializer.serialize(ArraySlice(n))
            // e (public exponent)
            try serializer.serialize(ArraySlice(e))
            // d (private exponent)
            try serializer.serialize(ArraySlice(d))
            // p (prime1)
            try serializer.serialize(ArraySlice(p))
            // q (prime2)
            try serializer.serialize(ArraySlice(q))
            // dp = d mod (p-1)
            try serializer.serialize(ArraySlice(dp))
            // dq = d mod (q-1)
            try serializer.serialize(ArraySlice(dq))
            // qInv (coefficient) = iqmp
            try serializer.serialize(ArraySlice(iqmp))
        }

        return Data(serializer.serializedBytes)
    }

    private static func createSSHPublicKeyData(algorithm: SSHKeyAlgorithm, n: Data, e: Data) -> Data {
        var writer = SSHBufferWriter()
        writer.writeString(algorithm.rawValue)
        writer.writeBytes(e)
        writer.writeBytes(n)
        return writer.toData()
    }
    #endif
}

// MARK: - ECDSA Key Parsing
#if canImport(CryptoKit)
extension PrivateKey {
    private static func parseECDSAPrivateKey(buffer: inout SSHBuffer, algorithm: SSHKeyAlgorithm) throws -> (ECDSAPrivateKeyWrapper, PublicKey, Int) {
        // OpenSSH ECDSA private key format:
        // curve name, public point (Q), private scalar (d)
        let curveName = try buffer.readString()
        let publicPoint = try buffer.readBytes()
        var privateScalar = try buffer.readBytes()
        defer { Self.zeroize(&privateScalar) }

        guard curveName == algorithm.ecdsaCurveName else {
            throw SSHError.invalidKeyData("Curve mismatch")
        }

        let privateKey: ECDSAPrivateKeyWrapper
        let keySize: Int

        switch curveName {
        case "nistp256":
            let key = try P256.Signing.PrivateKey(rawRepresentation: privateScalar)
            privateKey = .p256(key)
            keySize = 256
        case "nistp384":
            let key = try P384.Signing.PrivateKey(rawRepresentation: privateScalar)
            privateKey = .p384(key)
            keySize = 384
        case "nistp521":
            let key = try P521.Signing.PrivateKey(rawRepresentation: privateScalar)
            privateKey = .p521(key)
            keySize = 521
        default:
            throw SSHError.unsupportedAlgorithm("Unsupported ECDSA curve: \(curveName)")
        }

        // Create public key data
        let publicKeyData = createSSHECDSAPublicKeyData(algorithm: algorithm, curveName: curveName, publicPoint: publicPoint)
        let publicKey = try PublicKey(algorithm: algorithm, keyData: publicKeyData)

        return (privateKey, publicKey, keySize)
    }

    private static func createSSHECDSAPublicKeyData(algorithm: SSHKeyAlgorithm, curveName: String, publicPoint: Data) -> Data {
        var writer = SSHBufferWriter()
        writer.writeString(algorithm.rawValue)
        writer.writeString(curveName)
        writer.writeBytes(publicPoint)
        return writer.toData()
    }
}
#endif

// MARK: - Ed25519 Key Parsing
#if canImport(CryptoKit)
extension PrivateKey {
    private static func parseEd25519PrivateKey(buffer: inout SSHBuffer) throws -> (Curve25519.Signing.PrivateKey, PublicKey, Int) {
        // OpenSSH Ed25519 private key format:
        // public key (32 bytes), private key (64 bytes = private + public)
        let publicKeyBytes = try buffer.readBytes()
        var privateKeyBytes = try buffer.readBytes()
        defer { Self.zeroize(&privateKeyBytes) }

        guard publicKeyBytes.count == 32 else {
            throw SSHError.invalidKeyData("Ed25519 public key must be 32 bytes")
        }

        guard privateKeyBytes.count == 64 else {
            throw SSHError.invalidKeyData("Ed25519 private key must be 64 bytes")
        }

        // The first 32 bytes of privateKeyBytes is the actual private seed
        var privateSeed = Data(privateKeyBytes.prefix(32))
        defer { Self.zeroize(&privateSeed) }
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateSeed)

        // Create public key data
        let publicKeyData = createSSHEd25519PublicKeyData(publicKeyBytes: publicKeyBytes)
        let publicKey = try PublicKey(algorithm: .ed25519, keyData: publicKeyData)

        return (privateKey, publicKey, 256)
    }

    private static func createSSHEd25519PublicKeyData(publicKeyBytes: Data) -> Data {
        var writer = SSHBufferWriter()
        writer.writeString(SSHKeyAlgorithm.ed25519.rawValue)
        writer.writeBytes(publicKeyBytes)
        return writer.toData()
    }
}
#endif

// MARK: - Signing
extension PrivateKey {
    #if canImport(Security)
    private func signRSA(_ data: Data, key: SecKey) -> Data {
        let secAlgorithm: SecKeyAlgorithm
        switch algorithm {
        case .rsa:
            secAlgorithm = .rsaSignatureMessagePKCS1v15SHA1
        case .rsaSha256:
            secAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
        case .rsaSha512:
            secAlgorithm = .rsaSignatureMessagePKCS1v15SHA512
        default:
            return Data()
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, secAlgorithm, data as CFData, &error) else {
            return Data()
        }

        return signature as Data
    }
    #endif

    #if canImport(CryptoKit)
    private func signECDSA(_ data: Data, key: ECDSAPrivateKeyWrapper) -> Data {
        do {
            let derSignature: Data
            switch key {
            case .p256(let privKey):
                let sig = try privKey.signature(for: SHA256.hash(data: data))
                derSignature = sig.derRepresentation
            case .p384(let privKey):
                let sig = try privKey.signature(for: SHA384.hash(data: data))
                derSignature = sig.derRepresentation
            case .p521(let privKey):
                let sig = try privKey.signature(for: SHA512.hash(data: data))
                derSignature = sig.derRepresentation
            }

            // Convert DER to SSH format (r || s as mpints)
            return try convertECDSADERToSSH(derSignature)
        } catch {
            return Data()
        }
    }

    private func convertECDSADERToSSH(_ der: Data) throws -> Data {
        // Parse DER SEQUENCE containing two INTEGERs (r and s)
        let parsed = try DER.parse(Array(der))

        guard case .constructed(let nodes) = parsed.content else {
            throw SSHError.invalidSignature
        }

        var r = Data()
        var s = Data()
        var count = 0

        for node in nodes {
            if case .primitive(let bytes) = node.content {
                if count == 0 {
                    r = Data(bytes)
                } else if count == 1 {
                    s = Data(bytes)
                }
                count += 1
            }
        }

        var writer = SSHBufferWriter()
        writer.writeBytes(r)
        writer.writeBytes(s)
        return writer.toData()
    }

    private func signEd25519(_ data: Data, key: Curve25519.Signing.PrivateKey) -> Data {
        do {
            return try key.signature(for: data)
        } catch {
            return Data()
        }
    }
    #endif
}

// MARK: - PEM Parsing (Traditional formats)
extension PrivateKey {
    private init(pkcs1RSAData: Data, passphrase: Data?) throws {
        #if canImport(Security)
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(pkcs1RSAData as CFData, attributes as CFDictionary, &error) else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw SSHError.invalidKeyData("Failed to create RSA private key: \(errorMessage)")
        }

        guard let keyAttributes = SecKeyCopyAttributes(secKey) as? [String: Any],
              let keySize = keyAttributes[kSecAttrKeySizeInBits as String] as? Int else {
            throw SSHError.invalidKeyData("Cannot determine key size")
        }

        self.algorithm = .rsa
        self.keySize = keySize
        self.keyData = .rsa(secKey)
        self.comment = nil

        // Create public key from private key
        guard let publicSecKey = SecKeyCopyPublicKey(secKey) else {
            throw SSHError.invalidKeyData("Cannot extract public key")
        }

        guard let publicKeyDER = SecKeyCopyExternalRepresentation(publicSecKey, nil) as Data? else {
            throw SSHError.invalidKeyData("Cannot export public key")
        }

        let (n, e) = try Self.parseRSAPublicKeyDER(publicKeyDER)
        let sshPublicKeyData = Self.createSSHPublicKeyData(algorithm: .rsa, n: n, e: e)
        self.publicKey = try PublicKey(algorithm: .rsa, keyData: sshPublicKeyData)
        #else
        throw SSHError.unsupportedAlgorithm("RSA not supported on this platform")
        #endif
    }

    #if canImport(Security)
    private static func parseRSAPublicKeyDER(_ der: Data) throws -> (n: Data, e: Data) {
        let parsed = try DER.parse(Array(der))

        guard case .constructed(let nodes) = parsed.content else {
            throw SSHError.invalidKeyData("Expected SEQUENCE for RSA public key")
        }

        var n = Data()
        var e = Data()
        var count = 0

        for node in nodes {
            if case .primitive(let bytes) = node.content {
                if count == 0 {
                    n = Data(bytes)
                } else if count == 1 {
                    e = Data(bytes)
                }
                count += 1
            }
        }

        guard !n.isEmpty && !e.isEmpty else {
            throw SSHError.invalidKeyData("Failed to parse RSA public key components")
        }

        return (n, e)
    }
    #endif

    private init(sec1ECData: Data, passphrase: Data?) throws {
        #if canImport(CryptoKit)
        // Try each curve size
        if let key = try? P256.Signing.PrivateKey(derRepresentation: sec1ECData) {
            self.algorithm = .ecdsaSha2Nistp256
            self.keySize = 256
            self.keyData = .ecdsa(.p256(key))
            self.comment = nil

            let publicKeyData = Self.createSSHECDSAPublicKeyData(
                algorithm: .ecdsaSha2Nistp256,
                curveName: "nistp256",
                publicPoint: Data([0x04]) + key.publicKey.rawRepresentation
            )
            self.publicKey = try PublicKey(algorithm: .ecdsaSha2Nistp256, keyData: publicKeyData)
            return
        }

        if let key = try? P384.Signing.PrivateKey(derRepresentation: sec1ECData) {
            self.algorithm = .ecdsaSha2Nistp384
            self.keySize = 384
            self.keyData = .ecdsa(.p384(key))
            self.comment = nil

            let publicKeyData = Self.createSSHECDSAPublicKeyData(
                algorithm: .ecdsaSha2Nistp384,
                curveName: "nistp384",
                publicPoint: Data([0x04]) + key.publicKey.rawRepresentation
            )
            self.publicKey = try PublicKey(algorithm: .ecdsaSha2Nistp384, keyData: publicKeyData)
            return
        }

        if let key = try? P521.Signing.PrivateKey(derRepresentation: sec1ECData) {
            self.algorithm = .ecdsaSha2Nistp521
            self.keySize = 521
            self.keyData = .ecdsa(.p521(key))
            self.comment = nil

            let publicKeyData = Self.createSSHECDSAPublicKeyData(
                algorithm: .ecdsaSha2Nistp521,
                curveName: "nistp521",
                publicPoint: Data([0x04]) + key.publicKey.rawRepresentation
            )
            self.publicKey = try PublicKey(algorithm: .ecdsaSha2Nistp521, keyData: publicKeyData)
            return
        }

        throw SSHError.invalidKeyData("Failed to parse SEC1 EC private key")
        #else
        throw SSHError.unsupportedAlgorithm("ECDSA not supported on this platform")
        #endif
    }

    private init(pkcs8Data: Data, passphrase: Data?) throws {
        // PKCS#8 can contain RSA, ECDSA, or Ed25519 keys
        #if canImport(CryptoKit)
        // Try ECDSA P256
        if let key = try? P256.Signing.PrivateKey(derRepresentation: pkcs8Data) {
            self.algorithm = .ecdsaSha2Nistp256
            self.keySize = 256
            self.keyData = .ecdsa(.p256(key))
            self.comment = nil

            let publicKeyData = Self.createSSHECDSAPublicKeyData(
                algorithm: .ecdsaSha2Nistp256,
                curveName: "nistp256",
                publicPoint: Data([0x04]) + key.publicKey.rawRepresentation
            )
            self.publicKey = try PublicKey(algorithm: .ecdsaSha2Nistp256, keyData: publicKeyData)
            return
        }
        #endif

        #if canImport(Security)
        // Try RSA
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ]

        var error: Unmanaged<CFError>?
        if let secKey = SecKeyCreateWithData(pkcs8Data as CFData, attributes as CFDictionary, &error) {
            guard let keyAttributes = SecKeyCopyAttributes(secKey) as? [String: Any],
                  let keySize = keyAttributes[kSecAttrKeySizeInBits as String] as? Int else {
                throw SSHError.invalidKeyData("Cannot determine key size")
            }

            self.algorithm = .rsa
            self.keySize = keySize
            self.keyData = .rsa(secKey)
            self.comment = nil

            guard let publicSecKey = SecKeyCopyPublicKey(secKey) else {
                throw SSHError.invalidKeyData("Cannot extract public key")
            }

            guard let publicKeyDER = SecKeyCopyExternalRepresentation(publicSecKey, nil) as Data? else {
                throw SSHError.invalidKeyData("Cannot export public key")
            }

            let (n, e) = try Self.parseRSAPublicKeyDER(publicKeyDER)
            let sshPublicKeyData = Self.createSSHPublicKeyData(algorithm: .rsa, n: n, e: e)
            self.publicKey = try PublicKey(algorithm: .rsa, keyData: sshPublicKeyData)
            return
        }
        #endif

        throw SSHError.invalidKeyData("Failed to parse PKCS#8 private key")
    }
}

// MARK: - Key Generation
extension PrivateKey {
    /// Generate a new RSA key pair
    /// - Parameters:
    ///   - keySize: The key size in bits (2048, 3072, or 4096)
    ///   - comment: Optional comment for the key
    /// - Returns: A new RSA private key
    public static func generateRSA(keySize: Int = 2048, comment: String? = nil) throws -> PrivateKey {
        #if canImport(Security)
        guard [2048, 3072, 4096].contains(keySize) else {
            throw SSHError.invalidKeyData("RSA key size must be 2048, 3072, or 4096 bits")
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: keySize
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw SSHError.invalidKeyData("Failed to generate RSA key: \(errorMessage)")
        }

        // Extract public key
        guard let publicSecKey = SecKeyCopyPublicKey(secKey) else {
            throw SSHError.invalidKeyData("Cannot extract public key from generated key")
        }

        guard let publicKeyDER = SecKeyCopyExternalRepresentation(publicSecKey, nil) as Data? else {
            throw SSHError.invalidKeyData("Cannot export public key")
        }

        // Parse n and e from public key DER
        let (n, e) = try parseRSAPublicKeyDER(publicKeyDER)

        // Create SSH public key data
        let sshPublicKeyData = createSSHPublicKeyData(algorithm: .rsa, n: n, e: e)
        let publicKey = try PublicKey(algorithm: .rsa, keyData: sshPublicKeyData, comment: comment)

        return PrivateKey(
            algorithm: .rsa,
            keySize: keySize,
            comment: comment,
            publicKey: publicKey,
            keyData: .rsa(secKey)
        )
        #else
        throw SSHError.unsupportedAlgorithm("RSA key generation not supported on this platform")
        #endif
    }

    /// Generate a new ECDSA key pair
    /// - Parameters:
    ///   - curve: The ECDSA curve (nistp256, nistp384, or nistp521)
    ///   - comment: Optional comment for the key
    /// - Returns: A new ECDSA private key
    public static func generateECDSA(curve: ECDSACurve = .p256, comment: String? = nil) throws -> PrivateKey {
        #if canImport(CryptoKit)
        let privateKeyWrapper: ECDSAPrivateKeyWrapper
        let algorithm: SSHKeyAlgorithm
        let keySize: Int
        let curveName: String
        let publicPoint: Data

        switch curve {
        case .p256:
            let key = P256.Signing.PrivateKey()
            privateKeyWrapper = .p256(key)
            algorithm = .ecdsaSha2Nistp256
            keySize = 256
            curveName = "nistp256"
            publicPoint = Data([0x04]) + key.publicKey.rawRepresentation

        case .p384:
            let key = P384.Signing.PrivateKey()
            privateKeyWrapper = .p384(key)
            algorithm = .ecdsaSha2Nistp384
            keySize = 384
            curveName = "nistp384"
            publicPoint = Data([0x04]) + key.publicKey.rawRepresentation

        case .p521:
            let key = P521.Signing.PrivateKey()
            privateKeyWrapper = .p521(key)
            algorithm = .ecdsaSha2Nistp521
            keySize = 521
            curveName = "nistp521"
            publicPoint = Data([0x04]) + key.publicKey.rawRepresentation
        }

        // Create SSH public key data
        let sshPublicKeyData = createSSHECDSAPublicKeyData(
            algorithm: algorithm,
            curveName: curveName,
            publicPoint: publicPoint
        )
        let publicKey = try PublicKey(algorithm: algorithm, keyData: sshPublicKeyData, comment: comment)

        return PrivateKey(
            algorithm: algorithm,
            keySize: keySize,
            comment: comment,
            publicKey: publicKey,
            keyData: .ecdsa(privateKeyWrapper)
        )
        #else
        throw SSHError.unsupportedAlgorithm("ECDSA key generation not supported on this platform")
        #endif
    }

    /// Generate a new Ed25519 key pair
    /// - Parameters:
    ///   - comment: Optional comment for the key
    /// - Returns: A new Ed25519 private key
    public static func generateEd25519(comment: String? = nil) throws -> PrivateKey {
        #if canImport(CryptoKit)
        let key = Curve25519.Signing.PrivateKey()

        // Create SSH public key data
        let sshPublicKeyData = createSSHEd25519PublicKeyData(publicKeyBytes: key.publicKey.rawRepresentation)
        let publicKey = try PublicKey(algorithm: .ed25519, keyData: sshPublicKeyData, comment: comment)

        return PrivateKey(
            algorithm: .ed25519,
            keySize: 256,
            comment: comment,
            publicKey: publicKey,
            keyData: .ed25519(key)
        )
        #else
        throw SSHError.unsupportedAlgorithm("Ed25519 key generation not supported on this platform")
        #endif
    }

    /// Internal initializer for key generation
    private init(algorithm: SSHKeyAlgorithm, keySize: Int, comment: String?, publicKey: PublicKey, keyData: PrivateKeyData) {
        self.algorithm = algorithm
        self.keySize = keySize
        self.comment = comment
        self.publicKey = publicKey
        self.keyData = keyData
    }
}

/// ECDSA curve types for key generation
public enum ECDSACurve: Sendable {
    case p256
    case p384
    case p521
}

// MARK: - Zeroization
extension PrivateKey {
    private static func zeroize(_ data: inout Data) {
        guard !data.isEmpty else { return }
        data.resetBytes(in: 0..<data.count)
    }

    private static func zeroize(_ bytes: inout [UInt8]) {
        guard !bytes.isEmpty else { return }
        for index in bytes.indices {
            bytes[index] = 0
        }
    }
}

// MARK: - Encryption Helpers
extension PrivateKey {
    /// Get cipher parameters: (key length, IV length, block size)
    private static func cipherParams(_ cipher: String) throws -> (Int, Int, Int) {
        switch cipher {
        case "aes256-ctr":
            return (32, 16, 16)  // AES-256, IV=16, block=16
        case "aes256-cbc":
            return (32, 16, 16)
        case "aes128-ctr":
            return (16, 16, 16)
        case "aes128-cbc":
            return (16, 16, 16)
        case "aes192-ctr":
            return (24, 16, 16)
        case "aes192-cbc":
            return (24, 16, 16)
        default:
            throw SSHError.unsupportedCipher("Unsupported cipher: \(cipher)")
        }
    }

    #if canImport(CommonCrypto)
    /// Decrypt data using AES
    private static func decryptAES(_ data: Data, key: Data, iv: Data, cipher: String, blockSize: Int) throws -> Data {
        let isCTR = cipher.hasSuffix("-ctr")

        if isCTR {
            // CTR mode - manual implementation using ECB
            return try decryptAESCTR(data, key: key, iv: iv)
        } else {
            // CBC mode
            return try decryptAESCBC(data, key: key, iv: iv)
        }
    }

    /// Decrypt using AES-CBC
    private static func decryptAESCBC(_ data: Data, key: Data, iv: Data) throws -> Data {
        var outputBuffer = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
        var numBytesDecrypted: size_t = 0
        defer { Self.zeroize(&outputBuffer) }

        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                data.withUnsafeBytes { dataBytes in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(0), // No padding - OpenSSH handles its own padding
                        keyBytes.baseAddress, key.count,
                        ivBytes.baseAddress,
                        dataBytes.baseAddress, data.count,
                        &outputBuffer, outputBuffer.count,
                        &numBytesDecrypted
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw SSHError.decryptionFailed("AES-CBC decryption failed: \(status)")
        }

        return Data(outputBuffer.prefix(numBytesDecrypted))
    }

    /// Decrypt using AES-CTR (counter mode)
    private static func decryptAESCTR(_ data: Data, key: Data, iv: Data) throws -> Data {
        var counter = [UInt8](iv)
        var result = Data()
        let blockSize = 16
        defer { Self.zeroize(&counter) }

        for blockStart in stride(from: 0, to: data.count, by: blockSize) {
            let blockEnd = min(blockStart + blockSize, data.count)
            let block = data[blockStart..<blockEnd]

            // Encrypt the counter to get the keystream
            var keystream = [UInt8](repeating: 0, count: blockSize + kCCBlockSizeAES128)
            var numBytesEncrypted: size_t = 0

            let status = key.withUnsafeBytes { keyBytes in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionECBMode),
                    keyBytes.baseAddress, key.count,
                    nil,
                    &counter, blockSize,
                    &keystream, keystream.count,
                    &numBytesEncrypted
                )
            }

            guard status == kCCSuccess else {
                throw SSHError.decryptionFailed("AES-CTR encryption failed: \(status)")
            }

            // XOR block with keystream
            for (i, byte) in block.enumerated() {
                result.append(byte ^ keystream[i])
            }
            Self.zeroize(&keystream)

            // Increment counter (big-endian)
            for i in (0..<blockSize).reversed() {
                counter[i] = counter[i] &+ 1
                if counter[i] != 0 {
                    break
                }
            }
        }

        return result
    }
    #endif
}
