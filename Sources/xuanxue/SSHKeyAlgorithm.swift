import Foundation

/// SSH key algorithm types
public enum SSHKeyAlgorithm: String, Sendable, Hashable {
    /// EdDSA (Ed25519)
    case ed25519 = "ssh-ed25519"

    /// ECDSA
    case ecdsaSha2Nistp256 = "ecdsa-sha2-nistp256"
    case ecdsaSha2Nistp384 = "ecdsa-sha2-nistp384"
    case ecdsaSha2Nistp521 = "ecdsa-sha2-nistp521"

    /// RSA (ssh-rsa uses SHA-1 for signatures)
    case rsa = "ssh-rsa"
    case rsaSha256 = "rsa-sha2-256"
    case rsaSha512 = "rsa-sha2-512"

    /// Returns the base algorithm family
    public var family: SSHKeyFamily {
        switch self {
        case .ed25519:
            return .ed25519
        case .ecdsaSha2Nistp256, .ecdsaSha2Nistp384, .ecdsaSha2Nistp521:
            return .ecdsa
        case .rsa, .rsaSha256, .rsaSha512:
            return .rsa
        }
    }

    /// ECDSA curve name for this algorithm, if applicable
    public var ecdsaCurveName: String? {
        switch self {
        case .ecdsaSha2Nistp256:
            return "nistp256"
        case .ecdsaSha2Nistp384:
            return "nistp384"
        case .ecdsaSha2Nistp521:
            return "nistp521"
        default:
            return nil
        }
    }
}

/// SSH key algorithm family
public enum SSHKeyFamily: String, Sendable, Hashable {
    case rsa
    case ecdsa
    case ed25519
}
