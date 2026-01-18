import Testing
import Foundation
import SwiftASN1
@testable import xuanxue

// MARK: - Test Keys
struct TestKeys {
    static let rsaPublicKey = """
        ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwyKFONMj13fcjN7gf+kkmkqmoFLS/nbmHRknVzMYdgHG53MCfUZZUuWHPobQPnt1fIISTjjkhE/RPgEN36bssgNgFzjbdcf7ybDAmfCkBLRPZuoQDGT2w1g5kkDVzvA27aa35AtUZXNihd49OEISCyH/z5l/0myI5JNBSVPuX2vY1pmk9o21adO3+wFpCjsTnpJQDTTvxg9pJNUlmg0Bf9PKM+cr5T7ikLnBNsNRRFrwJyVqbIaimt05Sv4KNTaiUhuibpX8aQd/eJyXstGk5u9bK/hrAKAxHZJBWtlZWbhGAWQsucdAEvbUqTru2EgZpnQ6W+IzUO01L2Qcsw4mp cheesekun@cheese-mbpr14
        """

    static let rsaPrivateKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
        NhAAAAAwEAAQAAAQEAsMihTjTI9d33Ize4H/pJJpKpqBS0v525h0ZJ1czGHYBxudzAn1GW
        VLlhz6G0D57dXyCEk445IRP0T4BDd+m7LIDYBc423XH+8mwwJnwpAS0T2bqEAxk9sNYOZJ
        A1c7wNu2mt+QLVGVzYoXePThCEgsh/8+Zf9JsiOSTQUlT7l9r2NaZpPaNtWnTt/sBaQo7E
        56SUA0078YPaSTVJZoNAX/TyjPnK+U+4pC5wTbDUURa8CclamyGoprdOUr+CjU2olIbom6
        V/GkHf3icl7LRpObvWyv4awCgMR2SQVrZWVm4RgFkLLnHQBL21Kk67thIGaZ0OlviM1DtN
        S9kHLMOJqQAAA9B3kNi3d5DYtwAAAAdzc2gtcnNhAAABAQCwyKFONMj13fcjN7gf+kkmkq
        moFLS/nbmHRknVzMYdgHG53MCfUZZUuWHPobQPnt1fIISTjjkhE/RPgEN36bssgNgFzjbd
        cf7ybDAmfCkBLRPZuoQDGT2w1g5kkDVzvA27aa35AtUZXNihd49OEISCyH/z5l/0myI5JN
        BSVPuX2vY1pmk9o21adO3+wFpCjsTnpJQDTTvxg9pJNUlmg0Bf9PKM+cr5T7ikLnBNsNRR
        FrwJyVqbIaimt05Sv4KNTaiUhuibpX8aQd/eJyXstGk5u9bK/hrAKAxHZJBWtlZWbhGAWQ
        sucdAEvbUqTru2EgZpnQ6W+IzUO01L2Qcsw4mpAAAAAwEAAQAAAQAnb9psM+JQ1v9238s3
        dwIylK08TcI0rN7iio+WHmRj2G+GYvSllfHPXLuxMgWVJn+D5SEuOaAM/QKXaamjaoTS3L
        tUMDiVFgUl13S2YSRUmtW+0Jj6h/r3JAl57aG++8ikcmLZFgSr78Zz3tQdOhoVgtzocBAf
        5SuxS8EdXM/zhAoBaINZk53bCNyTLpWoWQSdKaF8l1Sc/sX+Xr7WGPJvY/z+g8KSYSgvQf
        VG29gCp8/+Qq3j7ErLyPSYZW21e3YO80OKIDkxBD0VMabUidAQzgA7v/NFBfdQMLonLnM+
        kfT1sjcdBiUkhXbWlZCn7+5lpBDlKlZ0mscbU3emYkgBAAAAgH1iSkUsWFV7Z+3OSd0gsa
        vzCDHTMvYNmNT3pxf17Pm7thsNPPGTsRAepavKNaqKKlUY2DMraMJvUtQ0/uL4AImTOcUf
        S9KBRCK/9jnjAamp+Qo2dkz9GDQCYXQN+kjHsR8aqrxTGrR8/04QHY2ZTCswIx34Q7Dl2Y
        MiptAtXxStAAAAgQDnSah2osVccqGiIktLICHY//UA5E9OdLKshRK8aEJUTghrXmx3mdGB
        N09A52Cx5nhm7jaGp3czVHtodJN84N59Z0r8ipRr6MRjN9uN/rw2FtsWRZG8ngvVgY2eLf
        jaCEV7u/n/54MjgG/dAgpC3Eh6avYi62TMPYrKujKLJ86WwQAAAIEAw6wj93iirmGmMl2O
        v93g5IM1Kqalp6akcLSSqlNbdVgz5KSO2PlO0ui8pUOxcPVxY8ewCEwE+Ub2M09At6q7l2
        r8s5bZZ4BC5VX6+c8ACKVCF0V4/gUXcf1hp/y+bHVKWmDbfihfVP0mNlyUwJ3SZrSTVbDX
        +pnjyP5PF1aFVOkAAAAXY2hlZXNla3VuQGNoZWVzZS1tYnByMTQBAgME
        -----END OPENSSH PRIVATE KEY-----
        """

    static let ed25519PublicKey = """
        ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGu+15tPSzPZLQXuNt/ItyuNRCRAuJw8KIGFvoAW8Mz7 cheesekun@cheese-mbpr14
        """

    static let ed25519PrivateKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACBrvtebT0sz2S0F7jbfyLcrjUQkQLicPCiBhb6AFvDM+wAAAKBy29bsctvW
        7AAAAAtzc2gtZWQyNTUxOQAAACBrvtebT0sz2S0F7jbfyLcrjUQkQLicPCiBhb6AFvDM+w
        AAAEBIkEcYfwhXpLkcxuYM5spXXxrqcyA6+sG3MtqsZtZQymu+15tPSzPZLQXuNt/ItyuN
        RCRAuJw8KIGFvoAW8Mz7AAAAF2NoZWVzZWt1bkBjaGVlc2UtbWJwcjE0AQIDBAUG
        -----END OPENSSH PRIVATE KEY-----
        """

    static let ecdsaP256PublicKey = """
        ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKPdECxPZoK9RURpky5iFStlbSkhDKcQELvd9tto7oZCpoPXWMjvQnYo6Ar7C+5K9sR6E6CH1AnRp2TQ0DuZ2a8= cheesekun@cheese-mbpr14
        """

    static let ecdsaP256PrivateKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
        1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSj3RAsT2aCvUVEaZMuYhUrZW0pIQyn
        EBC73fbbaO6GQqaD11jI70J2KOgK+wvuSvbEehOgh9QJ0adk0NA7mdmvAAAAsG9rHOhvax
        zoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKPdECxPZoK9RURp
        ky5iFStlbSkhDKcQELvd9tto7oZCpoPXWMjvQnYo6Ar7C+5K9sR6E6CH1AnRp2TQ0DuZ2a
        8AAAAgfk7I/VLNmjZoHBdWlnYS1hHxhJTBOhq/sCMmNV03UxUAAAAXY2hlZXNla3VuQGNo
        ZWVzZS1tYnByMTQB
        -----END OPENSSH PRIVATE KEY-----
        """

    // Encrypted key (passphrase: "testpassword")
    static let ed25519EncryptedPrivateKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAAHu28gx
        Y8Fw15CBmEsid/AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIE/WAkhUfNqdx0aa
        DgiwY3XxPdyBKboNqzdicJeS/g6/AAAAoBZi7KJXdO4sH8uQDjm8NMd6wqCJNKBX4wgEgJ
        t1sP9C7ro74XkuGbUu+iDgF+3pjauZkHIbaME38//4cspDrWIpPS7dkpx/JOWdNrn3fx4t
        p9upe3IyvVo8pDXJucZllMHIZNTRo9nfHyPLLEf4ZfjzqOMNZ2jh8onVYuED7Zu9USlf2l
        YxA5MYD1IZox9mxsHb3aMHEqBR6adpEaKnDcc=
        -----END OPENSSH PRIVATE KEY-----
        """

    static let ed25519EncryptedPassphrase = Data("testpassword".utf8)
}

@Suite("Xuanxue Tests")
struct XuanxueTests {

    @Test("SwiftASN1 dependency is available")
    func swiftASN1Available() throws {
        let identifier = ASN1Identifier(tagWithNumber: 2, tagClass: .universal)
        #expect(identifier.tagNumber == 2)
    }
}

@Suite("Public Key Loading Tests")
struct PublicKeyLoadingTests {

    @Test("Load RSA public key")
    func loadRSAPublicKey() throws {
        let publicKey = try Xuanxue.PublicKey(sshString: TestKeys.rsaPublicKey)

        #expect(publicKey.algorithm == .rsa)
        #expect(publicKey.keySize == 2048)
        #expect(publicKey.comment == "cheesekun@cheese-mbpr14")
    }

    @Test("Load Ed25519 public key")
    func loadEd25519PublicKey() throws {
        let publicKey = try Xuanxue.PublicKey(sshString: TestKeys.ed25519PublicKey)

        #expect(publicKey.algorithm == .ed25519)
        #expect(publicKey.keySize == 256)
        #expect(publicKey.comment == "cheesekun@cheese-mbpr14")
    }

    @Test("Load ECDSA P-256 public key")
    func loadECDSAP256PublicKey() throws {
        let publicKey = try Xuanxue.PublicKey(sshString: TestKeys.ecdsaP256PublicKey)

        #expect(publicKey.algorithm == .ecdsaSha2Nistp256)
        #expect(publicKey.keySize == 256)
        #expect(publicKey.comment == "cheesekun@cheese-mbpr14")
    }

    @Test("Invalid public key format throws error")
    func invalidPublicKeyFormat() {
        #expect(throws: SSHError.self) {
            _ = try Xuanxue.PublicKey(sshString: "invalid key format")
        }
    }

    @Test("Unsupported algorithm throws error")
    func unsupportedAlgorithm() {
        #expect(throws: SSHError.self) {
            _ = try Xuanxue.PublicKey(sshString: "unknown-algo AAAAB3NzaC1 comment")
        }
    }
}

@Suite("Private Key Loading Tests")
struct PrivateKeyLoadingTests {

    @Test("Load RSA private key")
    func loadRSAPrivateKey() throws {
        let privateKey = try Xuanxue.PrivateKey(sshString: TestKeys.rsaPrivateKey)

        #expect(privateKey.algorithm == .rsa)
        #expect(privateKey.keySize == 2048)
        #expect(privateKey.comment == "cheesekun@cheese-mbpr14")
    }

    @Test("Load Ed25519 private key")
    func loadEd25519PrivateKey() throws {
        let privateKey = try Xuanxue.PrivateKey(sshString: TestKeys.ed25519PrivateKey)

        #expect(privateKey.algorithm == .ed25519)
        #expect(privateKey.keySize == 256)
        #expect(privateKey.comment == "cheesekun@cheese-mbpr14")
    }

    @Test("Load ECDSA P-256 private key")
    func loadECDSAP256PrivateKey() throws {
        let privateKey = try Xuanxue.PrivateKey(sshString: TestKeys.ecdsaP256PrivateKey)

        #expect(privateKey.algorithm == .ecdsaSha2Nistp256)
        #expect(privateKey.keySize == 256)
        #expect(privateKey.comment == "cheesekun@cheese-mbpr14")
    }

    @Test("Private key includes public key")
    func privateKeyIncludesPublicKey() throws {
        let privateKey = try Xuanxue.PrivateKey(sshString: TestKeys.ed25519PrivateKey)
        let publicKey = try Xuanxue.PublicKey(sshString: TestKeys.ed25519PublicKey)

        #expect(privateKey.publicKey.algorithm == publicKey.algorithm)
    }

    @Test("Load encrypted Ed25519 private key")
    func loadEncryptedEd25519PrivateKey() throws {
        let privateKey = try Xuanxue.PrivateKey(
            sshString: TestKeys.ed25519EncryptedPrivateKey,
            passphrase: TestKeys.ed25519EncryptedPassphrase
        )

        #expect(privateKey.algorithm == .ed25519)
        #expect(privateKey.keySize == 256)
        #expect(privateKey.comment == "test@encrypted")
    }

    @Test("Encrypted key without passphrase throws error")
    func encryptedKeyWithoutPassphrase() {
        #expect(throws: SSHError.self) {
            _ = try Xuanxue.PrivateKey(sshString: TestKeys.ed25519EncryptedPrivateKey)
        }
    }

    @Test("Encrypted key with wrong passphrase throws error")
    func encryptedKeyWithWrongPassphrase() {
        #expect(throws: SSHError.self) {
            _ = try Xuanxue.PrivateKey(
                sshString: TestKeys.ed25519EncryptedPrivateKey,
            passphrase: Data("wrongpassword".utf8)
            )
        }
    }
}

@Suite("Signing and Verification Tests")
struct SigningTests {

    @Test("Ed25519 sign and verify")
    func ed25519SignAndVerify() throws {
        let privateKey = try Xuanxue.PrivateKey(sshString: TestKeys.ed25519PrivateKey)
        let publicKey = try Xuanxue.PublicKey(sshString: TestKeys.ed25519PublicKey)

        let data = "Hello, World!".data(using: .utf8)!
        let signature = privateKey.sign(data)

        #expect(!signature.isEmpty)
        #expect(publicKey.verify(signature, for: data))
    }

    @Test("ECDSA P-256 sign and verify")
    func ecdsaP256SignAndVerify() throws {
        let privateKey = try Xuanxue.PrivateKey(sshString: TestKeys.ecdsaP256PrivateKey)
        let publicKey = try Xuanxue.PublicKey(sshString: TestKeys.ecdsaP256PublicKey)

        let data = "Hello, World!".data(using: .utf8)!
        let signature = privateKey.sign(data)

        #expect(!signature.isEmpty)
        #expect(publicKey.verify(signature, for: data))
    }

    @Test("RSA sign and verify")
    func rsaSignAndVerify() throws {
        let privateKey = try Xuanxue.PrivateKey(sshString: TestKeys.rsaPrivateKey)
        let publicKey = try Xuanxue.PublicKey(sshString: TestKeys.rsaPublicKey)

        let data = "Hello, World!".data(using: .utf8)!
        let signature = privateKey.sign(data)

        #expect(!signature.isEmpty)
        #expect(publicKey.verify(signature, for: data))
    }

    @Test("Invalid signature fails verification")
    func invalidSignatureFails() throws {
        let publicKey = try Xuanxue.PublicKey(sshString: TestKeys.ed25519PublicKey)

        let data = "Hello, World!".data(using: .utf8)!
        let invalidSignature = Data(repeating: 0, count: 64)

        #expect(!publicKey.verify(invalidSignature, for: data))
    }

    @Test("Wrong data fails verification")
    func wrongDataFails() throws {
        let privateKey = try Xuanxue.PrivateKey(sshString: TestKeys.ed25519PrivateKey)
        let publicKey = try Xuanxue.PublicKey(sshString: TestKeys.ed25519PublicKey)

        let data = "Hello, World!".data(using: .utf8)!
        let wrongData = "Goodbye, World!".data(using: .utf8)!
        let signature = privateKey.sign(data)

        #expect(!publicKey.verify(signature, for: wrongData))
    }
}

@Suite("Key Generation Tests")
struct KeyGenerationTests {

    @Test("Generate Ed25519 key")
    func generateEd25519Key() throws {
        let privateKey = try Xuanxue.PrivateKey.generateEd25519(comment: "test@generated")

        #expect(privateKey.algorithm == .ed25519)
        #expect(privateKey.keySize == 256)
        #expect(privateKey.comment == "test@generated")
        #expect(privateKey.publicKey.algorithm == .ed25519)
    }

    @Test("Generate Ed25519 key and sign/verify")
    func generateEd25519KeySignAndVerify() throws {
        let privateKey = try Xuanxue.PrivateKey.generateEd25519()
        let publicKey = privateKey.publicKey

        let data = "Hello, World!".data(using: .utf8)!
        let signature = privateKey.sign(data)

        #expect(!signature.isEmpty)
        #expect(publicKey.verify(signature, for: data))
    }

    @Test("Generate ECDSA P-256 key")
    func generateECDSAP256Key() throws {
        let privateKey = try Xuanxue.PrivateKey.generateECDSA(curve: .p256, comment: "test@ecdsa-p256")

        #expect(privateKey.algorithm == .ecdsaSha2Nistp256)
        #expect(privateKey.keySize == 256)
        #expect(privateKey.comment == "test@ecdsa-p256")
        #expect(privateKey.publicKey.algorithm == .ecdsaSha2Nistp256)
    }

    @Test("Generate ECDSA P-384 key")
    func generateECDSAP384Key() throws {
        let privateKey = try Xuanxue.PrivateKey.generateECDSA(curve: .p384, comment: "test@ecdsa-p384")

        #expect(privateKey.algorithm == .ecdsaSha2Nistp384)
        #expect(privateKey.keySize == 384)
        #expect(privateKey.comment == "test@ecdsa-p384")
        #expect(privateKey.publicKey.algorithm == .ecdsaSha2Nistp384)
    }

    @Test("Generate ECDSA P-521 key")
    func generateECDSAP521Key() throws {
        let privateKey = try Xuanxue.PrivateKey.generateECDSA(curve: .p521, comment: "test@ecdsa-p521")

        #expect(privateKey.algorithm == .ecdsaSha2Nistp521)
        #expect(privateKey.keySize == 521)
        #expect(privateKey.comment == "test@ecdsa-p521")
        #expect(privateKey.publicKey.algorithm == .ecdsaSha2Nistp521)
    }

    @Test("Generate ECDSA key and sign/verify")
    func generateECDSAKeySignAndVerify() throws {
        let privateKey = try Xuanxue.PrivateKey.generateECDSA(curve: .p256)
        let publicKey = privateKey.publicKey

        let data = "Test message for ECDSA signing".data(using: .utf8)!
        let signature = privateKey.sign(data)

        #expect(!signature.isEmpty)
        #expect(publicKey.verify(signature, for: data))
    }

    @Test("Generate RSA 2048 key")
    func generateRSA2048Key() throws {
        let privateKey = try Xuanxue.PrivateKey.generateRSA(keySize: 2048, comment: "test@rsa-2048")

        #expect(privateKey.algorithm == .rsa)
        #expect(privateKey.keySize == 2048)
        #expect(privateKey.comment == "test@rsa-2048")
        #expect(privateKey.publicKey.algorithm == .rsa)
    }

    @Test("Generate RSA 3072 key")
    func generateRSA3072Key() throws {
        let privateKey = try Xuanxue.PrivateKey.generateRSA(keySize: 3072, comment: "test@rsa-3072")

        #expect(privateKey.algorithm == .rsa)
        #expect(privateKey.keySize == 3072)
        #expect(privateKey.comment == "test@rsa-3072")
    }

    @Test("Generate RSA 4096 key")
    func generateRSA4096Key() throws {
        let privateKey = try Xuanxue.PrivateKey.generateRSA(keySize: 4096, comment: "test@rsa-4096")

        #expect(privateKey.algorithm == .rsa)
        #expect(privateKey.keySize == 4096)
        #expect(privateKey.comment == "test@rsa-4096")
    }

    @Test("Generate RSA key and sign/verify")
    func generateRSAKeySignAndVerify() throws {
        let privateKey = try Xuanxue.PrivateKey.generateRSA(keySize: 2048)
        let publicKey = privateKey.publicKey

        let data = "Test message for RSA signing".data(using: .utf8)!
        let signature = privateKey.sign(data)

        #expect(!signature.isEmpty)
        #expect(publicKey.verify(signature, for: data))
    }

    @Test("Invalid RSA key size throws error")
    func invalidRSAKeySize() {
        #expect(throws: SSHError.self) {
            _ = try Xuanxue.PrivateKey.generateRSA(keySize: 1024)
        }
    }

    @Test("Generated keys are unique")
    func generatedKeysAreUnique() throws {
        let key1 = try Xuanxue.PrivateKey.generateEd25519()
        let key2 = try Xuanxue.PrivateKey.generateEd25519()

        // Public keys should be different
        #expect(key1.publicKey != key2.publicKey)
    }
}
