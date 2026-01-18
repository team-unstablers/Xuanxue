import Testing
import SwiftASN1
import libbcrypt
@testable import xuanxue

@Suite("Xuanxue Tests")
struct XuanxueTests {

    @Test("SwiftASN1 dependency is available")
    func swiftASN1Available() throws {
        // Test that SwiftASN1 is properly linked by creating a simple ASN.1 object
        let identifier = ASN1Identifier(tagWithNumber: 2, tagClass: .universal)
        #expect(identifier.tagNumber == 2)
    }

    @Test("libbcrypt can generate salt")
    func libbcryptCanGenerateSalt() throws {
        // Test that libbcrypt is properly linked and functional
        var salt = [CChar](repeating: 0, count: Int(BCRYPT_HASHSIZE))
        let result = bcrypt_gensalt(12, &salt)
        #expect(result == 0, "bcrypt_gensalt should succeed")

        // Salt should start with $2b$ (bcrypt format)
        let saltData = salt.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        let saltString = String(decoding: saltData, as: UTF8.self)
        #expect(saltString.hasPrefix("$2"), "Salt should be in bcrypt format")
    }

    @Test("libbcrypt can hash password")
    func libbcryptCanHashPassword() throws {
        var salt = [CChar](repeating: 0, count: Int(BCRYPT_HASHSIZE))
        var hash = [CChar](repeating: 0, count: Int(BCRYPT_HASHSIZE))

        // Generate salt
        let saltResult = bcrypt_gensalt(4, &salt) // Use work factor 4 for speed
        #expect(saltResult == 0)

        // Hash password
        let password = "testpassword"
        let hashResult = password.withCString { pwd in
            bcrypt_hashpw(pwd, &salt, &hash)
        }
        #expect(hashResult == 0, "bcrypt_hashpw should succeed")

        // Hash should not be empty
        let hashData = hash.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        let hashString = String(decoding: hashData, as: UTF8.self)
        #expect(!hashString.isEmpty, "Hash should not be empty")
        #expect(hashString.hasPrefix("$2"), "Hash should be in bcrypt format")
    }
}
