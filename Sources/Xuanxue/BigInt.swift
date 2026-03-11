import Foundation

/// Simple big integer operations for RSA key handling
enum BigIntOps {
    /// Subtract 1 from a big-endian unsigned integer
    static func subtractOne(_ data: Data) -> Data {
        var result = [UInt8](data)
        var borrow: UInt8 = 1

        for i in (0..<result.count).reversed() {
            let (newValue, newBorrow) = result[i].subtractingReportingOverflow(borrow)
            result[i] = newValue
            borrow = newBorrow ? 1 : 0
        }

        let output = Data(result)
        zeroize(&result)
        return output
    }

    /// Calculate a mod b for big-endian unsigned integers
    static func modulo(_ a: Data, _ b: Data) -> Data {
        // Convert to arrays for easier manipulation
        var dividend = [UInt8](a)
        var divisor = [UInt8](b)
        var effectiveDivisor = [UInt8]()
        var remainder = [UInt8]()
        defer {
            zeroize(&dividend)
            zeroize(&divisor)
            zeroize(&effectiveDivisor)
            zeroize(&remainder)
        }

        // Remove leading zeros from divisor
        var divisorStart = 0
        while divisorStart < divisor.count - 1 && divisor[divisorStart] == 0 {
            divisorStart += 1
        }
        effectiveDivisor = Array(divisor[divisorStart...])

        // Simple long division for modulo
        // This is a basic implementation suitable for RSA key derivation
        for byte in dividend {
            remainder.append(byte)

            // Remove leading zeros from remainder
            while remainder.count > 1 && remainder[0] == 0 {
                remainder.removeFirst()
            }

            // Subtract divisor as many times as possible
            while compare(remainder, effectiveDivisor) >= 0 {
                remainder = subtract(remainder, effectiveDivisor)
                // Remove leading zeros
                while remainder.count > 1 && remainder[0] == 0 {
                    remainder.removeFirst()
                }
            }
        }

        // Pad result to match divisor length if needed
        while remainder.count < effectiveDivisor.count {
            remainder.insert(0, at: 0)
        }

        let output = Data(remainder)
        return output
    }

    /// Compare two big-endian unsigned integers
    /// Returns: -1 if a < b, 0 if a == b, 1 if a > b
    private static func compare(_ a: [UInt8], _ b: [UInt8]) -> Int {
        // Remove leading zeros for comparison
        var aStart = 0
        while aStart < a.count - 1 && a[aStart] == 0 {
            aStart += 1
        }
        var bStart = 0
        while bStart < b.count - 1 && b[bStart] == 0 {
            bStart += 1
        }

        let aLen = a.count - aStart
        let bLen = b.count - bStart

        if aLen < bLen { return -1 }
        if aLen > bLen { return 1 }

        for i in 0..<aLen {
            if a[aStart + i] < b[bStart + i] { return -1 }
            if a[aStart + i] > b[bStart + i] { return 1 }
        }

        return 0
    }

    /// Subtract b from a (a must be >= b)
    private static func subtract(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var result = a
        var borrow: Int = 0

        // Align arrays
        let offset = a.count - b.count

        for i in (0..<a.count).reversed() {
            let bValue: Int
            if i >= offset {
                bValue = Int(b[i - offset])
            } else {
                bValue = 0
            }

            var diff = Int(result[i]) - bValue - borrow
            if diff < 0 {
                diff += 256
                borrow = 1
            } else {
                borrow = 0
            }
            result[i] = UInt8(diff)
        }

        return result
    }

    private static func zeroize(_ bytes: inout [UInt8]) {
        guard !bytes.isEmpty else { return }
        for index in bytes.indices {
            bytes[index] = 0
        }
    }
}
