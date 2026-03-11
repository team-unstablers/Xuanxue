import Foundation

/// A buffer for reading SSH wire format data
struct SSHBuffer {
    private var data: Data
    private var cursor: Int = 0

    init(_ data: Data) {
        self.data = data
    }

    var remainingBytes: Int {
        return data.count - cursor
    }

    var isAtEnd: Bool {
        return cursor >= data.count
    }

    /// Read a UInt32 in big-endian format
    mutating func readUInt32() throws -> UInt32 {
        guard remainingBytes >= 4 else {
            throw SSHError.invalidKeyData("Unexpected end of data while reading UInt32")
        }

        let value = data.subdata(in: cursor..<cursor+4).withUnsafeBytes {
            $0.load(as: UInt32.self).bigEndian
        }
        cursor += 4
        return value
    }

    /// Read a length-prefixed string
    mutating func readString() throws -> String {
        let length = try readUInt32()
        guard remainingBytes >= Int(length) else {
            throw SSHError.invalidKeyData("Unexpected end of data while reading string")
        }

        let stringData = data.subdata(in: cursor..<cursor+Int(length))
        cursor += Int(length)

        guard let string = String(data: stringData, encoding: .utf8) else {
            throw SSHError.invalidKeyData("Invalid UTF-8 string")
        }
        return string
    }

    /// Read a length-prefixed byte buffer (mpint or raw bytes)
    mutating func readBytes() throws -> Data {
        let length = try readUInt32()
        guard remainingBytes >= Int(length) else {
            throw SSHError.invalidKeyData("Unexpected end of data while reading bytes")
        }

        let bytes = data.subdata(in: cursor..<cursor+Int(length))
        cursor += Int(length)
        return bytes
    }

    /// Read exactly n bytes
    mutating func readExactBytes(_ n: Int) throws -> Data {
        guard remainingBytes >= n else {
            throw SSHError.invalidKeyData("Unexpected end of data while reading \(n) bytes")
        }

        let bytes = data.subdata(in: cursor..<cursor+n)
        cursor += n
        return bytes
    }

    /// Read a UInt64 in big-endian format
    mutating func readUInt64() throws -> UInt64 {
        guard remainingBytes >= 8 else {
            throw SSHError.invalidKeyData("Unexpected end of data while reading UInt64")
        }

        let value = data.subdata(in: cursor..<cursor+8).withUnsafeBytes {
            $0.load(as: UInt64.self).bigEndian
        }
        cursor += 8
        return value
    }

    /// Get remaining data without advancing cursor
    func remainingData() -> Data {
        return data.subdata(in: cursor..<data.count)
    }

    /// Skip n bytes
    mutating func skip(_ n: Int) throws {
        guard remainingBytes >= n else {
            throw SSHError.invalidKeyData("Unexpected end of data while skipping \(n) bytes")
        }
        cursor += n
    }
}

/// A buffer for writing SSH wire format data
struct SSHBufferWriter {
    private var data: Data = Data()

    mutating func writeUInt32(_ value: UInt32) {
        var bigEndian = value.bigEndian
        data.append(contentsOf: withUnsafeBytes(of: &bigEndian) { Array($0) })
    }

    mutating func writeString(_ string: String) {
        let bytes = Data(string.utf8)
        writeUInt32(UInt32(bytes.count))
        data.append(bytes)
    }

    mutating func writeBytes(_ bytes: Data) {
        writeUInt32(UInt32(bytes.count))
        data.append(bytes)
    }

    mutating func writeRawBytes(_ bytes: Data) {
        data.append(bytes)
    }

    func toData() -> Data {
        return data
    }
}
