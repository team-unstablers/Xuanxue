// The Swift Programming Language
// https://docs.swift.org/swift-book

@_exported import SwiftASN1

/// Xuanxue - SSH Key Library for Swift
public enum Xuanxue {
    /// SSH Public Key
    public typealias PublicKey = xuanxue.PublicKey

    /// SSH Private Key
    public typealias PrivateKey = xuanxue.PrivateKey

    /// SSH Key Algorithm
    public typealias Algorithm = xuanxue.SSHKeyAlgorithm

    /// SSH Error
    public typealias Error = xuanxue.SSHError
}
