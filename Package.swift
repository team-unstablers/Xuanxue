// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "xuanxue",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(
            name: "xuanxue",
            targets: ["xuanxue"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "libbcrypt",
            path: "dependencies/libbcrypt",
            exclude: [
                "bcrypt_test.c",
                "Makefile",
                "README",
                "COPYING",
                "INSTALL",
                "bcrypt.3.txt",
                ".gitignore",
                "crypt_blowfish/Makefile",
                "crypt_blowfish/README",
                "crypt_blowfish/LINKS",
                "crypt_blowfish/PERFORMANCE",
                "crypt_blowfish/crypt.3",
                "crypt_blowfish/crypt.h",
                "crypt_blowfish/ow-crypt.h",
                "crypt_blowfish/glibc-2.1.3-crypt.diff",
                "crypt_blowfish/glibc-2.14-crypt.diff",
                "crypt_blowfish/glibc-2.3.6-crypt.diff",
                "crypt_blowfish/x86.S",
            ],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("."),
                .headerSearchPath("crypt_blowfish"),
            ]
        ),
        .target(
            name: "xuanxue",
            dependencies: [
                "libbcrypt",
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
        .testTarget(
            name: "xuanxueTests",
            dependencies: ["xuanxue"]
        ),
    ]
)
