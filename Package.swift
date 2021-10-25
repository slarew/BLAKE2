// swift-tools-version:5.3
// SPDX-License-Identifier: CC0-1.0 OR Apache-2.0 OR OpenSSL
// Copyright 2021 Stephen Larew

import PackageDescription

let package = Package(
  name: "swift-crypto-blake2",
  platforms: [.macOS(.v10_15),.iOS(.v13),.tvOS(.v13),.watchOS(.v6)],
  products: [
    .library(
      name: "BLAKE2",
      targets: ["BLAKE2"]),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-crypto", from: "2.0.0"),
  ],
  targets: [
    .target(name: "CBLAKE2"),
    .target(
      name: "BLAKE2",
      dependencies: [
        .product(name: "Crypto", package: "swift-crypto"),
        .target(name: "CBLAKE2")
      ]),
    .testTarget(
      name: "BLAKE2Tests",
      dependencies: ["BLAKE2"]),
  ]
)
