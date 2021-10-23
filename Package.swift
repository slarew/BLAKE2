// swift-tools-version:5.3
// Copyright 2021 Stephen Larew

import PackageDescription

let package = Package(
  name: "BLAKE2",
  platforms: [.macOS(.v10_15),.iOS(.v13),.tvOS(.v13),.watchOS(.v6)],
  products: [
    .library(
      name: "BLAKE2",
      targets: ["BLAKE2"]),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-crypto", from: "1.1.6"),
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
