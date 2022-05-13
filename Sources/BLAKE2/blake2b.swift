// SPDX-License-Identifier: CC0-1.0 OR Apache-2.0 OR OpenSSL
// Copyright 2021 Stephen Larew

import Foundation
import Crypto
import CBLAKE2

public extension Crypto.SymmetricKeySize {
  /// Maximum size (512 bits) for keyed BLAKE2b.
  static var blake2b = Crypto.SymmetricKeySize(bitCount: Int(BLAKE2B_KEYBYTES.rawValue) * 8)
}

public protocol BLAKE2bDigest: Crypto.Digest {
  init()
  mutating func withUnsafeMutableBytes<ResultType>(_ body: (UnsafeMutableRawBufferPointer) throws -> ResultType) rethrows -> ResultType
}

/// The output of a BLAKE2b hash with a 512-bit digest.
public struct BLAKE2b512Digest : BLAKE2bDigest {

  public static var byteCount: Int {
    return Int(BLAKE2B_OUTBYTES.rawValue)
  }

  fileprivate var bytes = (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64)(0,0,0,0,0,0,0,0)
  mutating public func withUnsafeMutableBytes<ResultType>(_ body: (UnsafeMutableRawBufferPointer) throws -> ResultType) rethrows -> ResultType {
    return try Swift.withUnsafeMutableBytes(of: &bytes) { return try body($0) }
  }

  public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
    try Swift.withUnsafeBytes(of: bytes) { try body($0) }
  }

  public func hash(into hasher: inout Hasher) {
    self.withUnsafeBytes { hasher.combine(bytes: $0) }
  }

  public init() {}
}

/// The output of a BLAKE2b hash with a 256-bit digest.
public struct BLAKE2b256Digest : BLAKE2bDigest {

  public static var byteCount: Int {
    return Int(BLAKE2B_OUTBYTES.rawValue / 2)
  }

  fileprivate var bytes = (UInt64, UInt64, UInt64, UInt64)(0,0,0,0)
  mutating public func withUnsafeMutableBytes<ResultType>(_ body: (UnsafeMutableRawBufferPointer) throws -> ResultType) rethrows -> ResultType {
    return try Swift.withUnsafeMutableBytes(of: &bytes) { return try body($0) }
  }

  public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
    try Swift.withUnsafeBytes(of: bytes) { try body($0) }
  }

  public func hash(into hasher: inout Hasher) {
    self.withUnsafeBytes { hasher.combine(bytes: $0) }
  }

  public init() {}
}

/// An implementation of BLAKE2b hashing with a 512-bit digest.
public struct BLAKE2b<SizedDigest> : Crypto.HashFunction where SizedDigest: BLAKE2bDigest {

  public static var blockByteCount: Int { Int(BLAKE2B_BLOCKBYTES.rawValue) }

  public typealias Digest = SizedDigest

  private var state = blake2b_state(h: (0, 0, 0, 0, 0, 0, 0, 0), t: (0, 0), f: (0, 0), buf: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), buflen: 0, outlen: 0, last_node: 0)

  public init() {
    withUnsafeMutablePointer(to: &state) {
      precondition(blake2b_init($0, Digest.byteCount) == 0)
    }
  }

  /// An alias for the symmetric key type used to compute or verify a message authentication code.
  public typealias Key = Crypto.SymmetricKey

  /// Initializes the hasher instance with a key (MAC/PRF).
  public init(key: Key) {
    precondition(key.bitCount <= Crypto.SymmetricKeySize.blake2b.bitCount)
    withUnsafeMutablePointer(to: &state) { state in
      key.withUnsafeBytes { key in
        precondition(
          blake2b_init_key(state, Digest.byteCount, key.baseAddress, key.count)
          == 0)
      }
    }
  }

  public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
    withUnsafeMutablePointer(to: &state) {
      precondition(
        blake2b_update($0, bufferPointer.baseAddress, bufferPointer.count)
        == 0)
    }
  }

  public func finalize() -> Digest {
    var digest = Digest()
    var state = state

    digest.withUnsafeMutableBytes { ptr in
      withUnsafeMutablePointer(to: &state) {
        precondition(
          blake2b_final($0, ptr.baseAddress, ptr.count)
          == 0)
      }
    }

    return digest
  }
}

public typealias BLAKE2b512 = BLAKE2b<BLAKE2b512Digest>
public typealias BLAKE2b256 = BLAKE2b<BLAKE2b256Digest>
