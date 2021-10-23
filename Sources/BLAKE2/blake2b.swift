// SPDX-License-Identifier: CC0-1.0 OR Apache-2.0 OR OpenSSL
// Copyright 2021 Stephen Larew

import Foundation
import Crypto
import CBLAKE2

extension Crypto.SymmetricKeySize {
  /// Maximum size (512 bits) for keyed BLAKE2b.
  static var blake2b = Crypto.SymmetricKeySize(bitCount: Int(BLAKE2B_KEYBYTES.rawValue) * 8)
}

/// An implementation of BLAKE2b hashing with a 512-bit digest.
public struct BLAKE2b : Crypto.HashFunction {

  public static let blockByteCount = Int(BLAKE2B_BLOCKBYTES.rawValue)

  /// The output of a BLAKE2b hash with a 512-bit digest.
  public struct BLAKE2bDigest : Crypto.Digest {

    public static var byteCount: Int {
      return Int(BLAKE2B_OUTBYTES.rawValue)
    }

    fileprivate var bytes = (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64)(0,0,0,0,0,0,0,0)

    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
      try Swift.withUnsafeBytes(of: bytes) { try body($0) }
    }

    public func hash(into hasher: inout Hasher) {
      self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
  }

  private var state = blake2b_state(h: (0, 0, 0, 0, 0, 0, 0, 0), t: (0, 0), f: (0, 0), buf: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), buflen: 0, outlen: 0, last_node: 0)

  public init() {
    withUnsafeMutablePointer(to: &state) {
      precondition(blake2b_init($0, BLAKE2bDigest.byteCount) == 0)
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
          blake2b_init_key(state, BLAKE2bDigest.byteCount, key.baseAddress, key.count)
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

  public func finalize() -> BLAKE2bDigest {
    var digest = BLAKE2bDigest()
    var state = state

    withUnsafeMutableBytes(of: &digest.bytes) { ptr in
      withUnsafeMutablePointer(to: &state) {
        precondition(
          blake2b_final($0, ptr.baseAddress, ptr.count)
            == 0)
      }
    }

    return digest
  }
}
